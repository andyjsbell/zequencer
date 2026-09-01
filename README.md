# zequencer

A minimal simulator of a ZK-L2 sequencing flow: intents are admitted, ordered
deterministically, given an inclusion guarantee, preconfirmed by a (mocked) TEE
and carried to a mocked final proof.

There are no state transitions. Nothing is executed, matched or settled — the
system proves *sequencing*, and every guarantee below is about ordering and
inclusion rather than outcome.

```bash
make            # lists every target
make pipeline   # serves on :3000
make check      # fmt + clippy + tests — the gate
make bench      # latency + throughput, see BENCH.md
make docker     # the same service in a container, on :3000
```

Every target is a thin wrapper over cargo; nothing here depends on `make`, and
`cargo run` / `cargo test` / `cargo bench --bench submit` still work unchanged.
See [Make targets](#make-targets).

`GET /health` returns `ok` once the process is serving; compose uses it as the
container health check.

---

## Architecture

One append-only log is the only channel between components. Each stage is an
independent task that reads the log, does its work, and appends its result.
No stage calls another.

```
                    ┌──────────────────────────────────────────┐
  POST /intents ──► │ admission │ replay · nonce · validity     │
                    │           │ guarantee window              │
                    └─────┬─────┴──────────────────────────────┘
                          │ append (holds one lock: this is the total order)
                          ▼
    ┌──────────────────── log ────────────────────┐
    │  IntentReceived · IntentExpired             │
    │  SlotCommitted  · SlotAttested/AttestFailed │
    │  SlotsProven    · ProveFailed               │
    └──┬────────────┬─────────────┬───────────┬───┘
       │            │             │           │
       ▼            ▼             ▼           ▼
   sequencer ──► attester ──► prover      projector
   (slots,       (TEE          (batched    (read model)
    ordering)     preconf)      proof)         │
                                               ▼
                                  GET /intents/{id}[/receipt]
```

Why a log in the middle: every stage rebuilds its position from it on start, so
the pipeline is replayable and each component is testable in isolation. The
projector persists nothing — it is a pure function of the log.

The prover consumes `SlotAttested`, not `SlotCommitted`, so it runs strictly
behind the attester. That ordering is load-bearing: when it did not hold, a slot
could be proven before it was attested and the preconfirmation was discarded.

| module | responsibility |
|---|---|
| `intent` | the intent domain and its content-derived identity |
| `log` | the append-only log and the values entries carry |
| `admission` | the gate an intent passes to enter the protocol |
| `sequencer` | ordering policy and the inclusion guarantee |
| `attest` | TEE preconfirmation, and its verification path |
| `prove` | the final proof stage — `Prove` is the zkVM seam |
| `projection` | the read model |
| `receipt` / `api` | the client contract and its HTTP surface |

---

## API

Three operations, all JSON. 32-byte values are hex strings, never integer arrays.

### `submitIntent` — `POST /intents`

```bash
curl -sX POST localhost:3000/intents -H 'content-type: application/json' -d '{
  "submitter": "aa11111111111111111111111111111111111111",
  "nonce": 1,
  "market": {"base": "ETH", "quote": "USDC"},
  "side": "buy",
  "size": 1000000000000000000,
  "max_slippage_bps": 50,
  "priority_fee": 7,
  "timestamp_ms": 1788500000000,
  "deadline_ms": 1788500600000
}'
```
```json
{"intent_id":"6ab0a18d…","log_position":2}
```

`intent_id` is keccak over the canonical encoding of every field above, so the
client can recompute it. `size` is integer base units; there are no floats
anywhere in the ordering path.

Rejections carry a machine-readable `reason` rather than prose:

| reason | status | when |
|---|---|---|
| `replay` | 409 | this exact intent was already admitted |
| `stale_nonce` | 409 | the nonce does not advance past this submitter's highest |
| `expired` | 400 | `deadline_ms` has already passed |
| `unmeetable_window` | 400 | it expires before the guarantee window could close |
| `zero_size`, `empty_market`, `slippage_out_of_range` | 400 | malformed |

### `getStatus` — `GET /intents/{id}`

The cheap poll.

```json
{"intent_id":"6ab0a18d…","status":"preconfirmed","slot":2}
```

### `getReceipt` — `GET /intents/{id}/receipt`

The evidence bundle.

```json
{"intent_id":"6ab0a18d…","status":"final_proven","log_position":2,
 "sequence":{"slot":1,"index":0,"slot_commitment":"358bc971…"},
 "guarantee":{"received_at_ms":…,"max_slots":2,"deadline_ms":…,
              "intent_deadline_ms":…,"state":"met","slot":1,"committed_at_ms":…},
 "preconf":{"slot":1,"commitment":"358bc971…","quote":"4d4f434b…","signature":"17e15c00…"},
 "proof":{"from_slot":0,"to_slot":4,"vkey_hash":"aaaa…","proof":"e449da9f…"}}
```

`sequence.index` is the rank inside the slot's ordering — not a log offset;
`log_position` is arrival. `404` for an unknown id, `503` while the projector is
behind (retry), `400` for a malformed id.

**Lifecycle:** `received → sequenced → preconfirmed → final_proven`, with
terminal `expired` (guarantee missed) and `failed` (attestation or proving
failed). The spec names `sequenced` and `included` separately; here they are the
same event — an intent gains its position when its slot commitment is logged —
so only `sequenced` exists rather than inventing a state with no distinct meaning.

---

## Sequencing policy

**The ordering domain is the market.** Intents on ETH/USDC compete with each
other, not with BTC/USDC. A slot lays its domains out in lexicographic market
order and orders within each domain by:

1. **nonce**, per submitter
2. **priority_fee**, descending
3. **received_at**, ascending
4. **intent_id**, ascending — the last resort, so the order is *total*

**Rule 1 outranks rule 2 deliberately.** Priority reorders submitters against
each other, never a submitter against itself: bidding more on a later nonce must
not jump it ahead of your own earlier one. Each submitter keeps a nonce-ordered
queue and a k-way merge takes whichever head wins on (2,3,4). A flat sort by
rank looks equivalent and is not.

Nonce *validity* is absent from the policy because admission already enforced it
— everything in the log advances its submitter's nonce.

**Determinism.** The slot is a pure function of the buffered set. Concurrency
decides which submission wins the admission lock, and therefore what lands in
the buffer; it has no say in what the sequencer does with it. 64 arrival
permutations of the same 12 intents produce identical slots.

---

## Guarantee semantics

> An admitted intent is committed into a slot closing no later than
> `received_at + max_slots × slot_duration` — 2 seconds by default.

Both halves are enforced, not just reported:

- **Refused up front.** An intent expiring before the window could close is
  rejected with `unmeetable_window`. The protocol declines to promise what it
  cannot deliver.
- **Terminal on miss.** At slot close the sequencer *drops* any intent whose
  window elapsed, writing `IntentExpired` **before** the slot so replaying the
  log can never both drop and commit the same intent.

Late inclusion is not an option. A guarantee that degrades into "eventually" is
not a guarantee, and a stale intent is exactly what a client did not want filled.

A consequence worth stating: a dropped intent cannot be resubmitted verbatim —
same content means the same id, so it hits `replay`, and its nonce is already the
high-water mark. Clients resubmit with a fresh nonce.

---

## Threat model (high level)

**This is a simulator. It establishes no security property.** The mock signature
is a keyed hash and the mock proof is a digest. What follows is where the trust
would sit if they were real, and what is missing regardless.

**Submission is unauthenticated — the largest gap.** `Intent` carries no
signature, so `submitter` is a claimed address. Anyone can submit on anyone's
behalf, and because nonces must strictly advance, anyone can burn another
account's nonce space — one forged submit at `u64::MAX` closes an account for
good, which `tests/adversarial.rs` demonstrates rather than describes. A real
deployment signs the intent and verifies it in `Admission::check` before anything
else. Nothing else in the threat model matters until this is closed.

**The sequencer is trusted for ordering.** The TEE attests the *commitment*, not
that the commitment follows the published policy — so a malicious sequencer can
order badly and still get a valid preconfirmation. It cannot later change what it
committed to, which is a real property, but it can commit to the wrong thing.
The fix is architectural: compute the ordering *inside* the enclave so the
attestation covers the policy, not just the result. `tests/adversarial.rs` drives
this end to end: a slot committed in reverse of the policy obtains a preconf that
`verify_preconf` accepts, and the only check that catches it needs the buffer the
sequencer held — which no holder has.

**The inclusion guarantee is self-enforced.** The sequencer honours it against
itself; a censored client has no recourse and no escape hatch. A real L2 needs
forced inclusion via L1. Only the sequencer writes `IntentExpired`, so a censoring
one never adjudicates the miss: the receipt sits at `overdue` rather than
reaching `missed`. `overdue` is therefore the signal a client has to act on —
waiting for `missed` waits on the censor to confess.

**Verification shifts trust rather than removing it.** `MockVerifier` pins the
enclave measurement, which is the check that decides *what code* signed —
without it you have proven that something signed. A real verifier adds a vendor
certificate chain, TCB and revocation checks, report-data binding and freshness;
none of that is here. TEEs remain exposed to side channels and rollback.

**`priority_fee` is cheap talk.** It is declared, never escrowed or charged, so
bidding maximum priority costs nothing. Fee collection is out of scope here but
the policy is meaningless without it.

**Denial of service, measured.** No rate limiting, no proof of work, no fee. A
rejection returns before the log append, so spam is *cheaper* per attempt than an
honest submit while contending for the same admission lock: eight spam threads
cost an honest submitter 15.5× its throughput and 54× its p95, and each spammer
gets roughly twice the honest thread's share of the lock. See the contended-burst
section of `BENCH.md`, and `tests/adversarial.rs` for the correctness side — the
honest submitter is slowed, never dropped or duplicated. Separately, admission's
replay set and the prover's pending map both grow without bound and need eviction
past the longest guarantee window.

**What does hold, mocks aside:** replay and nonce ordering cannot be raced —
admission's lock spans check *and* append; intent identity is content-derived, so
a client verifies what was sequenced by recomputing it rather than trusting the
receipt; and the preconf verification path never consults the sequencer.

---

## Assumptions and tradeoffs

**The admission lock is the serialisation point.** One lock spans check and
append. That is what makes concurrent replay impossible rather than unlikely, and
it is where the log's total order comes from. It costs scaling: throughput
*falls* from 2.7M/s at one thread to 0.95M/s at four, because the critical
section (~0.13 µs) is shorter than the cost of contending for a mutex. Submit is
cheap enough single-threaded that this is not the practical constraint. If it
became one, the shape is to shard admission by submitter — nonce state is already
per-submitter — and serialise only the append. See `BENCH.md`.

**Nonces strictly increase, but need not be gapless.** Requiring `last + 1` needs
a buffer holding future nonces until their predecessors arrive, which is mempool
territory. The same reasoning excludes replacement-by-fee: with an enforced
2-second inclusion guarantee there is little to speed up.

**In-memory log by default.** `RedbLog` is implemented and tested but not wired
into `main`. With a durable log the append must move off the lock — holding it
across an fsync would serialise every submit behind disk.

**Single sequencer.** No consensus, no failover, no L1 anchoring.

**Wall-clock guarantee.** The window is time-based rather than counted in slots.
Clock skew is unhandled.

**`size` is `u128` base units.** JSON clients on 64-bit floats will need string
encoding before this is real.

**The bundled demo prover deliberately fails slots 20–29** (`main.rs`) so the
failure path is visible in a live run: intents in those slots settle to `failed`
rather than `final_proven`.

---

## Make targets

`make` on its own lists them.

| target | runs | |
|---|---|---|
| `check` | `fmt` then `lint` then `test` | the gate — must pass before every commit |
| `test` | `cargo test` | 197 tests: 174 unit, 17 adversarial, 6 end-to-end |
| `unit` | `cargo test --lib` | the in-module tests alone, no pipeline wiring |
| `integration` | `cargo test --test pipeline -- --nocapture` | the end-to-end tests in `tests/` |
| `pipeline` | `cargo run` | serves on :3000 |
| `docker` | `docker compose up --build` | the same service, containerised |
| `bench` | `cargo bench --bench submit` | latency and throughput |
| `fmt` | `cargo fmt --check` | reports, never rewrites |
| `lint` | `cargo clippy --all-targets -- -D warnings` | warnings are errors |
| `clean` | `cargo clean` | |

**`lint` covers every target, not just the library.** A benchmark that stopped
compiling, or an unused import in a test, fails the gate rather than scrolling
past — which is how the bench was caught spawning a sequencer with a zero slot
duration, panicking its own background task and measuring an unconsumed log.

**`fmt` checks rather than rewrites**, so `make check` cannot leave the working
tree different from what it just verified. Run `cargo fmt` to actually format.

`unit` and `integration` split the suite by what breaks them: `unit` needs no
timers or tasks and finishes in under a second, while `integration` runs the
real wiring and is the one to reach for after touching how the stages compose.

`cargo test --test adversarial` is the third suite: it drives the attacks
rather than asserting the invariants they target. Fee floods, id grinding,
replay and rejection storms, nonce-space burning, a sequencer that orders
maliciously, one that equivocates, one that censors. It is deliberately honest
about the attacks that *work* — see the threat model — and asserts what they
actually achieve rather than pretending they fail. Nothing in it is
timing-sensitive; the cost of a rejection flood is measured in `BENCH.md`.
`make integration` runs the pipeline suite only, so reach for the command above
directly, or `make test` for everything.

Override the toolchain per invocation:

```bash
make test CARGO="cargo +nightly"
```

---

## Running in Docker

```bash
docker compose up --build
curl localhost:3000/health          # -> ok
```

Multi-stage build: a `rust:1.90-slim-bookworm` builder, a `debian:bookworm-slim`
runtime holding only the binary and `curl`, running as an unprivileged uid. The
build uses BuildKit cache mounts for the crate registry and the target
directory, so rebuilds do not start from scratch; that needs BuildKit, which is
the default in Docker 23 and later.

`/health` reports liveness only — that the process is up and serving. It says
nothing about the pipeline behind it, which is adequate here precisely because
every stage is load-bearing: a stage that dies takes the process down with it
(see the `select!` in `main`), so an unhealthy pipeline shows up as a dead
container rather than a healthy one serving nothing.

No volume is declared. `main` runs the in-memory log, so a restart deliberately
begins from an empty one; `RedbLog` is implemented and tested but not wired in,
so there is nothing yet to persist.

---

## Invariants

All four are enforced and tested, and each test was mutation-checked — the fix
reverted, the test confirmed to fail.

| invariant | test |
|---|---|
| No duplicate inclusion for one intent id | `concurrent_replays_admit_exactly_one` |
| Monotonic nonce progression per submitter | `concurrent_same_nonce_admits_exactly_one` |
| Deterministic ordering under concurrent submission | `ordering_is_deterministic_under_arrival_permutations` |
| The status machine skips no transition | `proving_cannot_skip_attestation` |
