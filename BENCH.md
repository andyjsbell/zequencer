# Benchmark

```
cargo bench --bench submit
```

Source: `benches/submit.rs`. Raw output: `BENCH.txt`.
Measured on an Apple M4 Pro (14 cores), rustc 1.96.0, release build.

Every figure below is from one run, so the sections compare directly. The one
exception is the before/after table at the end, which is the historical run that
found the bottleneck and is labelled as such.

## What is measured

`admit_and_append` — the content hash, the admission checks and the log append.

Deliberately excluded: HTTP framing (that is axum's cost, not the protocol's) and
durability (`MemLog`; a durable log is dominated by fsync). Both would bury the
numbers this design can actually move. Absolute figures are not the point —
where the time goes is.

Five sections: submit latency, where a submit goes, burst throughput under
honest load, the same burst under spam, and submit rate with the pipeline
consuming the log.

## Submit latency

One thread, 50 000 samples after 5 000 warmup:

| | |
|---|---|
| p50 | **0.33 µs** |
| p95 | **0.42 µs** |
| p99 | 1.00 µs |
| max | 517.96 µs |
| mean | 0.37 µs |
| rate | 2.67 M submit/s |

The max is nearly three orders above p99: it is the `MemLog` vector reallocating
as it grows, plus OS scheduling. A ring buffer or a pre-sized log would remove
it.

## Where a submit goes

| | mean | share | |
|---|---|---|---|
| `Intent::id` (keccak over content) | 0.17 µs | 57% | **outside** the lock |
| admission check + log append | 0.13 µs | 43% | **inside** the lock |

Hashing dominates, and it already happens before the lock is taken — the
critical section is only the part that must be serial. The 0.13 µs critical
section implies a ceiling near 7.6 M submit/s.

## Burst throughput

20 000 submits, each thread on its own address so nothing is rejected and the
only shared thing is the admission lock:

| threads | total/s | per-thread/s | p95 |
|---|---|---|---|
| 1 | 2 896 120 | 2 896 120 | 0.33 µs |
| 2 | 1 879 398 | 939 699 | 4.96 µs |
| 4 | 964 731 | 241 183 | 13.25 µs |
| 8 | 1 007 364 | 125 921 | 33.88 µs |

**Throughput falls as threads rise.** This is the expected shape, not a
surprise: the critical section is ~0.13 µs, far shorter than the cost of
contending for a mutex, so extra threads mostly queue and ping-pong a cache
line. p95 degrades 103× from one thread to eight.

The honest reading is that submit is *already* cheap enough single-threaded
(2.9 M/s) that the lock is not the practical constraint, and that the lock
buys something concurrency cannot: it is what makes replay and nonce ordering
impossible to race, and it is where the log's total order comes from. If
submit throughput ever did need to scale, the shape of the fix is to shard
admission by submitter — nonce state is already per-submitter — and serialise
only the append.

## Contended burst — spam against one honest submitter

The section above is the honest-load case by construction: every thread submits
under its own address, so nothing is rejected. This section is the adversarial
one. One honest submitter runs 20 000 submits while N threads submit nothing but
work the gate will reject, so the only thing contended is the admission lock.

A rejection returns *before* the append, so a spammer takes and releases the lock
faster than the submitter it is starving. Three spam kinds bracket how much of
the critical section an attacker has to pay for — `expired` exits at the deadline
check before either hash lookup, `replay` at the `seen` set, `stale nonce` one
check further still:

| spam | threads | honest p50 | honest p95 | honest/s | spam/s |
|---|---|---|---|---|---|
| none | 0 | 0.29 µs | 0.33 µs | **2 917 366** | — |
| replay | 1 | 0.29 µs | 1.12 µs | 1 989 588 | 693 968 |
| replay | 4 | 1.21 µs | 7.46 µs | 482 521 | 2 180 221 |
| replay | 8 | 3.83 µs | 17.92 µs | **187 582** | 2 868 058 |
| stale nonce | 1 | 0.29 µs | 1.38 µs | 1 644 833 | 847 418 |
| stale nonce | 4 | 1.21 µs | 7.92 µs | 466 286 | 2 124 772 |
| stale nonce | 8 | 3.88 µs | 18.58 µs | 184 752 | 2 801 732 |
| expired | 1 | 0.29 µs | 1.12 µs | 1 991 197 | 560 721 |
| expired | 4 | 1.12 µs | 4.29 µs | 612 558 | 3 085 333 |
| expired | 8 | 3.96 µs | 18.54 µs | 183 832 | 2 994 850 |

**Eight spam threads cost the honest submitter 15.5× its throughput and 54× its
p95** — 2.92 M/s and 0.33 µs down to 0.19 M/s and 17.9 µs. The spam kind barely
matters at eight threads: all three land within 2% of each other, because what
dominates is the queue for the lock rather than the work done under it.

The sharper reading is the per-thread split. At eight spammers the attacker is
running 2.87 M rejections/s across 8 threads — **358 500/s each, against the
honest thread's 187 600/s.** The lock is *fair*, and that is the problem: the
attacker gets an equal share of the queue while paying about half as much for
each turn, because it never reaches the append.

Two caveats, both making these numbers conservative:

- **The 1-thread rows understate the attack.** Each spam attempt clones an
  `Intent`, which allocates two `String`s. That cost is the attacker's and sits
  outside the lock, so at low thread counts it throttles the spammer more than
  the victim; by four threads it is hidden behind lock waiting. A real attacker
  submitting over the wire pays HTTP framing instead, which is worse for them —
  but they also do not have to be a thread on the victim's own machine.
- **This is the cheapest possible attack.** Every spam intent here is one the
  gate rejects, so it costs the attacker nothing but the submit itself. Nothing
  in the system rate-limits, charges or authenticates it.

The fix has the same shape as the one section 3 implies — shard admission by
submitter and serialise only the append — but the fix that actually matters here
is upstream of the lock: authenticate the submitter, and price the attempt.
`tests/adversarial.rs` covers the correctness side of all of this; the honest
submitter is never dropped or duplicated under any of these floods, only slowed.

## Bottleneck found and fixed

The first run measured submit rate with the full pipeline consuming the log,
reported per batch so any dependence on log size stayed visible instead of
being averaged away. It collapsed:

| log size | before | after |
|---|---|---|
| 2k | 284 777/s | 1 074 787/s |
| 6k | 105 580/s | 1 524 487/s |
| 10k | 70 423/s | 1 379 746/s |
| 16k | **25 623/s** | **1 300 954/s** |

That 1/n curve was `MemLog::read_from` cloning the **entire** log on every call
and then filtering to the cursor — O(log size) per read rather than O(new
entries). Four consumers wake on every append, so the run cost O(n²).

Copying only the tail past the cursor made the curve flat and the throughput
**~50× higher** at 16k entries. Reporting per batch rather than as one average
is what made the slope legible at all; a single aggregate number would have
shown a mediocre figure and hidden the shape.
