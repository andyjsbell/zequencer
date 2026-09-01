# Benchmark

```
cargo bench --bench submit
```

Source: `benches/submit.rs`. Raw output: `BENCH.txt`.
Measured on an Apple M4 Pro (14 cores), rustc 1.96.0, release build.

## What is measured

`admit_and_append` — the content hash, the admission checks and the log append.

Deliberately excluded: HTTP framing (that is axum's cost, not the protocol's) and
durability (`MemLog`; a durable log is dominated by fsync). Both would bury the
numbers this design can actually move. Absolute figures are not the point —
where the time goes is.

## Submit latency

One thread, 50 000 samples after 5 000 warmup:

| | |
|---|---|
| p50 | **0.42 µs** |
| p95 | **0.54 µs** |
| p99 | 1.21 µs |
| max | 686.79 µs |
| mean | 0.48 µs |
| rate | 2.07 M submit/s |

The max is three orders above p99: it is the `MemLog` vector reallocating as it
grows, plus OS scheduling. A ring buffer or a pre-sized log would remove it.

## Where a submit goes

| | mean | share | |
|---|---|---|---|
| `Intent::id` (keccak over content) | 0.20 µs | 61% | **outside** the lock |
| admission check + log append | 0.13 µs | 39% | **inside** the lock |

Hashing dominates, and it already happens before the lock is taken — the
critical section is only the part that must be serial. The 0.13 µs critical
section implies a ceiling near 7.6 M submit/s.

## Burst throughput

20 000 submits, each thread on its own address so nothing is rejected and the
only shared thing is the admission lock:

| threads | total/s | per-thread/s | p95 |
|---|---|---|---|
| 1 | 2 709 094 | 2 709 094 | 0.38 µs |
| 2 | 1 931 512 | 965 756 | 5.12 µs |
| 4 | 948 617 | 237 154 | 13.29 µs |
| 8 | 967 293 | 120 912 | 36.17 µs |

**Throughput falls as threads rise.** This is the expected shape, not a
surprise: the critical section is ~0.13 µs, far shorter than the cost of
contending for a mutex, so extra threads mostly queue and ping-pong a cache
line. p95 degrades 95× from one thread to eight.

The honest reading is that submit is *already* cheap enough single-threaded
(2.7 M/s) that the lock is not the practical constraint, and that the lock
buys something concurrency cannot: it is what makes replay and nonce ordering
impossible to race, and it is where the log's total order comes from. If
submit throughput ever did need to scale, the shape of the fix is to shard
admission by submitter — nonce state is already per-submitter — and serialise
only the append.

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
