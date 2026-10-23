# What the server logs

This page lists what the server writes to its log. It covers the lines you will see most often, not every message.

## Format

The server writes one JSON object per line to standard output (Go's `slog` JSON handler). Each line has `time`, `level` and `msg`, plus the fields named below. There is no setting for the log level or the format.

## No access log

The server does not write a line per request. Requests log only when something goes wrong (a store failure, a short write to the client, a failed metadata or gauge update) or when a write triggers eviction. These lines never carry a request body, a credential or a client address. Per-request counts and statuses are in the metrics instead ([server responses](server-responses.md) says which requests are counted).

## The startup line

When the listener is open the server writes one line, `fscache: starting`, with these fields:

| Field | Value |
|---|---|
| `version` | The version of the binary. |
| `addr` | The address actually bound (with `:0` it shows the real port). |
| `data_dir` | The data directory. |
| `max_bytes` | `FSCACHE_MAX_BYTES` as a number (`0` means no cap). |
| `auth` | `enabled` or `disabled`. |
| `tls` | `enabled` or `disabled`. |
| `fips140` | `off`; `off (…)` when the validated module is linked but FIPS 140 mode is off; or `active (…)` when FIPS 140 mode is on, with a short note in brackets. |

## Other lines

| Message | Level | When | Fields |
|---|---|---|---|
| `fscache: unknown environment variable ignored` | warn | A variable starting with `FSCACHE_` that the server does not know. One line per distinct name. The value is never logged. | `name`, and `did_you_mean` when a known name is close |
| `fscache: unclean shutdown detected, reconciling stores before serving` | warn | The previous run did not shut down cleanly. | none |
| `fscache: reconciled` | info | The reconcile after an unclean shutdown is done. | `duration`, `adopted_blobs`, `dropped_records`, `removed_temp_files` |
| `cache: reconciliation complete` | info | The same reconcile, logged by the cache. | `adopted_blobs`, `dropped_records`, `removed_temp_files` |
| `fscache: shutting down` | info | The server received `SIGTERM` or `SIGINT`. | none |
| `fscache: unclean marker kept, next start reconciles` | warn | The run ended without a clean shutdown (a failed startup reconcile, a serving error or a shutdown error); the next start will reconcile. | none |
| `cache: evicted entries to fit size cap` | info | Entries were evicted to stay under `FSCACHE_MAX_BYTES`. | `count`, `max_bytes` |
| `server: store error` | error | A request hit a store failure and got a 500. | `method`, `key`, `error` |
| `server: GET: short write to client` | warn | A GET could not be fully written to the client. | `key`, `error` |
| `store_writable: the data directory is not writable` (error) and `store_writable: the data directory is writable again` (info) | error, info | A write or free-space check on the data directory failed, or both pass again. | `dir`, `free_bytes`, plus `error` on the first line |
| `fscache: fatal` | error | The server could not start or stopped with an error. The process exits with code 1. | `error` |

Where startup is slow after a crash, see [Kubernetes](kubernetes.md#startup-and-reconcile); for the settings that start the server, see [Docker](docker-deploy.md#configuration).
