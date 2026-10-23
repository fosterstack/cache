# After a crash or a forced stop

This page says what the server does when it did not shut down cleanly, and what you see. It is read from `cmd/fscache/main.go` (the marker and the reconcile) and from [Kubernetes](kubernetes.md#startup-and-reconcile).

## The marker

The server writes a marker file in the data directory when it starts and removes it on a clean shutdown. A clean shutdown is a `SIGTERM` or `SIGINT` that the server finishes handling (it waits up to 10 seconds for requests in flight). A kill, a crash, a power loss or a stop that runs out of grace time leaves the marker in place. A clean restart skips the work below.

## What happens at the next start

When the marker is present at startup, the server reconciles its two stores before it serves. The blob files are the truth; the metadata index can be rebuilt from them.

- A blob with no metadata record is adopted (its size is read from the disk and its recency is set to now).
- A metadata record with no blob is dropped.
- Stale temporary files are removed.
- The totals are recomputed.

The server logs a warning when it starts the reconcile and an info line with the counts when it ends (`adopted_blobs`, `dropped_records`, `removed_temp_files`, and the duration). The exact lines are in [logging](logging.md).

## What you see while it runs

The listening socket is already open, so a TCP connection succeeds, but `/healthz` does not answer until the reconcile finishes. On a large store that can be longer than a liveness probe allows; [Kubernetes](kubernetes.md#startup-and-reconcile) shows how to give it room with a startup probe.

If the reconcile itself fails, the process exits with an error and the marker stays, so the next start reconciles again.
