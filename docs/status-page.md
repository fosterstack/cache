# The landing page and the status page

These read-only paths tell you the server is up and what state it is in. This page is read from `internal/server/status.go` and `internal/server/server.go`.

| Path | Answers | Credentials when authentication is on |
|---|---|---|
| `GET /` | An HTML landing page (200). | Required. |
| `GET /statusz` | The status page for a browser, or JSON for anything else. | Required. |
| `GET /healthz` | `ok` (200). | Not required. |

`/metrics` (Prometheus format) is also open. All of these paths are read-only: any method other than `GET` or `HEAD` gets 405, and they never shadow a cache key ([server responses](server-responses.md)).

## The landing page

Opening the server's address in a browser shows a short page: the version, the FIPS 140-3 note, the uptime, and links to the status page, metrics and health paths, and the project docs. It exists so that the address answers with a page and not an error. Build tools address the server directly; there is nothing to click on it.

## The status page and `/statusz`

`/statusz` returns HTML when the request's `Accept` header contains `text/html`, and JSON otherwise (`curl` gets JSON). Counters are since the process started and are the same numbers `/metrics` reports.

The JSON has these fields: `version`, `revision` and `build_modified` (only when set), `fips140`, `fips140_note`, `uptime_seconds`, `uptime`, `store_bytes`, `max_bytes`, `store_entries`, `cache_hits`, `cache_misses`, `hit_ratio` (only when there is a ratio), `evicted_entries`, `auth_enabled`, `store_writable`, `store_free_bytes` and `put_errors` (a count per reason).

```sh
curl -s localhost:8080/statusz
```

With authentication on, add `-u USER:PASSWORD`.
