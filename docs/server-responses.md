# What the server answers

This page lists the HTTP status codes the cache returns and what each one means for a build client. A request to a cache path is counted in `fscache_http_requests_total` by method and status code once it passes authentication and the path check; 401, 403, and the 400 for an empty, `.` or `..` path segment are not counted. Requests to `/healthz`, `/metrics` and `/statusz` are not counted. It is read from the server code (`internal/server/server.go`, `internal/blobstore/blobstore.go`), not from the clients.

## Cache requests

A cache key is the request path without its leading slash. The cache handles three methods on cache paths: `GET`, `HEAD` and `PUT`.

| Request | Status | When |
|---|---|---|
| `GET` | 200 | The entry exists. The body is the stored bytes, `Content-Type: application/octet-stream`. |
| `GET`, `HEAD` | 404 | No entry under that key. A GET that returns 404 is counted as a cache miss in `fscache_cache_misses_total`. |
| `HEAD` | 200 | The entry exists. The response has `Content-Length` and no body. |
| `PUT` | 201 | The entry was stored. |
| `PUT` | 413 | The body is larger than `FSCACHE_MAX_BODY_BYTES` (default 1 GiB; `0` turns the limit off). Nothing is stored. |
| `PUT` | 413 with the header `X-FSCache-Reject: entry-exceeds-cache-cap` | The entry is larger than the whole cache size `FSCACHE_MAX_BYTES`, when that is set. Nothing is stored and nothing is evicted. The header tells this case apart from the body limit above. |
| `PUT` | 429 with `Retry-After: 1` | More uploads are running at once than `FSCACHE_MAX_CONCURRENT_UPLOADS` allows (`0` turns the bound off). The server does not queue the upload; it refuses it at once. |
| any method except `GET`, `PUT`, `HEAD` | 405 with `Allow: GET, PUT, HEAD` | The method is not part of the cache protocol (for example `DELETE`), on a cache path with no empty, `.` or `..` segment that passed authentication. |
| any | 500 | The store failed in a way that is not the client's doing. The server logs the method, the key and the error. |

## Key rules

A key is accepted when all of these hold:

- it has at most 16 segments (segments are separated by `/`);
- each segment is 1 to 255 characters from `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`;
- no segment is `.` or `..`, written literally or percent-encoded;
- no segment is empty, so a doubled slash or a trailing slash is refused.

A request that breaks a rule gets **400 `invalid key`**, with no redirect, and nothing is stored. Percent-encoded characters are decoded before the character check, so a space or a `+` in a key is refused too.

## Reserved paths

`/`, `/healthz`, `/metrics` and `/statusz` belong to the server and are read-only. `GET` and `HEAD` work on them. Any other method (a `PUT` or a `DELETE`, for example) gets **405 with `Allow: GET, HEAD`**, and nothing is stored, so a cache key can never shadow one of them. `GET /` returns a small HTML landing page.

## Authentication

When `FSCACHE_USERNAME` and `FSCACHE_PASSWORD` are set:

| Status | When |
|---|---|
| 401 with `WWW-Authenticate: Basic realm="fosterstack-cache"` | The request has no credentials or the wrong ones. |
| 403 `read-only credentials` | The credentials are the read-only pair (`FSCACHE_RO_USERNAME`, `FSCACHE_RO_PASSWORD`) and the request is not a `GET` or `HEAD`. There is no `WWW-Authenticate` header, because sending the same credentials again cannot help. |

`/healthz` and `/metrics` stay open without credentials, for probes and scrapers. The cache paths, `/statusz` and the landing page at `/` require them. A server with no credentials set accepts requests that carry an `Authorization` header and ignores it.

Where to set these variables: [Docker](docker-deploy.md#configuration), [Kubernetes](kubernetes.md), [Gradle](gradle.md), [Maven](maven.md).
