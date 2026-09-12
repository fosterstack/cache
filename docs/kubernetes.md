# Deploying on Kubernetes

Plain manifests, no Helm — a Deployment, a PVC, a Service, and a
`securityContext` you can defend in a review. Copy the four blocks below
into one file and `kubectl apply -f` it. A Helm chart is planned
post-launch; until then this page is the supported path.

> **Pre-beta.** These manifests are validated against the Kubernetes API
> schema and match how the image behaves (verified against
> `ghcr.io/fosterstack/cache:X.Y.Z`), but FosterStack Cache has not yet
> been through a beta on a production cluster. Treat it accordingly.

## Read this before you scale

**Run exactly one replica. Do not scale horizontally.** The metadata index
is a [bbolt](https://github.com/etcd-io/bbolt) database, and bbolt is
single-writer by design: the file is held under an exclusive lock by one
process. A second pod pointed at the same volume does not share the cache —
it blocks on the lock or fails to start. Two pods on *different* volumes
give you two half-populated caches and a hit rate that depends on which one
the load balancer picked.

Two consequences worth encoding in the manifest, both below:

- `replicas: 1`, and `strategy: Recreate` — the default `RollingUpdate`
  would start the new pod before terminating the old one, and the two would
  contend for the same lock during every rollout.
- `ReadWriteOnce` on the PVC, which is what single-writer requires.

A cache is a fail-safe dependency: if it is briefly down during a rollout,
builds miss the cache and run slower. Nothing breaks. Trading a few seconds
of that for HA complexity is not a good trade at this stage. HA/replication
is a paid-tier roadmap item, not something to improvise with `replicas: 2`.

## Sizing, in Kubernetes terms

The general guidance is stated as machines — 1 vCPU and 1 GB minimum, see
[Sizing](docker-deploy.md#sizing). On Kubernetes the contract is pod resources,
so here is the translation, which is what the Deployment below already sets:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    memory: 512Mi
```

Requests are what the scheduler reserves; the limit is where the kernel kills
the container. There is no CPU limit on purpose — a CPU limit throttles rather
than kills, and throttling a cache during a burst is the opposite of what you
want.

**A 1 GB node does not have 1 GB to give you.** The kubelet, the CNI, and the
provider's own agents take roughly half of a small node before your pod is
scheduled. The smallest practical node on managed Kubernetes is 2 GB. If you
size a node pool from the 1 GB machine minimum, the pod will not schedule.

Disk is the variable that matters: size the PVC from `FSCACHE_MAX_BYTES` plus
about 20% headroom, not the other way round.

## Secret (credentials)

Every manifest on this page uses the same `fscache-auth` Secret — the server
reads it, and in-cluster runners read it too, so there is one credential to
rotate rather than two that can drift apart.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fscache-auth
type: Opaque
stringData:
  username: gradle
  password: CHANGE-ME        # generate: openssl rand -base64 24
```

`stringData` is plain text in the manifest, which is fine for a value you keep
in a sealed-secrets or external-secrets pipeline and wrong for one you commit
as-is. Do not commit a real password.

## PersistentVolumeClaim

Size this from your eviction cap plus ~20% headroom — see
[Sizing](docker-deploy.md#sizing).

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fscache-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
  # storageClassName: fast-ssd   # set to taste; omitted = cluster default
```

## Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fscache
  labels:
    app.kubernetes.io/name: fscache
spec:
  replicas: 1                     # single-writer bbolt — see above
  strategy:
    type: Recreate                # never two pods on one volume
  selector:
    matchLabels:
      app.kubernetes.io/name: fscache
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fscache
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532            # makes the PVC writable by the image user
        seccompProfile:
          # Applies the container runtime's default syscall filter. It is
          # required by the restricted Pod Security Standard, and free
          # hardening for a static Go binary that makes no exotic syscalls.
          type: RuntimeDefault
      containers:
        - name: fscache
          image: ghcr.io/fosterstack/cache:X.Y.Z
          ports:
            - name: http
              containerPort: 8080
          env:
            - name: FSCACHE_DATA_DIR
              value: /data        # required — see "The data directory"
            - name: FSCACHE_MAX_BYTES
              value: "42949672960"   # 40 GiB, under the 50Gi PVC above
            # Credentials come from the fscache-auth Secret below. Both keys
            # must be set or neither; the server refuses to start with one.
            - name: FSCACHE_USERNAME
              valueFrom:
                secretKeyRef:
                  name: fscache-auth
                  key: username
            - name: FSCACHE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: fscache-auth
                  key: password
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 3
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /healthz
              port: http
            periodSeconds: 10
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              memory: 512Mi
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: fscache-data
```

**No `cpu` limit, on purpose.** A CPU limit throttles rather than protects
here; the `requests` reserve what the server needs and the memory limit is
the guard that matters.

**The probes are `httpGet`, not `exec`.** The image is distroless — no
shell, no `curl` — so an `exec` probe has nothing to run. Same reason the
[Docker deploy doc](docker-deploy.md) ships no container `HEALTHCHECK`.

## The data directory

`FSCACHE_DATA_DIR` is **required** in this manifest. The image sets no
default for it, so the server falls back to `./data` relative to its
working directory `/home/nonroot` — which on Kubernetes is the pod's
ephemeral writable layer, not your PVC. Omit the env var and you get a
cache that appears to work and silently loses everything on every restart.
Set it to the same path as `volumeMounts[].mountPath`.

## securityContext

Everything in the manifest above was verified against the published image,
not assumed:

| Setting | Supported | Why |
|---|---|---|
| `runAsNonRoot: true` | yes | image `User` is the numeric uid `65532`, which the kubelet can verify as nonroot without resolving a name |
| `runAsUser` / `runAsGroup: 65532` | yes | matches the `gcr.io/distroless/static:nonroot` base |
| `fsGroup: 65532` | **required** | a freshly provisioned PVC is `root`-owned; without `fsGroup` the nonroot process cannot create the blob store and the pod crash-loops |
| `readOnlyRootFilesystem: true` | yes | the server writes only inside its data directory — no temp files elsewhere, no `/tmp` use |
| `capabilities: drop: ["ALL"]` | yes | it binds `:8080`, an unprivileged port, so it needs none |
| `allowPrivilegeEscalation: false` | yes | static binary, no setuid anything |
| `seccompProfile: RuntimeDefault` | yes | nothing exotic in the syscall surface |

There is deliberately no `privileged`, no host networking, and no
`hostPath` anywhere in this deployment. If your cluster runs Pod Security
admission, these manifests satisfy the `restricted` profile.

## Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: fscache
  labels:
    app.kubernetes.io/name: fscache
spec:
  selector:
    app.kubernetes.io/name: fscache
  ports:
    - name: http
      port: 80
      targetPort: http
```

## In-cluster runners (the common case)

If your CI runners already run in this cluster — GitHub Actions Runner
Controller, GitLab runners, Jenkins agents — you are done after the manifests
above. No load balancer, no ingress controller, nothing billed.

Point the build at the cluster-internal DNS name:

```kotlin
// settings.gradle.kts
// FosterStack Cache — remote Gradle build cache.
// https://github.com/fosterstack/cache
buildCache {
    remote<HttpBuildCache> {
        url = uri("http://fscache.fscache-ns.svc.cluster.local/")
        isAllowInsecureProtocol = true
        isPush = true
        credentials {
            username = System.getenv("FSCACHE_USERNAME")
            password = System.getenv("FSCACHE_PASSWORD")
        }
    }
}
```

Replace `fscache-ns` with the namespace you deployed into. The trailing slash
matters — Gradle appends the cache key directly to the URL.

`isAllowInsecureProtocol = true` is required for **any** non-localhost `http://`
URL, cluster-internal included. This is the textbook case where it is justified:
the traffic never leaves the cluster network, and terminating TLS on a
service-to-service hop inside the same cluster buys little for the operational
cost.

**Wire the credentials into the runner too.** Configuring the server alone is
half the plumbing — the build needs the same Secret in its environment, or every
request 401s silently (see [gradle.md](gradle.md#5-credentials-that-stop-working-on-monday)):

```yaml
# In your runner pod spec / ARC RunnerScaleSet template
spec:
  containers:
    - name: runner
      env:
        - name: FSCACHE_USERNAME
          valueFrom:
            secretKeyRef:
              name: fscache-auth    # same Secret the server uses
              key: username
        - name: FSCACHE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: fscache-auth
              key: password
```

The explicit `secretKeyRef` mapping matters: the Secret's keys are
`username` and `password`, so an `envFrom` shortcut would inject variables
with *those* names — not the `FSCACHE_USERNAME` and `FSCACHE_PASSWORD` the
`settings.gradle.kts` above reads — and every request would 401 silently.
(An earlier revision of this page made exactly that mistake.)

## Reaching it from outside the cluster

### First: a smoke test with no exposure at all

`port-forward` exercises the whole stack — Deployment, PVC, probes, Service —
without provisioning anything or exposing anything:

```sh
kubectl port-forward svc/fscache 8080:80
```

Then, in another terminal:

```sh
# healthz and metrics stay open without credentials:
curl -s localhost:8080/healthz                                   # -> ok
curl -s localhost:8080/metrics | grep fscache_cache

# the cache surface needs the credentials from the fscache-auth Secret:
curl -s -u gradle:CHANGE-ME -X PUT --data-binary 'hello' \
  localhost:8080/testkey123                                      # stores it
curl -s -u gradle:CHANGE-ME localhost:8080/testkey123            # -> hello
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/testkey123  # -> 401 without them
```

If those four work, the deployment is correct and anything that fails later is
a networking problem, not a cache problem.

### Service type: LoadBalancer (the recommended external path)

For runners outside the cluster, this is the simplest thing that works. It needs
no ingress controller, works on every managed Kubernetes, and provisions in a
couple of minutes:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: fscache-lb
  labels:
    app.kubernetes.io/name: fscache
  annotations:
    # Provider-side TLS termination, DigitalOcean's spelling. Every managed
    # provider has an equivalent annotation; check yours.
    service.beta.kubernetes.io/do-loadbalancer-certificate-id: "<cert-uuid>"
    service.beta.kubernetes.io/do-loadbalancer-protocol: "https"
spec:
  type: LoadBalancer
  selector:
    app.kubernetes.io/name: fscache
  ports:
    - name: https
      port: 443
      targetPort: http
```

It is a raw public endpoint, so **pair it with Basic Auth** — the `fscache-auth`
Secret above is already wired into the Deployment. A cache on a public address
with no auth is a world-writable blob store that anyone can poison.

A load balancer costs money for as long as it exists. That is the trade against
port-forward, which costs nothing and cannot serve real traffic.

### If you already operate a routing layer

Only if your platform team already runs one. **We do not tell you to install an
ingress controller** — a build cache is one service on one port, and your
routing layer is your choice, not ours to pick.

The maintained shape is Gateway API:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: fscache
spec:
  parentRefs:
    - name: your-existing-gateway     # whatever your platform already runs
  hostnames:
    - cache.example.com
  rules:
    - backendRefs:
        - name: fscache
          port: 80
```

<details>
<summary>Legacy Ingress — only if your platform already runs a supported ingress controller</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fscache
  annotations:
    # ingress-nginx-family syntax. Other controllers spell this differently,
    # and Gateway API does not use annotations for it at all.
    nginx.ingress.kubernetes.io/proxy-body-size: "1024m"
spec:
  ingressClassName: your-controller
  tls:
    - hosts: [cache.example.com]
      secretName: fscache-tls
  rules:
    - host: cache.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: fscache
                port:
                  number: 80
```

Note that `ingress-nginx` reached end of maintenance in March 2026 — no further
releases, bug fixes, or security patches. If that is what your cluster runs, the
migration is yours to plan; we are not going to recommend you install it. The
Kubernetes Ingress API itself is not deprecated, and other ingress controllers
remain actively maintained.

</details>

**Whatever sits in front, it must pass large bodies.** Cache entries are
routinely tens of megabytes and most proxies default to 1 MiB, which turns into
silently failed uploads rather than a visible error. The annotation above is
ingress-nginx-family-specific; the universal requirement is that every proxy in
the path allows bodies at least as large as the server's own
`FSCACHE_MAX_BODY_BYTES` (1 GiB by default).

**Terminate TLS in front.** The server speaks plain HTTP and has no certificate
handling of its own, by design.

## Applying these manifests

They are one coherent set: the Secret, PVC, Deployment and Service share the
`app.kubernetes.io/name: fscache` label and reference each other by the names
used above. Apply them as written and they work together.

Two things that bite when splitting them into files:

- `kubectl apply -f <directory>` ignores files that are not `.yaml`/`.yml`/`.json`.
  A manifest saved as `deployment.txt` is silently skipped.
- Multiple documents in one file need `---` separators between them.

## Verify what you're running

Confirm the image is the real, signed, attested thing before it goes into
a cluster — see [Verify our images](verify-images.md), which includes a
[Kyverno policy](verify-images.md#5-enforcing-this-in-your-own-cluster-kyverno)
to enforce signature verification at admission.
