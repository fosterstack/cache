# Deploying on Kubernetes

Plain manifests, no Helm — a Deployment, a PVC, a Service, and a
`securityContext` you can defend in a review. Copy the four blocks below
into one file and `kubectl apply -f` it. A Helm chart is planned
post-launch; until then this page is the supported path.

> **Pre-beta.** These manifests are validated against the Kubernetes API
> schema and match how the image behaves (verified against
> `ghcr.io/fosterstack/cache:0.1.0`), but FosterStack Cache has not yet
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
          type: RuntimeDefault
      containers:
        - name: fscache
          image: ghcr.io/fosterstack/cache:0.1.0
          ports:
            - name: http
              containerPort: 8080
          env:
            - name: FSCACHE_DATA_DIR
              value: /data        # required — see "The data directory"
            - name: FSCACHE_MAX_BYTES
              value: "42949672960"   # 40 GiB, under the 50Gi PVC above
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
spec:
  selector:
    app.kubernetes.io/name: fscache
  ports:
    - name: http
      port: 80
      targetPort: http
```

In-cluster CI runners can point straight at
`http://fscache.<namespace>.svc.cluster.local/` — note the trailing slash,
which Gradle needs (the whole request path is the cache key). See
[Gradle setup](gradle.md) / [Maven setup](maven.md).

## Ingress and TLS

Only expose this outside the cluster if runners live outside it. If you do:

- **Terminate TLS at the ingress.** The server speaks plain HTTP; it has no
  certificate handling of its own, by design.
- **Turn on Basic Auth at the same time** — set `FSCACHE_USERNAME` and
  `FSCACHE_PASSWORD` (from a `Secret`, both together or neither). An
  unauthenticated cache reachable from the internet is a public read/write
  blob store.
- **Raise the ingress body-size limit.** Cache entries are routinely tens
  of megabytes and ingress-nginx defaults to 1 MiB, which silently turns
  into failed uploads:
  `nginx.ingress.kubernetes.io/proxy-body-size: "1024m"`. Keep it at or
  above the server's own `FSCACHE_MAX_BODY_BYTES` (1 GiB default).

## Verify what you're running

Confirm the image is the real, signed, attested thing before it goes into
a cluster — see [Verify our images](verify-images.md), which includes a
[Kyverno policy](verify-images.md#5-enforcing-this-in-your-own-cluster-kyverno)
to enforce signature verification at admission.
