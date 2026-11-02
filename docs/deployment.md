# Deployment

t10 auth runs from one image in both environments, and the difference is only in configuration.

| | Local | Production |
| --- | --- | --- |
| Tool | Docker Compose, `docker-compose.yml` | Kubernetes with Kustomize, `deploy/k8s/` |
| Mode | `AUTH_DEV_MODE=true`, seeded users, open registration | `AUTH_DEV_MODE=false`, registration by invitation |
| Postgres | A container | Managed, outside the cluster |
| Replicas | 1 | 2 |
| TLS and public access | None, on `localhost:8081` | At the ingress |
| Secrets | Dev defaults in the Compose file | Kubernetes Secrets, never in this repo |
| Setup | The `seed` service runs `auth-setup` | The setup Job runs `auth-setup` |

For local use, see [Run locally](../README.md#run-locally).

## Layout

```text
deploy/
  setup.sh                     Installed as auth-setup. Creates the first admin and service accounts
  k8s/
    base/                      Namespace, Deployment, Service, Ingress, budget and network policy
    setup/                     The one-shot setup Job
    overlays/production/       Image, host and public settings
    overlays/production/setup/ The Job, with the production image
```

Add an overlay for each further environment, such as staging.

## How it's designed

- **Portable ingress:** the manifests use the standard `Ingress` API with no controller annotations, so the choice of controller and cloud stays open.
- **Setup runs on its own:** the server refuses to start while a runtime in `clients.yaml` has no service account, so accounts must exist first. Until then, pods crash-loop and then recover without help.
- **Migrations stay at startup:** an advisory lock in Postgres serializes the replicas, so no separate migration step is needed. Rate limits are also in Postgres, so replicas share them.
- **One client list:** `clients.yaml` is built into the image, because it's reviewed with the code that reads it. A change ships as a new image, while Compose mounts the file for quick edits.
- **Least access:** pods run as non-root with a read-only filesystem, no Linux capabilities and no Kubernetes API token. The namespace enforces the `restricted` Pod Security level.
- **Closed network:** only the ingress controller and labelled t10 services can connect, and pods can only reach DNS and port 5432. This needs a CNI that enforces NetworkPolicy.
- **Memory:** an Argon2 hash uses 64 MiB, and the server runs half as many at once as it has CPUs. The CPU limit of 2 therefore means one hash at a time per replica, which a 384 MiB limit covers. If you raise the CPU limit, raise memory and `GOMEMLIMIT` too.

## First deploy

**1. Choose the values.** Replace every example value in `deploy/k8s/overlays/production/kustomization.yaml` and `setup/kustomization.yaml`: the image, host, ingress class and LiveKit settings. `AUTH_PUBLIC_URL` is the JWT issuer, so changing it later invalidates every verifier's configuration.

**2. Build and push the image.** Use an immutable tag.

```sh
docker build -t registry.example.com/t10/auth-server:0.1.0 .
docker push registry.example.com/t10/auth-server:0.1.0
```

**3. Prepare the database.** Create an empty database and a role that can create schemas. Connect directly rather than through a transaction pooler, because migrations use a session advisory lock. Set `pool_max_conns`, because the default follows the node's CPU count.

**4. Create the namespace and secrets.** Generate the keys with the image, and keep a copy in your secret store. If a secrets operator manages these, have it create the same names and keys.

```sh
IMAGE=registry.example.com/t10/auth-server:0.1.0
kubectl apply -f ../deploy/k8s/base/namespace.yaml   # the workspace owns the namespace
kubectl -n t10 create secret generic auth-server \
  --from-literal=DATABASE_URL='postgres://USER:PASSWORD@HOST:5432/auth?sslmode=verify-full&pool_max_conns=10' \
  --from-literal=AUTH_SIGNING_KEY_CURRENT="$(docker run --rm --entrypoint authctl "$IMAGE" gen-key)" \
  --from-literal=AUTH_TOTP_KEY="$(docker run --rm --entrypoint authctl "$IMAGE" gen-totp-key)" \
  --from-literal=LIVEKIT_API_SECRET='32 or more characters, matching your LiveKit server'
kubectl -n t10 create secret generic auth-server-setup \
  --from-literal=AUTHCTL_PASSWORD='first admin password' \
  --from-literal=AUTH_SETUP_ADMIN=root \
  --from-literal=AUTH_SETUP_TENANT_ID=ten_example \
  --from-literal=AUTH_SETUP_TENANT_NAME='Example' \
  --from-literal=LIVEKIT_AGENT_SECRET="$(openssl rand -base64 32)" \
  --from-literal=AGENT_PI_SECRET="$(openssl rand -base64 32)" \
  --from-literal=T10_COLLAB_SECRET="$(openssl rand -base64 32)"
```

If the database's CA isn't in the image's bundle, `sslmode=verify-full` will fail. Mount the CA and add `sslrootcert`, rather than weakening the mode.

The TLS certificate goes in a Secret called `auth-server-tls`, created by hand or by cert-manager.

**5. Run setup.** The output holds the first admin's recovery codes, so save them and treat the Job's log as a secret.

```sh
kubectl apply -k deploy/k8s/overlays/production/setup
kubectl -n t10 wait --for=condition=complete job/auth-server-setup --timeout=5m
kubectl -n t10 logs job/auth-server-setup
```

**6. Deploy.** Then open the controller to the server.

```sh
kubectl apply -k deploy/k8s/overlays/production
kubectl -n t10 rollout status deploy/auth-server
kubectl label namespace INGRESS_CONTROLLER_NAMESPACE t10.dev/ingress=true
```

**7. Finish.** Copy the service secrets to the runtimes, then delete the setup Secret. Sign in as the first admin, enroll TOTP and generate new recovery codes, especially if the cluster ships pod logs elsewhere.

```sh
kubectl -n t10 delete job auth-server-setup
kubectl -n t10 delete secret auth-server-setup
```

## Ingress requirements

Any controller works if it does the following:

- **Terminates TLS** and redirects http to https. Internal traffic is plain http inside the trust zone.
- **Keeps the client address last in `X-Forwarded-For`.** With `AUTH_TRUST_PROXY=true`, the server treats the last entry as the client. If a cloud load balancer sits in front of the controller, its address must not end up there, or every user shares one rate limit.
- **Keeps query strings out of access logs,** because invitation and reset tokens travel in them.
- **Connects from a namespace labelled `t10.dev/ingress=true`.** A cloud load balancer that targets pod IPs directly has no namespace, so it needs its own rule in the network policy.

## Connecting other services

Use `http://auth-server.t10.svc.cluster.local:8081` for JWKS, tokens and grants, and keep the public URL as `JWT_ISSUER`. To be allowed through, a pod needs the label `t10.dev/auth-client: "true"`, and so does its namespace. `t10` already has it.

## Routine changes

**Upgrades:** change the image in both overlays, then apply. Replicas roll one at a time, and a new pod that can't start leaves the old ones serving.

**Migrations:** new pods migrate while old pods are still running, and migrations are forward-only. Each one must therefore work with the previous version: add columns first, and drop them in a later release. `kubectl rollout undo` is only safe under this rule.

**Adding a runtime:** add it to `clients.yaml` and `deploy/setup.sh`, then build the image, run setup with a new secret, and deploy.

**Rotating a signing key:** the `auth-server` Secret holds `AUTH_SIGNING_KEY_NEXT`, and a pod reads it at startup, so run `kubectl -n t10 rollout restart deploy/auth-server` after each change. Follow the steps in [design.md](design.md#deployment-and-operations).

**Rotating a service secret:** run `authctl` from a shell in a running pod, or from a Job. See [service-api.md](service-api.md).

## Not included

- **Database backups and failover,** which belong to the managed Postgres service.
- **Metrics and tracing:** the server only writes structured logs to stdout today, so use the ingress and `/readyz` for alerts.
- **Autoscaling:** two replicas fit an invite-only launch, and scaling on CPU would respond poorly to Argon2 bursts.
