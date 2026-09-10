# EnvPlane Webhook

Stateless GitHub and GitLab webhook receiver for [EnvPlane](https://envplane.dev).

## Responsibilities

- Validate GitHub signatures locally and forward GitLab deliveries for
  control-plane signature verification.
- Normalize pull-request and merge-request payloads.
- Submit normalized events through the receiver-only control-plane capability.
- Expose health and liveness endpoints.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/webhooks/github` | GitHub events with `X-Hub-Signature-256` validation |
| `POST /api/v1/webhooks/gitlab` | GitLab events forwarded raw for control-plane validation |
| `GET /health` | Service health |
| `GET /livez` | Process liveness |

## Local development

```bash
ENVPLANE_CONTROL_PLANE_URL=http://localhost:8080 \
ENVPLANE_WEBHOOK_RECEIVER_TOKEN=receiver-token \
ENVPLANE_GITHUB_WEBHOOK_SECRET=development-secret \
go run ./apps/webhook
```

`ENVPLANE_WEBHOOK_RECEIVER_TOKEN` is a machine credential restricted to
receiver endpoints; it cannot call control-plane user or admin APIs.
`ENVPLANE_CONTROL_PLANE_TOKEN` is retained only for legacy normalized command
delivery. GitLab signing secrets are not configured in this pod: Merge Request
and Note Hook payloads are forwarded raw, and control-plane verifies
`X-Gitlab-Token` against its encrypted per-project credential.
The standalone Helm chart is maintained in
[EnvPlane/deploy](https://github.com/EnvPlane/deploy/tree/main/deploy/helm/envplane-webhook).

## Security

Reject unsigned or invalid events before normalization. Keep webhook secrets
and machine credentials outside source control and inject them through
Kubernetes Secrets in production. The umbrella chart creates a stable
`envplane-webhook-receiver` Secret on first install; Helm upgrades, rollbacks,
and uninstalls preserve it. Rotate by adding the old value as
`ENVPLANE_WEBHOOK_RECEIVER_PREVIOUS_TOKEN` to control-plane, changing the
receiver Secret, then removing the previous value after receiver rollout.

## Migration preflight

Before enabling the Helm-managed receiver, verify that the public callback URL
uses HTTPS, DNS resolves to the webhook ingress, and its TLS certificate is
valid. For local development, a public HTTPS tunnel is required; a ClusterIP
service is not reachable by GitHub or GitLab. Keep existing provider webhook
URLs until a signed test delivery reaches the new receiver. Rolling back is
safe: retain the managed Secret and restore the previous receiver deployment
before changing the provider callback URL.

GitLab Note Hook author membership checks still use the GitLab API token in the
receiver, with the minimum `read_api` scope and access limited to the served
groups and projects. This token is separate from the per-project signing
secret. A Note Hook is accepted only after membership authorization and raw
forwarding; the control-plane then performs the signing-secret check.

## GitLab signing-secret migration

GitLab signing secrets remain encrypted in the control plane and are never
loaded into the public webhook receiver pod. The receiver forwards the raw
GitLab body together with `X-Gitlab-Token` to the receiver-only control-plane
endpoint, where the project binding and token are checked in constant time.
`ENVPLANE_GITLAB_WEBHOOK_TOKENS` is not required for this mode and should not be
set in the umbrella deployment. This is a breaking change for installations
that relied on local receiver-side GitLab token validation: configure
`ENVPLANE_CONTROL_PLANE_URL` and `ENVPLANE_WEBHOOK_RECEIVER_TOKEN` instead.

The control plane accepts the current signing secret and the previous secret
only during the configured rotation window. Rotate and reconcile the GitLab
hook without restarting the receiver. The receiver's status endpoint exposes
only safe state and fingerprints, never the signing secret.

## Status

Private EnvPlane platform component under active development.
