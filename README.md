# EnvPlane Webhook

Stateless GitHub and GitLab webhook receiver for [EnvPlane](https://envplane.dev).

## Responsibilities

- Validate provider signatures before processing events.
- Normalize pull-request and merge-request payloads.
- Submit normalized events through the receiver-only control-plane capability.
- Expose health and liveness endpoints.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/webhooks/github` | GitHub events with `X-Hub-Signature-256` validation |
| `POST /api/v1/webhooks/gitlab` | GitLab events with `X-Gitlab-Token` validation |
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
`/api/v1/webhook-receiver/events`; it cannot call control-plane user or admin
APIs. During a staged migration, `ENVPLANE_CONTROL_PLANE_TOKEN` remains a
legacy fallback only when the receiver token is absent. Remove that fallback
after every deployed receiver has been upgraded.
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

GitLab Note Hook author membership checks require `ENVPLANE_GITLAB_API_TOKEN`
whenever `ENVPLANE_GITLAB_WEBHOOK_TOKENS` configures one or more projects. The
current implementation intentionally uses one GitLab API token for all
configured projects; provision it with the minimum `read_api` scope and grant
it access only to the groups and projects served by this webhook. A missing
API token is a startup configuration error, not a runtime fallback. Membership
requests use the configured webhook request timeout and retry/backoff settings.

## Status

Private EnvPlane platform component under active development.
