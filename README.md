# EnvPlane Webhook

Stateless GitHub and GitLab webhook receiver for [EnvPlane](https://envplane.dev).

## Responsibilities

- Validate provider signatures before processing events.
- Normalize pull-request and merge-request payloads.
- Submit authorized events to the control-plane jobs API.
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
ENVPLANE_CONTROL_PLANE_TOKEN=write-token \
ENVPLANE_GITHUB_WEBHOOK_SECRET=development-secret \
go run ./apps/webhook
```

The existing environment variable names are retained for runtime compatibility.
The standalone Helm chart is maintained in
[EnvPlane/deploy](https://github.com/EnvPlane/deploy/tree/main/deploy/helm/envplane-webhook).

## Security

Reject unsigned or invalid events before normalization. Keep webhook secrets
and control-plane tokens outside source control and inject them through
Kubernetes Secrets in production.

## Status

Private EnvPlane platform component under active development.
