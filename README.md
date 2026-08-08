# EnvPilot Webhook

Standalone stateless GitHub and GitLab webhook receiver.

```bash
ENVPILOT_CONTROL_PLANE_URL=http://localhost:8080 \
ENVPILOT_CONTROL_PLANE_TOKEN=write-token \
ENVPILOT_GITHUB_WEBHOOK_SECRET=development-secret \
go run ./apps/webhook
```

Endpoints:

- `POST /api/v1/webhooks/github` validates `X-Hub-Signature-256`.
- `POST /api/v1/webhooks/gitlab` validates `X-Gitlab-Token`.
- `GET /health` and `GET /livez` expose health checks.

Valid pull/merge request payloads are normalized and submitted to the
authenticated control-plane `POST /api/v1/jobs` endpoint. Provider secrets and
the control-plane write token must be supplied through a Kubernetes Secret in
production. The standalone Helm chart lives at
`deploy/helm/envpilot-webhook` in the deploy repository.
