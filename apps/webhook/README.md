# envpilot-webhook

Production entrypoint for the standalone webhook receiver:

```bash
go build ./apps/webhook
```

Configuration is environment-only; see the repository README for required
control-plane and provider credentials.
