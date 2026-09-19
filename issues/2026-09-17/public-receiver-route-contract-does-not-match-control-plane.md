# Public receiver route contract does not match control plane

## Observed

With `webhook.publicEndpoint.mode=external`, the umbrella chart sends the
public endpoint to the control plane. The control plane registers GitLab at
`/api/v1/webhook-receiver/gitlab` and probes
`/api/v1/webhook-receiver/readyz`. The standalone `envplane-webhook` service
instead exposed `/api/v1/webhooks/gitlab` and `/readyz` only.

An externally reachable temporary tunnel therefore returned `404` to both the
registered GitLab URL and the control-plane readiness probe.

## Impact

Webhook automation cannot be configured through the documented umbrella
external-endpoint flow, even when the receiver is healthy and publicly
reachable.

## Implementation prompt

Keep the public callback contract stable by making the standalone receiver
accept the canonical control-plane routes as aliases. Preserve the existing
receiver routes for compatibility. Add route-level tests for GitLab delivery
and readiness through the canonical paths, then cover the umbrella external
endpoint integration in an E2E contract.

## Acceptance criteria

- `GET /api/v1/webhook-receiver/readyz` returns the receiver readiness proof.
- `POST /api/v1/webhook-receiver/gitlab` processes the same signed GitLab
  delivery as the existing receiver path.
- Existing public receiver routes remain supported.
- A temporary HTTPS endpoint can be registered and verified without a 404.
