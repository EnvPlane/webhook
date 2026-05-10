# EnvPilot Webhook

SCM webhook and PR/MR event integration boundary.

## Scope

- GitHub and GitLab webhook event parsing.
- Pull request and merge request lifecycle events.
- Comment command parsing and posting.
- Translation from SCM events into EnvPilot environment actions.

## Source Origin

This repository was split from:

- `apps/webhook`
- `internal/scm`
- `internal/scm/comment`
- shared notification/domain packages

## Runtime Note

Webhook HTTP handlers currently live in the control-plane server package. A follow-up extraction should add a standalone webhook binary that calls the control-plane API or publishes jobs.
