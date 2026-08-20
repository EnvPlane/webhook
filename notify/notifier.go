// Package notify exposes the canonical environment notification client.
package notify

import (
	"context"

	"github.com/envplane/contracts/domain"
	"github.com/envplane/webhook/internal/notify"
	"github.com/envplane/webhook/secrets"
)

type SettingsProvider = notify.SettingsProvider
type Notifier = notify.Notifier

func New(settings SettingsProvider, resolver *secrets.Resolver) *Notifier {
	return notify.New(settings, resolver)
}

func NotifyEnvironment(ctx context.Context, notifier *Notifier, environment domain.Environment) error {
	if notifier == nil {
		return nil
	}
	return notifier.NotifyEnvironment(ctx, environment)
}
