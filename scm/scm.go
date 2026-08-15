// Package scm exposes the canonical SCM webhook parser to other services.
package scm

import internal "github.com/envpilot/webhook/internal/scm"

type Provider = internal.Provider
type EventAction = internal.EventAction
type PRCommand = internal.PRCommand
type PullRequestEvent = internal.PullRequestEvent
type PullRequestCommand = internal.PullRequestCommand

const (
	ProviderGitHub  = internal.ProviderGitHub
	ProviderGitLab  = internal.ProviderGitLab
	ActionOpen      = internal.ActionOpen
	ActionUpdate    = internal.ActionUpdate
	ActionClose     = internal.ActionClose
	ActionIgnore    = internal.ActionIgnore
	CommandRecreate = internal.CommandRecreate
	CommandDestroy  = internal.CommandDestroy
	CommandPin      = internal.CommandPin
)

func ParseGitHubPRCommand(body []byte) (PullRequestCommand, error) {
	return internal.ParseGitHubPRCommand(body)
}

func ParseGitLabPRCommand(body []byte) (PullRequestCommand, error) {
	return internal.ParseGitLabPRCommand(body)
}

func ParseGitHubPullRequest(body []byte) (PullRequestEvent, error) {
	return internal.ParseGitHubPullRequest(body)
}

func ParseGitLabMergeRequest(body []byte) (PullRequestEvent, error) {
	return internal.ParseGitLabMergeRequest(body)
}
