// Package secrets exposes the canonical external secret resolver.
package secrets

import (
	"net/http"

	internal "github.com/envpilot/webhook/internal/secrets"
)

type Resolver = internal.Resolver
type KubernetesConfig = internal.KubernetesConfig
type VaultConfig = internal.VaultConfig
type ValidationResult = internal.ValidationResult
type Option = internal.Option

func NewResolver(options ...Option) *Resolver   { return internal.NewResolver(options...) }
func WithHTTPClient(client *http.Client) Option { return internal.WithHTTPClient(client) }
func WithKubernetesConfig(config KubernetesConfig) Option {
	return internal.WithKubernetesConfig(config)
}
func WithVaultConfig(config VaultConfig) Option            { return internal.WithVaultConfig(config) }
func HTTPClientWithCA(caPath string) (*http.Client, error) { return internal.HTTPClientWithCA(caPath) }
