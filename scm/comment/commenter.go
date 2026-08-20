// Package comment exposes the canonical SCM PR commenter.
package comment

import "github.com/envplane/contracts/domain"

import internal "github.com/envplane/webhook/internal/scm/comment"

type Commenter = internal.Commenter
type Config = internal.Config
type TokenResolver = internal.TokenResolver
type SCMCommenter = internal.SCMCommenter

func New(cfg Config) *SCMCommenter { return internal.New(cfg) }
func BuildEnvironmentComment(environment domain.Environment) string {
	return internal.BuildEnvironmentComment(environment)
}
