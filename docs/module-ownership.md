# Module ownership

`webhook` owns SCM provider payload parsing. Consumers must import
`github.com/envplane/webhook/scm`; they must not copy provider event decoders
into service repositories.

The internal package remains the implementation boundary for the webhook
service, while `scm` is the stable cross-module adapter.
