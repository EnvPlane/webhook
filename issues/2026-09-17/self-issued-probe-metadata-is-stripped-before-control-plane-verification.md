# Self-issued probe metadata is stripped before control-plane verification

## Observed

The standalone receiver only relays the probe marker and nonce when a separate
receiver credential is sent in the public callback. The control plane already
authenticates the GitLab signing secret and binds the nonce to the pending
proof, so the extra receiver credential prevents Bootstrap self-probes without
adding a necessary trust boundary.

## Implementation prompt

Forward probe metadata without forwarding or requiring a receiver credential.
The control plane remains the sole verifier of the GitLab signing secret and
the high-entropy pending nonce. Do not store or render either secret.

## Acceptance criteria

- A self-issued probe reaches control plane with its marker and nonce.
- The receiver does not require or expose an additional credential externally.
- Control plane continues to reject invalid GitLab signing secrets and nonce mismatches.
