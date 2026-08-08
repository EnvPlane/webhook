# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=github_token,required=true \
    TOKEN="$(cat /run/secrets/github_token)" && \
    git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/" && \
    GOPRIVATE=github.com/envpilot/* go mod download && \
    rm -f /root/.gitconfig
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/envpilot-webhook ./apps/webhook

FROM alpine:3.21

RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 envpilot && \
    adduser -S -D -H -u 10001 -G envpilot envpilot
COPY --from=builder /out/envpilot-webhook /usr/local/bin/envpilot-webhook
USER 10001:10001
ENTRYPOINT ["envpilot-webhook"]
