# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=github_token,required=true \
    TOKEN="$(cat /run/secrets/github_token)" && \
    git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/" && \
    GOPRIVATE=github.com/envplane/* go mod download && \
    rm -f /root/.gitconfig
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/envplane-webhook ./apps/webhook

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk upgrade --no-cache libcrypto3 libssl3 && \
    apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 envplane && \
    adduser -S -D -H -u 10001 -G envplane envplane
COPY --from=builder /out/envplane-webhook /usr/local/bin/envplane-webhook
USER 10001:10001
ENTRYPOINT ["envplane-webhook"]
