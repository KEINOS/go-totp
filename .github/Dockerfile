# =============================================================================
#  Test Container for Vaious Go Versions (Last Updated: 2023-03-17)
# =============================================================================
# Default version: golang:alpine
ARG VARIANT="alpine"

# -----------------------------------------------------------------------------
#  Main Stage
# -----------------------------------------------------------------------------
FROM golang:${VARIANT}

# Install git, make and other basic commands for building
RUN apk add --no-cache \
    alpine-sdk \
    build-base

# Install go tools/packages if set
ARG GOINSTALL
ENV GOINSTALL=${GOINSTALL}
COPY ./.github/goinstall.sh /goinstall.sh
RUN /goinstall.sh

WORKDIR /workspaces

ENTRYPOINT go mod download && go test -race ./...
