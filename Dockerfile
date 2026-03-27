
FROM golang:1.26 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Install bun
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

# Install templ
RUN go install github.com/a-h/templ/cmd/templ@v0.3.865

WORKDIR /app

# Copy source
COPY . .

# Install web dependencies
RUN bun i --cwd ./web

# Tidy modules
RUN go mod tidy

# Generate code (templ templates + web assets including icon download and vite build)
RUN go generate ./...

# Build binaries
ARG VERSION=""
RUN CGO_ENABLED=0 GOOS=linux go build -tags=prod \
  -ldflags "-X github.com/almeidapaulopt/tsdproxy/internal/core.version=${VERSION}" \
  -o /tsdproxyd ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /healthcheck ./cmd/healthcheck/main.go


FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /tsdproxyd /tsdproxyd
COPY --from=builder /healthcheck /healthcheck

ENTRYPOINT ["/tsdproxyd"]

EXPOSE 8080
HEALTHCHECK CMD [ "/healthcheck" ]
