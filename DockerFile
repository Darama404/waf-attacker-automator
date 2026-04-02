# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM golang:1.22-alpine AS builder

# Install git dan ca-certificates
# git: diperlukan jika ada dependency dari VCS
# ca-certificates: diperlukan untuk HTTPS calls ke Cloudflare API
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy dependency files terlebih dahulu
# Layer ini di-cache selama go.mod & go.sum tidak berubah
# Sangat mempercepat rebuild saat hanya mengubah kode
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy seluruh source code
COPY . .

# Build binary
# CGO_ENABLED=0  : static binary, tidak bergantung pada C library host
# -ldflags "-w -s": strip debug info & symbol table → binary lebih kecil
# -X main.version : inject version dari build arg
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION}" \
    -o /waf-attacker-automator \
    ./cmd/main.go

# =============================================================================
# Stage 2: Runtime
# Menggunakan distroless — tidak ada shell, tidak ada package manager
# Attack surface minimal, image size ~8MB
# =============================================================================
FROM gcr.io/distroless/static-debian12

# Copy ca-certificates dari builder untuk HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data (opsional, untuk log timestamp yang akurat)
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary dari stage builder
COPY --from=builder /waf-attacker-automator /waf-attacker-automator

# Jalankan sebagai non-root user (distroless menyediakan user "nonroot" dengan UID 65532)
USER nonroot:nonroot

ENTRYPOINT ["/waf-attacker-automator"]