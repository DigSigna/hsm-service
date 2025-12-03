# Build stage - Solo compilación
FROM golang:1.25.4-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compilar CON CGO habilitado para PKCS#11
RUN CGO_ENABLED=1 GOOS=linux go build -o api ./cmd/api

# Runtime stage - MINIMAL
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Solo librerías runtime necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libsofthsm2 \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/
COPY --from=builder /app/api .

# Health check MEJORADO
# HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
#     CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["./api"]