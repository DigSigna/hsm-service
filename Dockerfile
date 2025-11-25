# Build stage
FROM golang:1.21-alpine AS builder

# Instalar dependencias de compilación C
RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compilar CON CGO habilitado
RUN CGO_ENABLED=1 GOOS=linux go build -o api ./cmd/api

# Runtime stage
FROM alpine:latest

# Instalar runtime dependencies para HSM
RUN apk --no-cache add ca-certificates pcsc-lite pcsc-lite-dev tzdata 

WORKDIR /root/

COPY --from=builder /app/api .

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["./api"]