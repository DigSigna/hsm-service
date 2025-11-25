# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/api

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates softhsm tzdata

WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/deployments/docker/entrypoint.sh .

# Create SoftHSM token directory
RUN mkdir -p /var/lib/softhsm/tokens && \
    chmod 755 /var/lib/softhsm/tokens

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]