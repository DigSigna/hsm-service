SHELL := bash

export MSYS_NO_PATHCONV := 1
export MSYS2_ARG_CONV_EXCL := *

PROJECT_DIR := $(shell pwd)
BUILDER_IMAGE = go-cgo-builder:1.25
OUTPUT = bin/api
SOURCE = ./cmd/api

# 
DOCKER_COMPOSE_DEV = docker-compose -f docker-compose.dev.yml


.PHONY: sonar-up sonar-down sonar-local test coverage lint quality dev dev-up dev-down dev-logs dev-restart dev-shell test dev-keys dev-jwt dev-restart dev-jwt-export dev-aes-key dev-aes-encrypt

# SonarQube Local
sonar-up:
	@echo "Iniciando SonarQube local..."
	docker-compose -f docker/compose/docker-compose.dev.yml up -d

sonar-down:
	@echo "Deteniendo SonarQube local..."
	docker-compose -f docker/compose/docker-compose.dev.yml down

sonar-local:
	@echo "Ejecutando análisis SonarQube local..."
	chmod +x scripts/sonar/sonar-Go.sh
	./scripts/sonar/sonar-Go.sh

# Testing
# test:
# 	@echo "Ejecutando tests..."
# 	go test -v -race -coverprofile=coverage.out ./...

coverage:
	@echo "Generando cobertura..."
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Cobertura generada: coverage.html"

coverage-report:
	@echo "Reporte de cobertura:"
	go test -cover ./...

# Linting
lint:
	@echo "Ejecutando linter..."
	golangci-lint run

# Quality Check Completo
quality: lint test sonar-local

# Development
dev:
	@echo "Iniciando servidor en modo desarrollo..."
	go run cmd/api/main.go

# Build
# build:
# 	@echo "Compilando aplicación..."
# 	go build -o bin/api cmd/api/main.go

# ---------------------------------------------------------
# Build principal: compila el binario para Linux/amd64
# ---------------------------------------------------------
build: builder-image
	@echo ">> Compilando aplicación para Linux amd64 (CGO habilitado)..."
	docker run --rm \
		-v "$(PROJECT_DIR)":/app \
		-w /app \
		$(BUILDER_IMAGE) \
		bash -c "CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o $(OUTPUT) $(SOURCE)"
	@echo ">> Build finalizado: $(OUTPUT)"

# ---------------------------------------------------------
# Imagen builder (solo se construye una vez)
# ---------------------------------------------------------
builder-image:
	@if ! docker image inspect $(BUILDER_IMAGE) >/dev/null 2>&1; then \
		echo '>> Imagen builder no encontrada. Creando $(BUILDER_IMAGE)...'; \
		docker build -t $(BUILDER_IMAGE) -f Dockerfile.builder .; \
	else \
		echo '>> Imagen builder encontrada: $(BUILDER_IMAGE)'; \
	fi

# ---------------------------------------------------------
# Limpieza
# ---------------------------------------------------------
# clean:
# 	@echo ">> Limpiando binarios..."
# 	rm -rf bin/*



docker-build:
	@echo "Construyendo imagen Docker..."
	docker build -t template-go-gin .

# Lint
lint-minimal:
	@echo "Ejecutando linter mínimo..."
	golangci-lint run -c .golangci-minimal.yml


# GHCR build
build-ghcr:
	@echo "Building to GHCR..."
	docker build -t ghcr.io/digsigna/hsm-service/hsm-service:latest -f Dockerfile .
	@echo "Built to GHCR..."
#push to GHCR
push-ghcr:
	@echo 'Pushing to GHCR...'
	docker push ghcr.io/digsigna/hsm-service/hsm-service:latest
	@echo 'Pushed to GHCR...'

# Desarrollo
dev: dev-up dev-logs

dev-restart: dev-down dev-up dev-logs

dev-up:
	@echo "Starting development environment..."
	@$(DOCKER_COMPOSE_DEV) up -d --build
	@echo "Services running:"
	@echo "  - HSM Service: http://localhost:8080"
	@echo "  - Debug: localhost:2345"

dev-down:
	@echo "Stopping development environment..."
	@$(DOCKER_COMPOSE_DEV) down

dev-logs:
	@$(DOCKER_COMPOSE_DEV) logs -f hsm-service

dev-restart:
	@$(DOCKER_COMPOSE_DEV) restart hsm-service

dev-shell:
	@$(DOCKER_COMPOSE_DEV) exec hsm-service sh

# Testing
test:
	@$(DOCKER_COMPOSE_DEV) exec hsm-service go test ./... -v

test-coverage:
	@$(DOCKER_COMPOSE_DEV) exec hsm-service go test ./... -coverprofile=coverage.out
	@$(DOCKER_COMPOSE_DEV) exec hsm-service go tool cover -html=coverage.out -o coverage.html

# Database migrations
migrate-up:
	@$(DOCKER_COMPOSE_DEV) exec hsm-service go run cmd/migrate/main.go up

migrate-down:
	@$(DOCKER_COMPOSE_DEV) exec hsm-service go run cmd/migrate/main.go down

# Clean
clean:
	@$(DOCKER_COMPOSE_DEV) down -v
	@rm -rf ./tmp
	@docker system prune -f

dev-keys:
	@echo "Generando claves de desarrollo..."
	go run scripts/generate-keys/main.go
	@echo "Claves generadas en certs/"
	@echo " Asegúrate de que certs/private.pem está en .gitignore"

dev-jwt:
	@echo "Generando token JWT de desarrollo..."
	go run scripts/generate-jwt/main.go

dev-jwt-export:
	go run scripts/generate-jwt/main.go > tokens.txt

dev-aes-key:
	@echo "Generando clave AES de desarrollo..."
	go run scripts/generate-aes-key/main.go

dev-aes-encrypt:
	@echo "Encriptando datos de desarrollo..."
	go run scripts/aes-cryptografy/main.go
# test-jwt:
# 	@echo "🧪 Probando validación JWT..."
# 	curl -H "Authorization: Bearer $(shell cat .token.dev)" http://localhost:8080/api/v1/keys