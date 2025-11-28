SHELL := bash

export MSYS_NO_PATHCONV := 1
export MSYS2_ARG_CONV_EXCL := *

PROJECT_DIR := $(shell pwd)
BUILDER_IMAGE = go-cgo-builder:1.25
OUTPUT = bin/api
SOURCE = ./cmd/api

.PHONY: sonar-up sonar-down sonar-local test coverage lint quality

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
test:
	@echo "Ejecutando tests..."
	go test -v -race -coverprofile=coverage.out ./...

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
clean:
	@echo ">> Limpiando binarios..."
	rm -rf bin/*



docker-build:
	@echo "Construyendo imagen Docker..."
	docker build -t template-go-gin .

# Lint
lint-minimal:
	@echo "Ejecutando linter mínimo..."
	golangci-lint run -c .golangci-minimal.yml