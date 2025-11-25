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
build:
	@echo "Compilando aplicación..."
	go build -o bin/api cmd/api/main.go

docker-build:
	@echo "Construyendo imagen Docker..."
	docker build -t template-go-gin .

# Lint
lint-minimal:
	@echo "Ejecutando linter mínimo..."
	golangci-lint run -c .golangci-minimal.yml