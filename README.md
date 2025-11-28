# Go Gin Hexagonal Template

Template de microservicio en Go con Gin framework y arquitectura hexagonal.

## Características Específicas

- **Framework**: Gin HTTP
- **Arquitectura**: Hexagonal (Ports & Adapters)
- **Testing**: Testify + HTTPTest
- **Documentación**: Swagger integrado
- **Monitorización**: Metrics con Prometheus
- **Logging**: Structured logging con Zap

## Estructura
[STRUCTURE.md](./STRUCTURE.md) para más detalles.


## Comenzando

### Prerrequisitos

- Go 1.19+
- Docker (opcional)

### Desarrollo

```bash
# Inicializar módulo
go mod tidy

# Ejecutar tests
go test ./...

# Ejecutar en desarrollo
go run cmd/api/main.go


# Establecer variables para compilación Linux
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "1"

env GOOS=linux GOARCH=amd64 CGO_ENABLED=1
# Construir binario
make build

# Verificar compilación para linux
file api
```

## Docker
```bash
# Construir imagen
docker build -t hsm-service .
```

## Quality Gate
```bash
# Análisis SonarQube
./scripts/sonar/run-sonar.sh
```
