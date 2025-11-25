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
go run cmd/server/main.go

# Construir binario
make build
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
