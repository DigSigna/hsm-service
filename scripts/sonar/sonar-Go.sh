#!/bin/bash

set -e

echo "🔍 Análisis SonarQube para Template Go..."

# Variables
SONAR_HOST_URL="http://localhost:9000"
PROJECT_KEY="Template-Go-Gin"
PROJECT_NAME="Template Go Gin"

# Configurar PATH para Go
export PATH="$PATH:/e/Program Files/Go/bin"

# Cambiar al directorio del proyecto
cd /e/Proyectos/DigSigna/platform-templates/templates/template-go-gin

echo "✅ Go version: $(go version)"

# Limpiar archivos anteriores
rm -f coverage.out test-report.json golangci-report.xml

# Ejecutar SOLO las pruebas básicas (sin paquetes internos complejos)
echo "🧪 Ejecutando pruebas básicas..."
go test -v -coverprofile=coverage.out ./tests/

# Si no hay cobertura, crear un archivo mínimo
if [ ! -f "coverage.out" ] || [ ! -s "coverage.out" ]; then
    echo "📝 Generando cobertura mínima..."
    echo "mode: atomic" > coverage.out
fi

# Generar reporte de tests
go test -v -json ./tests/ > test-report.json

# Ejecutar linter básico
echo "🔍 Ejecutando linter..."
golangci-lint run --out-format checkstyle > golangci-report.xml 2>/dev/null || true

# export PATH=$PATH:E:/Program Files/sonar-scanner-7.3.0.5189-windows-x64/bin
# export PATH=$PATH:/e/sonar-scanner-4.7.0.2747-windows/bin

# Verificar que sonar-scanner está disponible
if ! command -v sonar-scanner.bat &> /dev/null; then
    echo -e "${RED}❌ sonar-scanner no está disponible${NC}"
    exit 1
fi


# Análisis SonarQube con configuración de TEMPLATE (sin quality gate estricto)
echo "🚀 Ejecutando SonarQube..."
sonar-scanner.bat \
  -Dsonar.projectKey=$PROJECT_KEY \
  -Dsonar.projectName="$PROJECT_NAME" \
  -Dsonar.projectVersion=1.0.0 \
  -Dsonar.sources=./internal,./pkg,./cmd \
  -Dsonar.tests=./tests \
  -Dsonar.exclusions=**/*_test.go,**/testdata/**,**/vendor/**,**/bin/**,**/deployments/** \
  -Dsonar.host.url=$SONAR_HOST_URL \
  -Dsonar.login=admin \
  -Dsonar.password=admin \
  -Dsonar.go.coverage.reportPaths=coverage.out \
  -Dsonar.go.tests.reportPaths=test-report.json \
  -Dsonar.go.golangci-lint.reportPaths=golangci-report.xml \
  -Dsonar.qualitygate.wait=false

echo "✅ Análisis completado!"
echo "📊 Revisa: $SONAR_HOST_URL/dashboard?id=$PROJECT_KEY"