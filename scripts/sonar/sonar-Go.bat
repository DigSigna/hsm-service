@echo off
setlocal enabledelayedexpansion

echo [INFO] Analisis SonarQube para Template Go...

REM Cambiar al directorio raíz del proyecto (donde está sonar.env)
cd /d "E:\Proyectos\DigSigna\platform-templates"

REM Verificar que existe el archivo .env
if not exist sonar.env (
    echo [ERROR] No se encuentra el archivo sonar.env
    echo [INFO] Crea el archivo sonar.env en la raíz del proyecto
    pause
    exit /b 1
)

REM Leer variables del archivo .env
echo [INFO] Cargando configuración desde sonar.env...
for /f "usebackq tokens=1,* delims==" %%A in ("sonar.env") do (
    if not "%%A"=="" if "%%A" neq "#" (
        set "%%A=%%B"
    )
)

REM Verificar que las variables necesarias están definidas
if "%SONAR_TOKEN_GO%"=="" (
    echo [ERROR] SONAR_TOKEN_GO no está definido en sonar.env
    pause
    exit /b 1
)

if "%SONAR_PROJECT_KEY_GO%"=="" (
    echo [ERROR] SONAR_PROJECT_KEY no está definido en sonar.env
    pause
    exit /b 1
)
if "%SONAR_PROJECT_NAME_GO%"=="" (
    echo [ERROR] SONAR_PROJECT_NAME no está definido en sonar.env
    pause
    exit /b 1
)

REM Cambiar al directorio del proyecto
cd /d "E:\Proyectos\DigSigna\platform-templates\templates\template-go-gin"

echo [INFO] Verificando Go...
go version

REM Limpiar archivos anteriores
del coverage.out 2>nul
del test-report.json 2>nul
del golangci-report.xml 2>nul
del sonar-project.properties 2>nul

REM Ejecutar SOLO las pruebas básicas
echo [INFO] Ejecutando pruebas basicas...
go test -v -coverprofile=coverage.out ./tests/

REM Generar reporte de tests
go test -v -json ./tests/ > test-report.json

REM Ejecutar linter básico
echo [INFO] Ejecutando linter...
golangci-lint run --out-format checkstyle > golangci-report.xml 2>nul

REM Generar reporte de tests
go test -v -json ./tests/ > test-report.json

REM Análisis SonarQube
echo [INFO] Ejecutando SonarQube...
sonar-scanner.bat ^
  -Dsonar.projectKey=%SONAR_PROJECT_KEY_GO% ^
  -Dsonar.projectName="%SONAR_PROJECT_NAME_GO%" ^
  -Dsonar.host.url=%SONAR_HOST_URL% ^
  -Dsonar.token=%SONAR_TOKEN_GO% ^

if %errorlevel% neq 0 (
    echo [ERROR] El análisis de SonarQube falló
    echo [INFO] Verifica que el token sea correcto y que SonarQube esté ejecutándose
    pause
    exit /b 1
)

echo [INFO] Analisis completado!
echo [INFO] Revisa: %SONAR_HOST_URL%/dashboard?id=%SONAR_PROJECT_KEY_GO%
pause