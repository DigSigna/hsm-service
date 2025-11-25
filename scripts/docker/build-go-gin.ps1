Write-Host "Building Go-Gin Template..." -ForegroundColor Cyan

# 1. Build Go
Write-Host "1. Compilando template-go-gin..." -ForegroundColor Yellow
go build -o bin/api cmd/api/main.go

# if ($LASTEXITCODE -ne 0) {
#     Write-Host "Maven build failed!" -ForegroundColor Red
#     exit 1
# }

# 2. Build Docker
Write-Host "2. Construyendo imagen Docker..." -ForegroundColor Yellow
# docker build -f docker/images/template-go-gin/Dockerfile -t template-go-gin ..
docker build -f .\templates\template-go-gin\Dockerfile -t template-go-gin ..

if ($LASTEXITCODE -ne 0) {
    Write-Host " Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Go-Gin Template construido exitosamente!" -ForegroundColor Green
Write-Host "Imagen: template-go-gin" -ForegroundColor White
Write-Host "Para ejecutar: docker run -p 8080:8080 -e ENVIRONMENT=development template-go-gin" -ForegroundColor White