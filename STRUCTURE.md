```text
.
├── cmd/
│ └── server/
│ └── main.go # Punto de entrada
├── internal/
│ ├── core/ # Lógica de negocio
│ │ ├── domain/ # Entidades
│ │ ├── ports/ # Interfaces
│ │ └── services/ # Servicios de aplicación
│ ├── handlers/ # Controladores HTTP
│ │ └── http/
│ │ ├── routes.go # Definición de rutas
│ │ └── middleware/ # Middlewares
│ └── infrastructure/ # Adaptadores externos
│ ├── adapters/ # Implementaciones
│ └── repositories/ # Acceso a datos
├── pkg/
│ ├── config/ # Configuración
│ ├── logger/ # Logging
│ └── utils/ # Utilidades
├── scripts/
│ ├── docker/ # Scripts de construcción
│ └── sonar/ # Análisis de código
├── Dockerfile # Contenerización
├── docker-compose.yml # Orquestación
├── go.mod # Dependencias
└── Makefile # Automatización
```