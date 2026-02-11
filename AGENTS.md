# AGENTS.md - HSM Service (Go)

Este archivo proporciona instrucciones específicas para que los agentes de IA trabajen de forma efectiva y segura en este servicio de firma digital y gestión criptográfica basado en HSM, escrito en Go.

## 📋 Resumen del Proyecto

Este es un **HSM Service** construido como una **API REST HTTP** en **Go (Golang)**. Su propósito es proporcionar una interfaz RESTful para operaciones criptográficas seguras a través de Módulos de Seguridad de Hardware (HSM), manejando tareas como firma, verificación, generación y gestión de claves criptográficas.

**Tecnologías clave:**
- **Lenguaje:** Go 1.25.4
- **Framework HTTP:** Gin Web Framework
- **Arquitectura:** Clean Architecture / Hexagonal (Ports & Adapters)
- **Cliente HSM:** Biblioteca `miekg/pkcs11` para comunicación PKCS#11
- **Base de datos:** MySQL (Digital Ocean managed database)
- **Configuración:** Viper
- **Logging:** Zap (structured logging)
- **Pruebas:** Paquete `testing` estándar con `testify/assert`
- **Gestión de módulos:** Go Modules (`go.mod`)
- **Desarrollo:** Docker Compose, Air (hot reload), Delve (debugging)

## 🚀 Comandos Esenciales

### Desarrollo Local (Recomendado)
```bash
# Iniciar entorno de desarrollo con Docker Compose (hot reload automático)
make dev

# Iniciar contenedores en background
make dev-up

# Ver logs en tiempo real
make dev-logs

# Detener entorno de desarrollo
make dev-down

# Reiniciar el servicio
make dev-restart

# Acceder al shell del contenedor
make dev-shell
```

### Instalación y Construcción
```bash
# Descargar y sincronizar dependencias del módulo
go mod tidy

# Construir el binario para Linux (usando Docker builder)
make build

# Construir imagen Docker para producción
docker build -t hsm-service -f Dockerfile .

# Ejecutar la aplicación directamente (requiere configuración local)
go run ./cmd/api/main.go
```

### Desarrollo y Pruebas
```bash
# Ejecutar TODAS las pruebas del proyecto
go test ./...

# Ejecutar pruebas con cobertura
make test-coverage

# Ejecutar pruebas dentro del contenedor de desarrollo
make test

# Ejecutar el linter
make lint

# Ejecutar análisis de SonarQube local
make sonar-local
```

### Limpieza
```bash
# Limpiar contenedores y volúmenes
make clean

# Limpiar binarios
rm -rf bin/*

# Limpiar caché de Go
go clean -cache
```

## Estructura del Proyecto
```text
hsm-service/
├── cmd/
│   └── api/                      # Punto de entrada principal del servidor HTTP
│       └── main.go               # Inicializa el servidor Gin y dependencias
├── internal/                     # Código interno privado de la aplicación
│   ├── application/              # Capa de aplicación (casos de uso)
│   │   ├── dtos/                 # DTOs para transferencia de datos
│   │   └── services/             # Servicios de aplicación (lógica de negocio)
│   ├── domain/                   # Capa de dominio (entidades y lógica central)
│   │   ├── entities/             # Entidades del dominio
│   │   ├── exceptions/           # Errores específicos del dominio
│   │   ├── ports/                # Interfaces (hexagonal architecture)
│   │   │   ├── input/            # Puertos de entrada (use cases)
│   │   │   └── output/           # Puertos de salida (repositories, clients)
│   │   └── valueobjects/         # Value Objects del dominio
│   ├── infrastructure/           # Capa de infraestructura (implementaciones)
│   │   ├── audit/                # Clientes de auditoría (REST, Mock)
│   │   ├── config/               # Carga de configuración (Viper)
│   │   ├── database/             # Conexión y utilidades de base de datos
│   │   ├── hsm/                  # Cliente HSM (PKCS#11, SoftHSM)
│   │   ├── persistence/          # Implementaciones de repositorios
│   │   │   └── mysql/            # Repositorios MySQL
│   │   └── security/             # Adaptadores de seguridad (JWT, HSM)
│   └── interfaces/               # Capa de interfaces (entrada/salida HTTP)
│       └── http/                 # Interfaz HTTP (Gin)
│           ├── dtos/             # DTOs de request/response HTTP
│           ├── handlers/         # Handlers HTTP (controladores)
│           ├── middlewares/      # Middlewares (auth, logging, recovery)
│           └── routes/           # Definición de rutas HTTP
├── pkg/                          # Código reutilizable (puede ser público)
│   ├── logger/                   # Logger estructurado (Zap)
│   ├── request/                  # Extracción de metadata de requests
│   └── health/                   # Health checks
├── deployments/                  # Configuraciones de despliegue
│   ├── database/                 # Migraciones de base de datos
│   ├── docker/                   # Dockerfiles específicos
│   └── kubernetes/               # Manifiestos K8s
├── scripts/                      # Scripts de utilidad
│   ├── build.sh                  # Scripts de compilación
│   ├── deploy.sh                 # Scripts de despliegue
│   └── sonar/                    # Scripts de análisis SonarQube
├── tests/                        # Pruebas de integración y E2E
├── config/                       # Archivos de configuración (no versionados)
├── certs/                        # Certificados SSL/TLS (no versionados)
├── .air.toml                     # Configuración de Air (hot reload)
├── docker-compose.dev.yml        # Docker Compose para desarrollo
├── docker-compose.debug.yml      # Docker Compose para debugging
├── Dockerfile                    # Dockerfile de producción
├── Dockerfile.dev                # Dockerfile de desarrollo
├── Dockerfile.builder            # Dockerfile para compilación
├── go.mod                        # Definición del módulo y dependencias
├── go.sum                        # Sumas de verificación de dependencias
├── Makefile                      # Automatización de tareas
└── .gitignore                    # Archivos y carpetas a ignorar en Git
```
## Convenciones y Estilo de Código
- Estilo oficial: Seguir estrictamente Effective Go y las reglas formateadas por gofmt. El código debe ser formateado automáticamente antes de confirmar.

- Herramientas de formateo:

```bash
# Formatear todo el código del proyecto
gofmt -w .
```

- Nomenclatura:

    - Packages: Nombres cortos, concisos y en minúscula una sola palabra (ej: crypto, signer, hsm).

    - Interfaces: Nombres que terminen en -er cuando describan una acción (ej: Signer, KeyManager). Usar interfaces pequeñas y específicas.

    - Variables: camelCase. Acrónimos como HSM o PKCS mantienen mayúsculas en el medio (ej: hsmClient, pkcs11Lib).

- Manejo de errores: Usar el patrón estándar de Go. Nunca ignorar errores devueltos. Los errores deben proporcionar contexto claro usando fmt.Errorf("...: %w", err).

- Logs: Usar el paquete estándar log o un logger estructurado. Los logs de depuración deben ser controlados por un nivel de log.

## Instrucciones para Pruebas
- Filosofía: Escribir pruebas unitarias para cada función exportada, especialmente en paquetes internal. Las pruebas deben estar en archivos *_test.go en el mismo paquete.

- Mocking del HSM: Dada la naturaleza sensible, las pruebas unitarias DEBEN simular (mock) la capa pkcs11. NUNCA llamar a un HSM real en pruebas automatizadas o en CI. Usar interfaces para permitir el mocking.

- Pruebas de integración: Si existen pruebas que requieren un HSM físico o simulador, deben estar en un paquete separado (ej: tests/integration/) y usar un //go:build integration tag. No ejecutarse por defecto con go test ./....

- Flujo de trabajo: Siempre ejecutar go test ./... y go vet ./... localmente antes de confirmar cambios. El pipeline de CI debe bloquear los PRs si fallan las pruebas.

## Consideraciones de Seguridad y Límites (CRÍTICO)
### ESTAS REGLAS NO DEBEN SER VIOLADAS POR EL AGENTE:

- NUNCA codificar (hardcode) rutas de librerías PKCS#11, PINs de HSM, identificadores de clave o seeds criptográficas en el código fuente. Estos datos DEBEN provenir de variables de entorno, flags de la CLI o archivos de configuración seguros.

- NUNCA imprimir o registrar (log) material criptográfico sensible (claves privadas, nonces, PINs) en ningún nivel de log, ni siquiera DEBUG.

- NO modificar la lógica central de firma o criptografía en internal/crypto/ o internal/hsm/ sin una revisión exhaustiva de seguridad.

- NO introducir nuevas dependencias externas sin verificar su mantenimiento, licencia y historial de seguridad. Preferir la biblioteca estándar de Go cuando sea posible.

- Validación de entrada: La aplicación es una CLI. NO reducir la validación de argumentos de línea de comandos o de archivos de entrada. Validar exhaustivamente antes de procesar.

- Manejo de memoria con datos sensibles: Considerar el uso de tipos como []byte para datos sensibles y sobrescribirlos con ceros después de su uso cuando sea posible, en lugar de string.

## Flujo de Trabajo y Contribución
- Commits: User de convenciones de mensajes de commit claros y descriptivos. Ejemplo: "chore: init"

- Ramas: Trabajar en ramas de feature. La rama principal suele ser main o master.

- Pull Requests:

    - Asegurarse de que todas las pruebas pasan (go test ./...).
    - Ejecutar gofmt -w . para formatear el código.
    - Ejecutar go vet ./... para buscar code smells.
    - Verificar que go mod tidy no realice cambios necesarios.
    - Actualizar la documentación relevante (incluido este AGENTS.md) si se cambian comandos o estructura.

- Dependencias: Agregar nuevas dependencias con go get <module>. El archivo go.mod y go.sum deben actualizarse y confirmarse juntos.

## Soporte para el Agente
- Al generar código relacionado con PKCS#11, priorizar el manejo robusto de errores y el cierre/liberación correcta de sesiones, handles y recursos del HSM.

- Para configuraciones con Viper, seguir los patrones ya establecidos en `internal/infrastructure/config/`.

- Respetar la arquitectura hexagonal: 
  - Lógica de negocio en `domain/` y `application/`
  - Implementaciones técnicas en `infrastructure/`
  - Interfaces HTTP en `interfaces/http/`

- Los handlers HTTP deben ser delgados y delegar lógica a los servicios de aplicación.

- Usar los DTOs apropiados para requests/responses HTTP en `interfaces/http/dtos/`.

- Para operaciones de auditoría, usar el `AuditRecorder` interface y el sistema de contexto (`pkg/request/`) para capturar metadata.

- Si una tarea implica cambios en endpoints HTTP o en la firma de servicios, sugiere primero añadir o actualizar una prueba que valide el resultado esperado.

- En caso de duda sobre una operación criptográfica o de seguridad, pregunta antes de implementar. La seguridad es la máxima prioridad.

- Recordar que este es un servicio HTTP de larga duración, no un binario CLI. El código debe manejar correctamente concurrencia, timeouts y ciclo de vida de recursos.