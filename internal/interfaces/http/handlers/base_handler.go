package handlers

import (
	"errors"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/pkg/logger"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

type BaseHandler struct {
	logger *logger.ZapLogger
}

func NewBaseHandler(logger *logger.ZapLogger) *BaseHandler {
	return &BaseHandler{logger: logger}
}

func (h *BaseHandler) HandleError(c *gin.Context, err error) {
	// 1. Intentar convertir a DomainError
	var domainErr *exceptions.DomainError
	if errors.As(err, &domainErr) {
		status := h.mapDomainErrorToHTTP(domainErr.Code)
		h.logger.Warn("Domain error",
			zap.String("code", string(domainErr.Code)),
			zap.String("message", domainErr.Message),
			zap.Any("details", domainErr.Details))

		response := gin.H{
			"error":   domainErr.Code,
			"message": domainErr.Message,
		}

		// Solo incluir details si existen
		if len(domainErr.Details) > 0 {
			response["details"] = domainErr.Details
		}

		c.JSON(status, response)
		return
	}

	// 2. Manejar errores de validación de Gin
	if validationErrs, ok := err.(validator.ValidationErrors); ok {
		h.handleValidationError(c, validationErrs)
		return
	}

	// 3. Error por defecto (generar error de dominio)
	h.logger.Error("Unhandled error type",
		zap.Error(err),
		zap.String("type", reflect.TypeOf(err).String()))

	// Crear un DomainError a partir del error
	de := exceptions.NewDomainError(
		exceptions.ErrorCode("INTERNAL_ERROR"),
		"An internal error occurred",
	).WithDetail("original_error", err.Error())

	c.JSON(http.StatusInternalServerError, gin.H{
		"error":   de.Code,
		"message": de.Message,
		"details": de.Details,
	})
}

func (h *BaseHandler) handleValidationError(c *gin.Context, err validator.ValidationErrors) {
	// Convertir errores de validación a un formato legible
	validationErrors := make(map[string]string)

	for _, fieldErr := range err {
		field := fieldErr.Field()
		tag := fieldErr.Tag()

		// Mensaje amigable por tipo de validación
		var message string
		switch tag {
		case "required":
			message = "field is required"
		case "oneof":
			message = "value must be one of: " + fieldErr.Param()
		case "min":
			message = "value must be at least " + fieldErr.Param()
		case "max":
			message = "value must be at most " + fieldErr.Param()
		case "uuid":
			message = "value must be a valid UUID"
		case "base64":
			message = "value must be valid base64"
		default:
			message = "validation failed for " + tag
		}

		validationErrors[field] = message
	}

	h.logger.Warn("Validation error", zap.Any("errors", validationErrors))

	c.JSON(http.StatusBadRequest, gin.H{
		"error":   "VALIDATION_ERROR",
		"message": "One or more fields failed validation",
		"details": validationErrors,
	})
}

func (h *BaseHandler) mapDomainErrorToHTTP(code exceptions.ErrorCode) int {
	switch code {
	case exceptions.ErrInvalidKeyName, exceptions.ErrInvalidAlgorithm,
		exceptions.ErrInvalidKeySize, exceptions.ErrInvalidKeyUsage,
		exceptions.ErrInvalidTenant, exceptions.ErrInvalidInput:
		return http.StatusBadRequest
	case exceptions.ErrKeyNotFound, exceptions.ErrTenantNotFound:
		return http.StatusNotFound
	case exceptions.ErrKeyInactive:
		return http.StatusConflict
	case exceptions.ErrHSMOperationFailed:
		return http.StatusServiceUnavailable
	case exceptions.ErrInvalidToken, exceptions.ErrSessionExpired:
		return http.StatusUnauthorized
	case exceptions.ErrSessionNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// BindAndValidate combina binding y validación en una sola función
func (h *BaseHandler) BindAndValidate(c *gin.Context, obj interface{}) error {
	if err := c.ShouldBindJSON(obj); err != nil {
		return err
	}

	// Validación adicional si es necesario
	if validator, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := validator.Struct(obj); err != nil {
			return err
		}
	}

	return nil
}

func (h *BaseHandler) GetTenantID(c *gin.Context) string {
	if tenantID, exists := c.Get("tenant_id"); exists {
		return tenantID.(string)
	}
	return ""
}
