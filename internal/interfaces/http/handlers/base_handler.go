package handlers

import (
	"net/http"
	"platform-templates/templates/template-go-gin/internal/domain/exceptions"
	"platform-templates/templates/template-go-gin/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type BaseHandler struct {
	logger *logger.ZapLogger
}

func NewBaseHandler(logger *logger.ZapLogger) *BaseHandler {
	return &BaseHandler{logger: logger}
}

func (h *BaseHandler) HandleError(c *gin.Context, err error) {
	switch e := err.(type) {
	case *exceptions.DomainError:
		status := h.mapDomainErrorToHTTP(e.Code)
		h.logger.Warn("Domain error", zap.String("code", string(e.Code)), zap.String("message", e.Message))
		c.JSON(status, gin.H{
			"error":   e.Code,
			"message": e.Message,
			"details": e.Details,
		})
	default:
		h.logger.Error("Internal server error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "INTERNAL_ERROR",
			"message": "An internal error occurred",
		})
	}
}

func (h *BaseHandler) mapDomainErrorToHTTP(code exceptions.ErrorCode) int {
	switch code {
	case exceptions.ErrInvalidKeyName, exceptions.ErrInvalidAlgorithm, exceptions.ErrInvalidKeySize:
		return http.StatusBadRequest
	case exceptions.ErrKeyNotFound:
		return http.StatusNotFound
	case exceptions.ErrKeyInactive, exceptions.ErrInvalidKeyUsage:
		return http.StatusConflict
	case exceptions.ErrHSMOperationFailed:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func (h *BaseHandler) GetTenantID(c *gin.Context) string {
	if tenantID, exists := c.Get("tenant_id"); exists {
		return tenantID.(string)
	}
	return ""
}
