package handlers

import (
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/internal/interfaces/http/dtos/requests"
	"hsm-service/pkg/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

type KeyHandler struct {
	*BaseHandler
	keyManager input.KeyManager
	signer     input.Signer
}

func NewKeyHandler(logger *logger.ZapLogger, keyManager input.KeyManager, signer input.Signer) *KeyHandler {
	return &KeyHandler{
		BaseHandler: NewBaseHandler(logger),
		keyManager:  keyManager,
		signer:      signer,
	}
}

func (h *KeyHandler) CreateKey(c *gin.Context) {
	var req requests.CreateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": "Invalid JSON format or structure",
			"details": gin.H{"reason": err.Error()},
		})
		return
	}

	identityVal, exists := c.Get("identity_context")
	if !exists {
		c.JSON(401, gin.H{"error": "identity not found"})
		return
	}

	identity := identityVal.(*valueobjects.IdentityContext)

	key, err := h.keyManager.CreateKey(
		c.Request.Context(),
		req.Name,
		valueobjects.KeyAlgorithm(req.Algorithm),
		req.KeySize,
		valueobjects.KeyUsage(req.Usage),
		identity,
	)
	if err != nil {
		println("ERROR CREATING KEY:", err.Error())
		h.HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         key.ID,
		"name":       key.Name,
		"algorithm":  key.Algorithm,
		"key_size":   key.KeySize,
		"usage":      key.Purpose,
		"tenant_id":  key.TenantID,
		"created_at": key.CreatedAt,
		"is_active":  key.IsActive,
	})
}

func (h *KeyHandler) ListKeys(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required"})
		return
	}

	keys, err := h.keyManager.ListKeys(c.Request.Context(), tenantID)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, keys)
}

func (h *KeyHandler) SignHash(c *gin.Context) {
	var req requests.SignHashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Decodificar hash de base64
	hash := []byte(req.Hash) // En producción, decodificar de base64

	signature, err := h.signer.SignHash(c.Request.Context(), req.KeyID, hash, req.TenantID)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"signature": signature, // En base64 en implementación real
		"key_id":    req.KeyID,
	})
}

func (h *KeyHandler) GetPublicKey(c *gin.Context) {
	keyID := c.Param("key_id")
	tenantID := c.Param("tenant_id")

	publicKey, err := h.signer.GetPublicKey(c.Request.Context(), keyID, tenantID)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"public_key": publicKey, // En base64 en implementación real
		"key_id":     keyID,
	})
}
