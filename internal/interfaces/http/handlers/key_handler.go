package handlers

import (
	"encoding/base64"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/internal/interfaces/http/dtos/requests"
	"hsm-service/pkg/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	identityNotFoundMsg = "identity not found"
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
		c.JSON(401, gin.H{"error": identityNotFoundMsg})
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
	identityVal, exists := c.Get("identity_context")
	if !exists {
		c.JSON(401, gin.H{"error": identityNotFoundMsg})
		return
	}

	var req requests.SignHashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Decodificar hash de base64
	hash, err := base64.StdEncoding.DecodeString(req.Hash)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	identity := identityVal.(*valueobjects.IdentityContext)

	signature, err := h.signer.SignHash(c.Request.Context(), req.KeyID, hash, identity)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"signature": base64.StdEncoding.EncodeToString(signature),
		"key_id":    req.KeyID,
	})
}

func (h *KeyHandler) VerifyHashSignature(c *gin.Context) {
	identityVal, exists := c.Get("identity_context")
	if !exists {
		c.JSON(401, gin.H{"error": identityNotFoundMsg})
		return
	}

	var req requests.VerifySignatureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": "Invalid JSON format or structure",
			"details": gin.H{"reason": err.Error()},
		})
		return
	}

	identity := identityVal.(*valueobjects.IdentityContext)

	// Decode hash from base64
	hash, err := base64.StdEncoding.DecodeString(req.Hash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_HASH",
			"message": "Hash must be valid base64 encoded data",
			"details": gin.H{"reason": err.Error()},
		})
		return
	}

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_SIGNATURE",
			"message": "Signature must be valid base64 encoded data",
			"details": gin.H{"reason": err.Error()},
		})
		return
	}

	isValid, err := h.signer.VerifyHashSignature(
		c.Request.Context(),
		req.KeyID,
		hash,
		signature,
		identity,
	)
	if err != nil {
		h.HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"is_valid": isValid,
		"key_id":   req.KeyID,
		"message": func() string {
			if isValid {
				return "Signature is valid"
			}
			return "Signature is invalid"
		}(),
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
