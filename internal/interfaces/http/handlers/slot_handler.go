package handlers

import (
	"fmt"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/valueobjects"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SlotHandler struct {
	slotManager input.SlotManager
}

func NewSlotHandler(slotManager input.SlotManager) *SlotHandler {
	return &SlotHandler{slotManager: slotManager}
}

type InitializeSlotRequest struct {
}

// InitializeSlot godoc
// @Summary Initialize HSM slot for tenant (INTERNAL)
// @Tags internal
// @Accept json
// @Produce json
// @Param request body InitializeSlotRequest true "Slot initialization data"
// @Success 201 {object} map[string]interface{}
// @Router /internal/hsm/slots/initialize [post]
func (h *SlotHandler) InitializeSlot(c *gin.Context) {
	identityVal, exists := c.Get("identity_context")
	if !exists {
		c.JSON(401, gin.H{"error": "identity not found"})
		return
	}

	identity := identityVal.(*valueobjects.IdentityContext)

	slotID, err := h.slotManager.InitializeSlot(c.Request.Context(), identity)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Slot initialized successfully",
		"slot":      slotID,
		"tenant_id": identity.TenantID,
	})
}

func (h *SlotHandler) GetAvailableSlots(c *gin.Context) {
	slots, err := h.slotManager.GetAvailableSlots(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"available_slots": slots})
}

func (h *SlotHandler) GetAllSlots(c *gin.Context) {
	slots, err := h.slotManager.GetAllSlots(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"all_slots": slots})
}

func (h *SlotHandler) DeleteSlot(c *gin.Context) {
	slotParam := c.Param("slot")
	var slot uint
	_, err := fmt.Sscanf(slotParam, "%d", &slot)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot parameter"})
		return
	}

	if err := h.slotManager.DeleteSlot(c.Request.Context(), slot); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Slot deleted successfully"})
}
