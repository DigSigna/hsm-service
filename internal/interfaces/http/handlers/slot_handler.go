package handlers

import (
	"fmt"
	"hsm-service/internal/domain/ports/input"
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
	Slot     uint   `json:"slot" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
	Pin      string `json:"pin" binding:"required,min=4"`
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
	var req InitializeSlotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.slotManager.InitializeSlot(c.Request.Context(), req.Slot, req.TenantID, req.Pin); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Slot initialized successfully",
		"slot":      req.Slot,
		"tenant_id": req.TenantID,
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
