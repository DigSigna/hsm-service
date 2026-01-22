package hsm

import (
	"context"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/valueobjects"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
)

const serviceName = "soft-hsm-client"

// GetPublicKey retrieves a public key from the HSM
func (c *SoftHSMClient) GetPublicKey(ctx context.Context, keyHandle string) (publicKey []byte, err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: serviceName,
			EventType:   "HSM_OPERATION",
			Operation:   "GET_PUBLIC_KEY",
			Success:     err == nil,
			ErrMsg:      errToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata:    nil,
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	handle, err := parseKeyHandle(keyHandle)
	if err != nil {
		return nil, err
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	attrs, err := c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %w", err)
	}

	for _, attr := range attrs {
		if len(attr.Value) > 0 {
			return attr.Value, nil
		}
	}

	return nil, errors.New("public key not found")
}

// DeleteKey deletes a key from the HSM
func (c *SoftHSMClient) DeleteKey(ctx context.Context, keyHandle string) (err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: serviceName,
			EventType:   "HSM_OPERATION",
			Operation:   "DELETE_KEY",
			Success:     err == nil,
			ErrMsg:      errToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata:    nil,
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	handle, err := parseKeyHandle(keyHandle)
	if err != nil {
		return err
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return errors.New(hsmClosedMsg)
	}

	err = c.ctx.DestroyObject(c.session, handle)

	return err
}

// ListKeys lists all keys in the HSM
func (c *SoftHSMClient) ListKeys(ctx context.Context) (keys []*entities.HSMKey, err error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: serviceName,
			EventType:   "HSM_OPERATION",
			Operation:   "LIST_KEYS",
			Success:     err == nil,
			ErrMsg:      errToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata:    nil,
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	if err := c.ctx.FindObjectsInit(c.session, template); err != nil {
		return nil, fmt.Errorf("failed to initialize key search: %w", err)
	}
	defer c.ctx.FindObjectsFinal(c.session)

	handles, _, err := c.ctx.FindObjects(c.session, objectBatchSize)
	if err != nil {
		return nil, fmt.Errorf("failed to find keys: %w", err)
	}

	hsmKeys := make([]*entities.HSMKey, 0, len(handles))
	for _, handle := range handles {
		hsmKey, err := c.getKeyInfo(handle)
		if err != nil {
			continue // Skip problematic keys
		}
		hsmKeys = append(hsmKeys, hsmKey)
	}

	return hsmKeys, nil
}

// getKeyInfo retrieves information about a specific key
func (c *SoftHSMClient) getKeyInfo(handle pkcs11.ObjectHandle) (*entities.HSMKey, error) {
	attrs, err := c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key attributes: %w", err)
	}

	hsmKey := &entities.HSMKey{
		KeyHandle: strconv.FormatUint(uint64(handle), 10),
		CreatedAt: time.Now().UTC(),
		IsActive:  true,
		Usage:     valueobjects.KeyUsageBoth,
	}

	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_LABEL:
			hsmKey.Label = string(attr.Value)
		case pkcs11.CKA_KEY_TYPE:
			hsmKey.Type = mapKeyType(attr.Value[0])
		case pkcs11.CKA_ID:
			if len(attr.Value) > 0 {
				hsmKey.TenantID = string(attr.Value)
			}
		}
	}

	// Try to get public key
	if publicKey, err := c.GetPublicKey(context.Background(), hsmKey.KeyHandle); err == nil {
		hsmKey.PublicKey = publicKey
	}

	return hsmKey, nil
}
func (c *SoftHSMClient) FindKeysByLabel(ctx context.Context, labelPattern string) ([]*entities.HSMKey, error) {
	allKeys, err := c.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	var matchedKeys []*entities.HSMKey
	for _, key := range allKeys {
		if strings.Contains(key.Label, labelPattern) {
			matchedKeys = append(matchedKeys, key)
		}
	}

	return matchedKeys, nil
}
