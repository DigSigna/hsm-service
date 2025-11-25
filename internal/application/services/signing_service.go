package services

import (
	"context"
	"errors"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
	"platform-templates/templates/template-go-gin/internal/domain/exceptions"
	"platform-templates/templates/template-go-gin/internal/domain/ports/input"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
)

type signingService struct {
	keyRepo   output.KeyRepository
	hsmClient output.HSMClient
}

var _ input.Signer = (*signingService)(nil)

func NewSigningService(
	keyRepo output.KeyRepository,
	hsmClient output.HSMClient,
) input.Signer {
	return &signingService{
		keyRepo:   keyRepo,
		hsmClient: hsmClient,
	}
}

func (s *signingService) SignHash(ctx context.Context, keyID string, hash []byte, tenantID string) ([]byte, error) {
	// Validar que la clave existe y pertenece al tenant
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	}

	if !key.IsActive {
		return nil, errors.New(string(exceptions.ErrKeyInactive))
	}

	if key.Usage != entities.Signing {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Firmar el hash usando el HSM
	signature, err := s.hsmClient.SignHash(ctx, key.KeyHandle, hash)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_hash")
	}

	return signature, nil
}

func (s *signingService) GetPublicKey(ctx context.Context, keyID, tenantID string) ([]byte, error) {
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	}

	return key.PublicKey, nil
}
