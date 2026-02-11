package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// to do optimize this class and key_service class
// complete al the keys to all actors
// complete all endpoints to use the jwt
// create and test new tenant to white label -ensure slot and client works
type CustomClaims struct {
	KID               string                 `json:"kid"`
	TenantID          string                 `json:"tenant_id"`
	OwnerType         string                 `json:"owner_type"`
	OwnerID           string                 `json:"owner_id"`
	OrganizationID    *string                `json:"organization_id"`
	ParentKeyID       *string                `json:"parent_key_id,omitempty"`
	UserID            string                 `json:"user_id,omitempty"`
	CertLevel         int                    `json:"cert_level"`
	MaxCertLevel      int                    `json:"max_cert_level"`
	CanCertify        bool                   `json:"can_certify"`
	CertificationPath string                 `json:"certification_path"`
	Permissions       map[string]interface{} `json:"permissions,omitempty"`
	jwt.StandardClaims
}

type TokenConfig struct {
	Name              string
	KID               string
	TenantID          string
	OwnerType         string
	OwnerID           string
	OrganizationID    *string
	ParentKeyID       *string
	UserID            string
	CertLevel         int
	MaxCertLevel      int
	CanCertify        bool
	CertificationPath string
	Permissions       map[string]interface{}
	Subject           string
	JWTID             string
}

const (
	depPublicKey = "dev-key"
	rootTenantId = "00000000-0000-0000-0000-000000000001"
	devKeyRootId = "e9195d89-0d7a-4c60-b759-580c714f1fe9" //crypto key id
	rootUserId   = "00000000-0000-0000-0000-000000000001"

	celayaTenantId          = "20000000-2000-2000-2000-000000000001"
	celayaOrganizationId    = "20000000-2000-2000-2000-000000000011"
	devKeyCelayaTenantId    = "c78fcdc4-ac80-4ef4-a210-143f4cd48782" //crypto key id
	celayaTenantUserId      = "20000000-2000-2000-2000-000000000101"
	celayaDepOrganizationId = "20000000-2000-2000-2000-000000000012"
	devKeyCelayaDepId       = "8535ffc9-0d23-4e55-8b0d-1ef91d37e950" //crypto key id
	celayaDepUserId         = "20000000-2000-2000-2000-000000000103"
	celayaDirDepUserId      = "20000000-2000-2000-2000-000000000102"

	resellerTenantId = "30000000-3000-3000-3000-000000000001"
	resellerUserId   = "30000000-3000-3000-3000-000000000001"
	resellerDevKeyID = "17157e7e-24b2-4473-97db-6104762085e7"
)

func main() {
	// get private key
	privateKey := loadPrivateKey()

	// Define configurations for different tokens
	configs := []TokenConfig{
		// 1. Root Tenant (DigSigna)
		{
			Name:              "Root Tenant - DigSigna",
			KID:               depPublicKey,
			TenantID:          rootTenantId,
			OwnerType:         "TENANT",
			OwnerID:           rootUserId,
			OrganizationID:    nil,
			ParentKeyID:       nil,
			UserID:            rootUserId,
			CertLevel:         0,
			MaxCertLevel:      3,
			CanCertify:        true,
			CertificationPath: "",
			Subject:           "tenant-root",
			JWTID:             "dev-jti-root",
			Permissions: map[string]interface{}{
				"keys":         []string{"create", "read", "update", "delete", "sign"},
				"certificates": []string{"issue", "revoke", "manage"},
				"tenants":      []string{"create", "manage"},
				"max_key_size": 4096,
			},
		},
		// 2. Municipality Tenant (Mpio-Corp)
		{
			Name:              "Municipality Tenant",
			KID:               depPublicKey,
			TenantID:          celayaTenantId,
			OwnerType:         "TENANT",
			OwnerID:           celayaTenantUserId,
			OrganizationID:    strPtr(celayaOrganizationId),
			ParentKeyID:       strPtr(devKeyRootId), // Signed by root
			UserID:            celayaTenantUserId,
			CertLevel:         1,
			MaxCertLevel:      2,
			CanCertify:        true,
			CertificationPath: devKeyRootId,
			Subject:           "organization-municipality",
			JWTID:             "dev-jti-municipality",
			Permissions: map[string]interface{}{
				"keys":         []string{"create", "read", "update", "sign"},
				"certificates": []string{"issue", "revoke"},
				"max_key_size": 2048,
			},
		},
		// 3. Department/Branch
		{
			Name:              "Department Branch",
			KID:               depPublicKey,
			TenantID:          celayaTenantId,
			OwnerType:         "ORGANIZATION",
			OwnerID:           celayaDepOrganizationId, // Department's organization ID owner of key
			OrganizationID:    strPtr(celayaDepOrganizationId),
			ParentKeyID:       strPtr(devKeyCelayaTenantId),
			UserID:            celayaDepUserId,
			CertLevel:         2,
			MaxCertLevel:      1,
			CanCertify:        true,                                // Departments certify end users
			CertificationPath: devKeyRootId + devKeyCelayaTenantId, //"root:municipality:department",
			Subject:           "organization-department",
			JWTID:             "dev-jti-department",
			Permissions: map[string]interface{}{
				"keys":      []string{"read", "sign"},
				"documents": []string{"sign", "validate"},
			},
		},
		// 4. End User
		{
			Name:              "End User",
			KID:               depPublicKey,
			TenantID:          celayaTenantId,
			OwnerType:         "USER",
			OwnerID:           celayaDirDepUserId,
			OrganizationID:    strPtr(celayaDepOrganizationId),
			ParentKeyID:       strPtr(devKeyCelayaDepId),
			UserID:            celayaDirDepUserId,
			CertLevel:         3,
			MaxCertLevel:      0,
			CanCertify:        false,
			CertificationPath: devKeyRootId + devKeyCelayaTenantId + devKeyCelayaDepId, //"root:municipality:department:user",
			Subject:           "end-user",
			JWTID:             "dev-jti-user",
			Permissions: map[string]interface{}{
				"keys":      []string{"sign"},
				"documents": []string{"sign"},
			},
		},
		// 5. Reseller (White-label)
		{
			Name:              "Reseller White-label",
			KID:               depPublicKey,
			TenantID:          resellerTenantId,
			OwnerType:         "TENANT",
			OwnerID:           resellerTenantId,
			OrganizationID:    nil,
			ParentKeyID:       nil, // Independent root
			UserID:            resellerUserId,
			CertLevel:         0,
			MaxCertLevel:      2,
			CanCertify:        true,
			CertificationPath: "",
			Subject:           "reseller-root",
			JWTID:             "dev-jti-reseller",
			Permissions: map[string]interface{}{
				"keys":         []string{"create", "read", "update", "delete", "sign"},
				"certificates": []string{"issue", "revoke"},
				"white_label":  []string{"branding", "customize"},
				"max_key_size": 2048,
			},
		},
	}

	// Generate tokens for all configurations
	for _, config := range configs {
		tokenString, err := generateToken(config, privateKey)
		if err != nil {
			log.Printf("Failed to generate token for %s: %v", config.Name, err)
			continue
		}

		fmt.Printf("=== %s ===\n", config.Name)
		fmt.Printf("Token: %s\n\n", tokenString)

		// Verify the token
		if err := verifyToken(tokenString, &privateKey.PublicKey); err != nil {
			log.Printf("Verification failed for %s: %v", config.Name, err)
		} else {
			fmt.Println(" Token verified successfully")
		}
		fmt.Println("---")
	}
}

// Helper function to create string pointer
func strPtr(s string) *string {
	return &s
}

// Generate token from config
func generateToken(config TokenConfig, privateKey *rsa.PrivateKey) (string, error) {
	claims := &CustomClaims{
		KID:               config.KID,
		TenantID:          config.TenantID,
		OwnerType:         config.OwnerType,
		OwnerID:           config.OwnerID,
		OrganizationID:    config.OrganizationID,
		ParentKeyID:       config.ParentKeyID,
		UserID:            config.UserID,
		CertLevel:         config.CertLevel,
		MaxCertLevel:      config.MaxCertLevel,
		CanCertify:        config.CanCertify,
		CertificationPath: config.CertificationPath,
		Permissions:       config.Permissions,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "identification-service",
			Subject:   config.Subject,
			Audience:  "hsm-service",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Id:        config.JWTID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = claims.KID
	return token.SignedString(privateKey)
}

// Verify token
func verifyToken(tokenString string, publicKey *rsa.PublicKey) error {
	_, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	return err
}

func loadPrivateKey() *rsa.PrivateKey {
	privateKeyPEM, err := os.ReadFile("./certs/private.pem")
	if err != nil {
		log.Fatalf("failed to read private key file: %v", err)
	}

	// Parsear la clave privada
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		log.Fatal("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Intentar parsear como PKCS8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse private key: %v", err)
		}
		privateKey = key.(*rsa.PrivateKey)
	}

	return privateKey
}
