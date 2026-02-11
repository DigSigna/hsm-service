package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/valueobjects"
	"io"
)

const (
	AESGCMIVSize  = 12 // Nonce 96 bits
	AESGCMTagSize = 16 // Tag 128 bits
	AES256KeySize = 32 // 256 bits
)

func GenerateAES256Key() ([]byte, error) {
	key := make([]byte, AES256KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func EncryptAESGCM(key, plaintext []byte) (*valueobjects.EncryptAESGCM, error) {
	// Validaciones básicas
	if len(key) != AES256KeySize {
		return nil, exceptions.DomainErrInvalidAESKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, exceptions.DomainErrAESCreateCipher
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, exceptions.DomainErrAESCreateGCM
	}

	// Generar nonce (12 bytes para GCM)
	nonce := make([]byte, AESGCMIVSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, exceptions.DomainErrAESCreateNonce
	}

	// Encriptar (Seal ya maneja la autenticación)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// IMPORTANTE: ciphertext incluye el tag al final
	// Separar ciphertext y tag
	tagStart := len(ciphertext) - aesgcm.Overhead()
	actualCiphertext := ciphertext[:tagStart]
	tag := ciphertext[tagStart:]

	return &valueobjects.EncryptAESGCM{
		IV:         nonce,
		Ciphertext: actualCiphertext,
		Tag:        tag,
		Algorithm:  "AES-256-GCM",
	}, nil
}

func DecryptAESGCM(key []byte, encrypted valueobjects.EncryptAESGCM) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, exceptions.DomainErrInvalidAESKeySize
	}

	if !encrypted.IsValid() {
		return nil, exceptions.DomainErrAESInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, exceptions.DomainErrAESCreateCipher
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, exceptions.DomainErrAESCreateGCM
	}

	// Reconstruir ciphertext + tag como espera GCM
	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)

	// Desencriptar
	plaintext, err := aesgcm.Open(nil, encrypted.IV, ciphertextWithTag, nil)
	if err != nil {
		return nil, exceptions.DomainErrAESDecryptFailed
	}

	return plaintext, nil
}

func EncryptAESGCMBase64(keyBase64 string, plaintext []byte) (*valueobjects.EncryptAESGCM, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, exceptions.DomainErrInvalidBase64
	}

	return EncryptAESGCM(key, plaintext)
}

func DecryptAESGCMBase64(keyBase64 string, encrypted valueobjects.EncryptAESGCM) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", exceptions.DomainErrInvalidBase64
	}

	plaintext, err := DecryptAESGCM(key, encrypted)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
