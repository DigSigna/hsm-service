package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"hsm-service/internal/domain/exceptions"
	"io"
)

// WrapKey wrapp a key using AES-256-GCM
// return: IV(12) + Ciphertext (include Tag at the end)
// Similar to: iv | aesgcm.Seal(nil, iv, keyToWrap, nil)
func WrapKey(wrappingKey, keyToWrap []byte) ([]byte, error) {
	if len(wrappingKey) != AES256KeySize {
		return nil, exceptions.DomainErrWrappingKeyLength
	}

	// validate keyToWrap length
	if len(keyToWrap) == 0 || len(keyToWrap) > 1024 {
		return nil, exceptions.DomainErrKeyToWrapLengthInvalid
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate unique IV
	iv := make([]byte, AESGCMIVSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt (Seal includes authentication tag)
	ciphertext := aesgcm.Seal(nil, iv, keyToWrap, nil)

	// Prepend IV
	wrapped := make([]byte, 0, len(iv)+len(ciphertext))
	wrapped = append(wrapped, iv...)
	wrapped = append(wrapped, ciphertext...)

	return wrapped, nil
}

// UnwrapKey unwraps a key using AES-256-GCM
func UnwrapKey(wrappingKey, wrappedKey []byte) ([]byte, error) {
	if len(wrappingKey) != AES256KeySize {
		return nil, exceptions.DomainErrWrappingKeyLength
	}

	if len(wrappedKey) < AESGCMIVSize+16 { // IV(12) + Tag(16) minimum
		return nil, exceptions.DomainErrWrappingKeyShort
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Separate IV (first 12 bytes) and ciphertext+tag
	iv := wrappedKey[:AESGCMIVSize]
	ciphertext := wrappedKey[AESGCMIVSize:]

	return aesgcm.Open(nil, iv, ciphertext, nil)
}

// WrapKeyDeterministic - Versión determinística si la necesitas
// Usa HKDF para derivar un IV único de la clave a envolver
// func WrapKeyDeterministic(wrappingKey, keyToWrap []byte) ([]byte, error) {
// 	if len(wrappingKey) != AES256KeySize {
// 		return nil, errors.New("wrapping key must be 32 bytes for AES-256")
// 	}

// 	// Derivar IV de la clave a envolver (determinístico)
// 	iv, err := DeriveIVFromKey(keyToWrap, wrappingKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	block, err := aes.NewCipher(wrappingKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	aesgcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ciphertext := aesgcm.Seal(nil, iv, keyToWrap, nil)

// 	wrapped := make([]byte, 0, len(iv)+len(ciphertext))
// 	wrapped = append(wrapped, iv...)
// 	wrapped = append(wrapped, ciphertext...)

// 	return wrapped, nil
// }

// DeriveIVFromKey - Deriva un IV determinístico usando HKDF
// func DeriveIVFromKey(key, salt []byte) ([]byte, error) {
// 	// Usa HKDF-SHA256 para derivar 12 bytes
// 	// Esto asegura que la misma clave produzca el mismo IV
// 	return HKDF(key, salt, []byte("aes-gcm-key-wrap"), AESGCMIVSize)
// }
