package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func encryptAESGCM(plaintext, keyBase64 string) (string, error) {
	// Decodificar clave
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generar nonce (12 bytes para GCM)
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encriptar
	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	// print IV, ciphertext and tag separately
	fmt.Printf("IV: %x\n", nonce)
	fmt.Printf("Ciphertext: %x\n", ciphertext[len(nonce):len(ciphertext)-aesgcm.Overhead()])
	fmt.Printf("Tag: %x\n", ciphertext[len(ciphertext)-aesgcm.Overhead():])

	// print 64 encoded IV, ciphertext and tag
	fmt.Printf("IV Base64 Encoded: %s\n", base64.StdEncoding.EncodeToString(nonce))
	fmt.Printf("Ciphertext Base64 Encoded: %s\n", base64.StdEncoding.EncodeToString(ciphertext[len(nonce):len(ciphertext)-aesgcm.Overhead()]))
	fmt.Printf("Tag Base64 Encoded: %s\n", base64.StdEncoding.EncodeToString(ciphertext[len(ciphertext)-aesgcm.Overhead():]))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAESGCM(ciphertextBase64, keyBase64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesgcm.NonceSize()
	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// WrapKey wrapp a key using AES-256-GCM
// return: IV(12) + Ciphertext (include Tag at the end)
// Similar to: iv | aesgcm.Seal(nil, iv, keyToWrap, nil)
func WrapKey(wrappingKey, keyToWrap string) ([]byte, error) {
	wKey, err := base64.StdEncoding.DecodeString(string(wrappingKey))
	if err != nil {
		return nil, err
	}
	println("Wrapping Key:", wKey)

	ktWrap, err := base64.StdEncoding.DecodeString(string(keyToWrap))
	if err != nil {
		return nil, err
	}

	if len(wKey) != 32 {
		panic("wrapping key length invalid")
	}

	// validate keyToWrap length
	if len(ktWrap) == 0 || len(ktWrap) > 1024 {
		panic("key to wrap length invalid")
	}

	block, err := aes.NewCipher(wKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate unique IV
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt (Seal includes authentication tag)
	ciphertext := aesgcm.Seal(nil, iv, ktWrap, nil)

	// Prepend IV
	wrapped := make([]byte, 0, len(iv)+len(ciphertext))
	wrapped = append(wrapped, iv...)
	wrapped = append(wrapped, ciphertext...)

	return wrapped, nil
}

// UnwrapKey unwraps a key using AES-256-GCM
func UnwrapKey(wrappingKey, wrappedKey []byte) ([]byte, error) {
	if len(wrappingKey) != 32 {
		panic("wrapping key length invalid ")
	}

	if len(wrappedKey) < 12+16 { // IV(12) + Tag(16) minimum
		panic("wrapped key length invalid")
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
	iv := wrappedKey[:12]
	ciphertext := wrappedKey[12:]

	return aesgcm.Open(nil, iv, ciphertext, nil)
}

func main() {
	keyBase64 := "LLvxgXPJCEY1sek2eTNihV7laqAIVdQVxz11eYcA8oU=" // Leer de variable de entorno/secreto
	pin := "1234"

	// Encriptar
	encrypted, err := encryptAESGCM(pin, keyBase64)
	if err != nil {
		panic(err)
	}
	fmt.Println("PIN encriptado:", encrypted)

	// Desencriptar
	decrypted, err := decryptAESGCM(encrypted, keyBase64)
	if err != nil {
		panic(err)
	}
	fmt.Println("PIN desencriptado:", decrypted)

	masterKeyDecodedBase64, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		panic(err)
	}
	println("Wrapping Key:", masterKeyDecodedBase64)

	wrappedKey, err := WrapKey(keyBase64, keyBase64)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrapped Key: %x\n", wrappedKey)
	wKeyBase64 := base64.StdEncoding.EncodeToString(wrappedKey)
	fmt.Println("Wrapped Key (base64):", wKeyBase64)

	// unwrap key
	unwrappedKey, err := UnwrapKey(masterKeyDecodedBase64, wrappedKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Unwrapped Key: %x\n", unwrappedKey)
	keyBase64 = base64.StdEncoding.EncodeToString(unwrappedKey)
	fmt.Println("Unwrapped Key (base64):", keyBase64)
}
