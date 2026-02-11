package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	// 1. Generar clave AES-256 (32 bytes)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	// 2. Convertir a Base64
	keyBase64 := base64.StdEncoding.EncodeToString(key)

	fmt.Println("Clave AES-256-GCM (base64):")
	fmt.Println(keyBase64)
	fmt.Println("\nLongitud:", len(keyBase64), "caracteres")

	// 3. Guardar en archivo
	err = os.WriteFile("aes-key.txt", []byte(keyBase64), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nClave guardada en aes-key.txt")
}
