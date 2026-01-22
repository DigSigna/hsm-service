package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Crear directorio certs si no existe
	certsDir := "certs"
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		os.Mkdir(certsDir, 0755)
	}

	// Generar clave privada RSA 2048
	fmt.Println("Generando claves RSA 2048...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error generando clave privada: %v", err))
	}

	// Guardar clave privada
	privateFile, err := os.Create(filepath.Join(certsDir, "private.pem"))
	if err != nil {
		panic(fmt.Sprintf("Error creando archivo private.pem: %v", err))
	}
	defer privateFile.Close()

	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(privateFile, privateBlock); err != nil {
		panic(fmt.Sprintf("Error escribiendo private.pem: %v", err))
	}

	// Guardar clave pública
	publicFile, err := os.Create(filepath.Join(certsDir, "public.pem"))
	if err != nil {
		panic(fmt.Sprintf("Error creando archivo public.pem: %v", err))
	}
	defer publicFile.Close()

	publicKey := &privateKey.PublicKey
	publicBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	if err := pem.Encode(publicFile, publicBlock); err != nil {
		panic(fmt.Sprintf("Error escribiendo public.pem: %v", err))
	}

	// También generar versión JWK para el identification-service
	jwkFile, err := os.Create(filepath.Join(certsDir, "jwks.json"))
	if err != nil {
		panic(fmt.Sprintf("Error creando jwks.json: %v", err))
	}
	defer jwkFile.Close()

	fmt.Println("Claves generadas exitosamente:")
	fmt.Println("   - certs/private.pem (NO committear)")
	fmt.Println("   - certs/public.pem")
	fmt.Println("   - certs/jwks.json (para identification-service)")
}
