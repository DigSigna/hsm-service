package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/square/go-jose.v2"
)

type KeyManager struct {
	keys      map[string]*rsa.PublicKey
	mu        sync.RWMutex
	jwksURL   string
	cacheTime time.Duration
	lastFetch time.Time
	config    *Config
}

// Config para KeyManager
type Config struct {
	Mode             string `yaml:"mode"`
	PublicKeyPath    string `yaml:"public_key_path"`
	JWKSUrl          string `yaml:"jwks_url"`
	JWKSCacheMinutes int    `yaml:"jwks_cache_minutes"`
}

type JWKSetResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func NewKeyManager(config *Config) (*KeyManager, error) {
	km := &KeyManager{
		keys:      make(map[string]*rsa.PublicKey),
		jwksURL:   config.JWKSUrl,
		cacheTime: time.Duration(config.JWKSCacheMinutes) * time.Minute,
		config:    config,
	}

	// Cargar claves iniciales
	if err := km.loadInitialKeys(); err != nil {
		return nil, fmt.Errorf("failed to load initial keys: %w", err)
	}

	return km, nil
}

func (km *KeyManager) loadInitialKeys() error {
	// if km.config.Mode == "development" {
	// return km.loadFromPEMFile(km.config.PublicKeyPath, "dev-key")
	return km.loadFromPEMFile("./certs/public.pem", "dev-key")
	// }

	// En producción, cargar desde JWKS
	// return km.fetchJWKS()
}

func (km *KeyManager) loadFromPEMFile(filepath, keyID string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read PEM file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	var pubKey *rsa.PublicKey
	switch block.Type {
	case "RSA PUBLIC KEY":
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS1 public key: %w", err)
		}
	case "PUBLIC KEY":
		genericPub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		var ok bool
		pubKey, ok = genericPub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("not an RSA public key")
		}
	default:
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	km.mu.Lock()
	km.keys[keyID] = pubKey
	km.mu.Unlock()

	return nil
}

// fetchJWKS obtiene claves desde endpoint JWKS
func (km *KeyManager) fetchJWKS() error {
	if km.jwksURL == "" {
		return fmt.Errorf("JWKS URL not configured")
	}

	resp, err := http.Get(km.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
	}

	var jwks JWKSetResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// Limpiar claves existentes
	km.keys = make(map[string]*rsa.PublicKey)

	// Procesar cada clave JWK
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			continue
		}

		// Convertir jose.JSONWebKey a *rsa.PublicKey
		if rsaKey, ok := jwk.Key.(*rsa.PublicKey); ok {
			km.keys[jwk.KeyID] = rsaKey
		}
	}

	km.lastFetch = time.Now()
	return nil
}

// GetPublicKey obtiene una clave pública por su KID
func (km *KeyManager) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	println("Getting public key for KID:", kid)
	// Si estamos en modo producción y el caché está expirado, refrescar
	// if km.config.Mode == "production" && time.Since(km.lastFetch) > km.cacheTime {
	// 	if err := km.fetchJWKS(); err != nil {
	// 		// Log error pero continuar con claves cacheadas
	// 		fmt.Printf("Warning: failed to refresh JWKS: %v\n", err)
	// 	}
	// }

	km.mu.RLock()
	key, exists := km.keys[kid]
	km.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("public key not found for kid: %s", kid)
	}

	return key, nil
}

// GetKeyFunc retorna una función para obtener claves compatible con jwt.Parse
func (km *KeyManager) GetKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Verificar el algoritmo
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Obtener KID del header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		// Obtener clave pública
		return km.GetPublicKey(kid)
	}
}
