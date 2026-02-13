package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/pkg/crypto"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type K8sAESKeyManager struct {
	config       K8SConfig
	clientset    *kubernetes.Clientset
	keyCache     map[string][]byte // Cache de múltiples versiones
	cacheMutex   sync.RWMutex
	currentKeyID string
}

var _ output.AESKeyManager = (*K8sAESKeyManager)(nil)

func NewK8SAESKeyManager(config K8SConfig) (*K8sAESKeyManager, error) {
	println("DEBUG: Initializing K8sAESKeyManager with config KEYID:", config.KeyID)
	println("DEBUG: K8sAESKeyManager InCluster:", config.InCluster)
	println("DEBUG: K8sAESKeyManager KubeconfigPath:", config.KubeconfigPath)
	println("DEBUG: K8sAESKeyManager SecretName:", config.SecretName)
	println("DEBUG: K8sAESKeyManager SecretNamespace:", config.SecretNamespace)
	println("DEBUG: K8sAESKeyManager MasterKeyKey:", config.MasterKeyKey)

	// Crear cliente Kubernetes
	clientset, err := createK8sClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Establecer valores por defecto
	if config.SecretNamespace == "" {
		config.SecretNamespace = "default"
	}
	if config.MasterKeyKey == "" {
		config.MasterKeyKey = "master-aes-key-v1"
	}

	manager := &K8sAESKeyManager{
		config:       config,
		clientset:    clientset,
		keyCache:     make(map[string][]byte),
		cacheMutex:   sync.RWMutex{},
		currentKeyID: config.KeyID,
	}

	return manager, nil
}

func (k *K8sAESKeyManager) GetKey(ctx context.Context, keyID string) (key []byte, err error) {
	println("DEBUG: GetKey called with keyID:", keyID)
	println("DEBUG: K8sAESKeyManager config: secretName=", k.config.SecretName,
		" namespace=", k.config.SecretNamespace,
		" keyID=", k.config.KeyID,
		" masterKeyKey=", k.config.MasterKeyKey,
		" oldMasterKeyKey=", k.config.OldMasterKeyKey)

	k.cacheMutex.RLock()
	if key, found := k.keyCache[keyID]; found {
		k.cacheMutex.RUnlock()
		println("DEBUG: Cache hit for keyID:", keyID)
		return key, nil
	}
	k.cacheMutex.RUnlock()
	println("DEBUG: Cache miss for keyID:", keyID, "cacheSize:", len(k.keyCache))
	println("DEBUG: Key not found in cache, fetching from K8s Secret:", keyID)
	// Determinar qué campo del Secret usar
	secretKeyField := keyID // Por defecto, el keyID es el campo en el Secret

	// Mapeo especial para keyID lógico a campo físico
	if keyID == k.config.KeyID {
		secretKeyField = k.config.MasterKeyKey
	} else if keyID == "old-master-key" && k.config.OldMasterKeyKey != "" {
		secretKeyField = k.config.OldMasterKeyKey
	}
	println("DEBUG: Secret field resolved for keyID:", keyID, "->", secretKeyField)

	secret, err := k.clientset.CoreV1().
		Secrets(k.config.SecretNamespace).
		Get(ctx, k.config.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, exceptions.DomainErrK8sSecretNotFound.
			WithDetail("secretName", k.config.SecretName).
			WithDetail("namespace", k.config.SecretNamespace).
			WithDetail("error", err.Error())
	}

	keyData, exists := secret.Data[secretKeyField]
	if !exists {
		return nil, exceptions.DomainErrK8sKeyNotFound.
			WithDetail("secretName", k.config.SecretName).
			WithDetail("namespace", k.config.SecretNamespace).
			WithDetail("field", secretKeyField)
	}

	// Decodificar si es base64
	if isBase64(string(keyData)) {
		key, err = base64.StdEncoding.DecodeString(string(keyData))
		if err != nil {
			return nil, exceptions.DomainErrInvalidBase64.WithDetail("error", err.Error())
		}
	} else {
		key = keyData
	}

	// Validar tamaño
	if len(key) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(key))
	}

	// Cachear
	k.cacheMutex.Lock()
	k.keyCache[keyID] = key
	k.cacheMutex.Unlock()

	return key, nil
}

// GenerateDataKey implements [output.AESKeyManager].
func (k *K8sAESKeyManager) GenerateDataKey() (key []byte, err error) {
	key, err = crypto.GenerateAES256Key()

	if err != nil {
		return nil, exceptions.DomainErrFailCreateAESKey.WithDetail("error", err.Error())
	}
	return key, nil
}

func createK8sClient(config K8SConfig) (*kubernetes.Clientset, error) {
	var restConfig *rest.Config
	var err error

	// Determinar cómo conectarse a Kubernetes
	if config.InCluster {
		// Dentro de un Pod en Kubernetes
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
		}
	} else {
		// Desarrollo local
		kubeconfig := config.KubeconfigPath
		if kubeconfig == "" {
			// Buscar kubeconfig en ubicaciones por defecto
			home, _ := os.UserHomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}

		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
		}
	}

	// Crear clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return clientset, nil
}

// UnwrapKey implements [output.AESKeyManager].
func (k *K8sAESKeyManager) UnwrapKey(
	ctx context.Context,
	keyID string,
	wrappedKey []byte,
) (plaintextKey []byte, err error) {
	masterKey, err := k.GetKey(ctx, keyID)
	if err != nil {
		return nil, exceptions.DomainErrK8sSecretNotFound.
			WithDetail("secretName", k.config.SecretName).
			WithDetail("namespace", k.config.SecretNamespace).
			WithDetail("error", err.Error())
	}

	// validate wrappedKey length
	if len(wrappedKey) < 28 { // IV(12) + Tag(16) mínimo
		return nil, exceptions.DomainErrWrappingKeyLength.
			WithDetail("minimum_expected", 28).
			WithDetail("actual", len(wrappedKey))
	}

	plaintextKey, err = crypto.UnwrapKey(masterKey, wrappedKey)

	if err != nil {
		return nil, exceptions.DomainErrFailUUnwrapKey.
			WithDetail("error", err.Error())
	}

	return plaintextKey, nil
}

// WrapKey implements [output.AESKeyManager].
func (k *K8sAESKeyManager) WrapKey(
	ctx context.Context,
	keyID string,
	plaintextKey []byte,
) (wrappedKey []byte, err error) {
	masterKey, err := k.GetKey(ctx, keyID)
	if err != nil {
		return nil, exceptions.DomainErrK8sSecretNotFound.
			WithDetail("secretName", k.config.SecretName).
			WithDetail("namespace", k.config.SecretNamespace).
			WithDetail("error", err.Error())
	}

	// validate plaintextKey length
	if len(plaintextKey) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(plaintextKey))
	}

	wrappedKey, err = crypto.WrapKey(masterKey, plaintextKey)
	if err != nil {
		return nil, err
	}

	return wrappedKey, nil
}

func (k *K8sAESKeyManager) EncryptWithKeyID(
	ctx context.Context,
	keyID string,
	plaintext []byte,
) (encrypt *valueobjects.EncryptAESGCM, err error) {
	key, err := k.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.EncryptAESGCM(key, []byte(plaintext))
	if err != nil {
		return nil, exceptions.DomainErrFailEncryptData.
			WithDetail("error", err.Error())
	}

	encrypted.KeyID = keyID
	return encrypted, nil
}

func (k *K8sAESKeyManager) DecryptWithKeyID(
	ctx context.Context, keyID string,
	encrypted valueobjects.EncryptAESGCM,
) (plaintext []byte, err error) {
	if encrypted.KeyID != keyID {
		return nil, exceptions.DomainErrKeyIDMismatch
	}
	key, err := k.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return crypto.DecryptAESGCM(key, encrypted)
}

func (k *K8sAESKeyManager) EncryptWithKey(
	key []byte,
	plaintext []byte,
) (encrypt *valueobjects.EncryptAESGCM, err error) {
	if len(key) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(key))
	}

	encrypted, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		return nil, exceptions.DomainErrFailEncryptData.
			WithDetail("error", err.Error())
	}

	encrypted.KeyID = k.currentKeyID

	return encrypted, nil
}

func (k *K8sAESKeyManager) DecryptWithKey(
	key []byte,
	encrypted valueobjects.EncryptAESGCM,
) (plaintext []byte, err error) {
	println("DEBUG: Decrypt function Local manager")

	if len(key) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(key))
	}

	return crypto.DecryptAESGCM(key, encrypted)
}

func (k *K8sAESKeyManager) RewrapKey(
	ctx context.Context,
	oldKeyID, newKeyID string,
	wrappedKey []byte,
) ([]byte, error) {
	// 1. Desenvolver con la clave antigua
	oldKey, err := k.GetKey(ctx, oldKeyID)
	if err != nil {
		return nil, exceptions.DomainErrK8sSecretNotFound.WithDetail("original_error", err.Error())
	}

	plaintextKey, err := crypto.UnwrapKey(oldKey, wrappedKey)
	if err != nil {
		return nil, exceptions.DomainErrFailUUnwrapKey.WithDetail("original_error", err.Error())
	}

	// 2. Envolver con la clave nueva
	newKey, err := k.GetKey(ctx, newKeyID)
	if err != nil {
		zeroBytes(plaintextKey)
		return nil, exceptions.DomainErrK8sSecretNotFound.WithDetail("original_error", err.Error())
	}

	newWrappedKey, err := crypto.WrapKey(newKey, plaintextKey)
	if err != nil {
		zeroBytes(plaintextKey)
		return nil, exceptions.DomainErrFailWrapKey.WithDetail("original_error", err.Error())
	}

	// 3. Limpiar
	zeroBytes(plaintextKey)

	return newWrappedKey, nil
}

func (k *K8sAESKeyManager) GetCurrentKeyID() string {
	return k.currentKeyID
}

func (k *K8sAESKeyManager) ListKeyVersions(ctx context.Context) ([]string, error) {
	secret, err := k.clientset.CoreV1().
		Secrets(k.config.SecretNamespace).
		Get(ctx, k.config.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	versions := make([]string, 0, len(secret.Data))
	for key := range secret.Data {
		versions = append(versions, key)
	}

	return versions, nil
}

// isBase64 checks if a string is base64 encoded
func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
