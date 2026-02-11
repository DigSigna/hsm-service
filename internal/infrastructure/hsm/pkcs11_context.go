package hsm

import (
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

var (
	// Singleton instance of PKCS#11 context shared across all HSM clients
	sharedPKCS11Ctx *pkcs11.Ctx

	// Ensures Initialize is called only once per process
	pkcs11InitOnce sync.Once

	// Stores any error from initialization
	pkcs11InitErr error

	// Tracks the library path used for initialization
	currentLibraryPath string

	// Mutex for thread-safe access to context state
	contextMutex sync.RWMutex
)

// GetOrInitPKCS11Context returns the shared PKCS#11 context, initializing it if necessary.
// This ensures that pkcs11.Ctx.Initialize() is called only once per process,
// which is required by the PKCS#11 specification.
//
// All HSM clients in the process must share the same PKCS#11 context.
// Each client opens its own session on different slots using this shared context.
//
// Parameters:
//   - libraryPath: Path to the PKCS#11 library (e.g., /usr/lib/softhsm/libsofthsm2.so)
//
// Returns:
//   - *pkcs11.Ctx: The initialized PKCS#11 context
//   - error: Any error that occurred during initialization
func GetOrInitPKCS11Context(libraryPath string) (*pkcs11.Ctx, error) {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	// Check if already initialized with a different library path
	if sharedPKCS11Ctx != nil && currentLibraryPath != libraryPath {
		return nil, fmt.Errorf("PKCS#11 already initialized with different library: %s (requested: %s)",
			currentLibraryPath, libraryPath)
	}

	// Initialize once using sync.Once for thread safety
	pkcs11InitOnce.Do(func() {
		currentLibraryPath = libraryPath

		sharedPKCS11Ctx = pkcs11.New(libraryPath)
		if sharedPKCS11Ctx == nil {
			pkcs11InitErr = fmt.Errorf("failed to create PKCS#11 context from library: %s", libraryPath)
			return
		}

		// Initialize the PKCS#11 library - this must be called only once per process
		pkcs11InitErr = sharedPKCS11Ctx.Initialize()
		if pkcs11InitErr != nil {
			sharedPKCS11Ctx = nil
			currentLibraryPath = ""
			pkcs11InitErr = fmt.Errorf("failed to initialize PKCS#11: %w", pkcs11InitErr)
		}
	})

	return sharedPKCS11Ctx, pkcs11InitErr
}

// FinalizePKCS11Context finalizes and releases the shared PKCS#11 context.
// This should be called only once during application shutdown, after all HSM clients
// have been closed.
//
// WARNING: After calling this, GetOrInitPKCS11Context will NOT reinitialize the context
// due to sync.Once behavior. This is intentional - PKCS#11 finalization should only
// happen at process termination.
//
// Returns:
//   - error: Any error that occurred during finalization
func FinalizePKCS11Context() error {
	contextMutex.Lock()
	defer contextMutex.Unlock()

	if sharedPKCS11Ctx == nil {
		return nil // Already finalized or never initialized
	}

	err := sharedPKCS11Ctx.Finalize()
	if err != nil {
		return fmt.Errorf("failed to finalize PKCS#11: %w", err)
	}

	sharedPKCS11Ctx = nil
	currentLibraryPath = ""

	return nil
}

// IsInitialized returns true if the PKCS#11 context has been initialized.
func IsInitialized() bool {
	contextMutex.RLock()
	defer contextMutex.RUnlock()
	return sharedPKCS11Ctx != nil
}

// GetLibraryPath returns the path to the currently loaded PKCS#11 library.
// Returns empty string if not initialized.
func GetLibraryPath() string {
	contextMutex.RLock()
	defer contextMutex.RUnlock()
	return currentLibraryPath
}

func GetFreshSlotList(libraryPath string) ([]uint, error) {
	ctx, err := GetOrInitPKCS11Context(libraryPath)
	if err != nil {
		return nil, err
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	// Convertir []pkcs11.SlotHandle a []uint
	result := make([]uint, len(slots))
	for i, slot := range slots {
		result[i] = uint(slot)
	}

	return result, nil
}

// GetFreshPKCS11Context crea un contexto PKCS#11 nuevo e inicializado
// Solo para operaciones que necesitan ver slots recién creados (como después de InitToken)
func GetFreshPKCS11Context(libraryPath string) (*pkcs11.Ctx, error) {
	// Crear un contexto completamente nuevo (no usar singleton)
	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create new PKCS#11 context from library: %s", libraryPath)
	}

	// Inicializar este contexto específico
	err := ctx.Initialize()
	if err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("failed to initialize new PKCS#11 context: %w", err)
	}

	return ctx, nil
}

// ClosePKCS11Context cierra un contexto creado con GetFreshPKCS11Context
func ClosePKCS11Context(ctx *pkcs11.Ctx) error {
	if ctx == nil {
		return nil
	}

	err := ctx.Finalize()
	if err != nil {
		return fmt.Errorf("failed to finalize PKCS#11 context: %w", err)
	}

	ctx.Destroy()
	return nil
}
