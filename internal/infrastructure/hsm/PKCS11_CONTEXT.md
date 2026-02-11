# PKCS#11 Context Singleton Pattern

## Overview
This implementation ensures that `pkcs11.Ctx.Initialize()` is called **only once per process**, which is required by the PKCS#11 specification. All HSM clients in the application share the same PKCS#11 context but open separate sessions on different slots.

## Files Modified

### New Files
- `pkcs11_context.go` - Singleton implementation for PKCS#11 context management

### Modified Files
- `client.go` - Updated to use shared context via `GetOrInitPKCS11Context()`
- `manager.go` - Updated `CloseAll()` to call `FinalizePKCS11Context()` on shutdown

## Key Functions

### `GetOrInitPKCS11Context(libraryPath string) (*pkcs11.Ctx, error)`
Returns the shared PKCS#11 context, initializing it if necessary. Thread-safe using `sync.Once`.

**Usage:**
```go
ctx, err := GetOrInitPKCS11Context("/usr/lib/softhsm/libsofthsm2.so")
if err != nil {
    return nil, fmt.Errorf("failed to get PKCS#11 context: %w", err)
}
```

### `FinalizePKCS11Context() error`
Finalizes and releases the shared PKCS#11 context. Should only be called during application shutdown.

**Usage:**
```go
// Called in HSMManager.CloseAll()
if err := FinalizePKCS11Context(); err != nil {
    log.Printf("Warning: failed to finalize PKCS#11: %v", err)
}
```

### `IsInitialized() bool`
Returns true if the PKCS#11 context has been initialized.

### `GetLibraryPath() string`
Returns the path to the currently loaded PKCS#11 library.

## Architecture

### Before (Problem)
```
SoftHSMClient #1 → pkcs11.New() → ctx.Initialize() 
SoftHSMClient #2 → pkcs11.New() → ctx.Initialize()  CKR_CRYPTOKI_ALREADY_INITIALIZED
```

### After (Solution)
```
GetOrInitPKCS11Context() → [sync.Once] → ctx.Initialize() 
    ↓
    ├─ SoftHSMClient #1 → uses shared ctx → OpenSession(slot=0)
    ├─ SoftHSMClient #2 → uses shared ctx → OpenSession(slot=1)
    └─ SoftHSMClient #N → uses shared ctx → OpenSession(slot=N)
```

## Lifecycle

### Startup
1. First call to `GetOrInitPKCS11Context()` initializes the library
2. Subsequent calls return the cached context
3. Each HSM client opens its own session on a specific slot

### Runtime
- Multiple clients can coexist, each with sessions on different slots
- All clients share the same PKCS#11 context
- Sessions are independent and can be opened/closed without affecting others

### Shutdown
1. `HSMManager.CloseAll()` closes all client sessions
2. `FinalizePKCS11Context()` finalizes the PKCS#11 library (called once)
3. After finalization, the context cannot be reinitialized (by design)

## Thread Safety
- `sync.Once` ensures single initialization
- `sync.RWMutex` protects context state access
- Safe for concurrent use by multiple goroutines

## Important Notes

### DO NOT:
- Call `ctx.Initialize()` directly in client code
- Call `ctx.Finalize()` in individual clients
- Call `ctx.Destroy()` in individual clients
- Try to reinitialize after calling `FinalizePKCS11Context()`

### DO:
- Use `GetOrInitPKCS11Context()` to obtain the context
- Call `ctx.OpenSession()` for each slot
- Call `ctx.CloseSession()` when done with a session
- Call `ctx.Logout()` before closing a session
- Call `FinalizePKCS11Context()` only during app shutdown

## Testing

Run tests with:
```bash
go test ./internal/infrastructure/hsm/pkcs11_context_test.go
```

Note: Tests require SoftHSM to be installed. Tests will be skipped if the library is not available.

## Migration from Old Code

If you have existing code that calls `ctx.Initialize()` directly:

**Old:**
```go
ctx := pkcs11.New(modulePath)
ctx.Initialize() // Will fail for second client
```

**New:**
```go
ctx, err := GetOrInitPKCS11Context(modulePath)
if err != nil {
    return err
}
// ctx is already initialized
```

## Troubleshooting

### Error: "CKR_CRYPTOKI_ALREADY_INITIALIZED"
**Cause:** Code is still calling `ctx.Initialize()` directly  
**Solution:** Use `GetOrInitPKCS11Context()` instead

### Error: "PKCS#11 already initialized with different library"
**Cause:** Attempting to initialize with a different library path  
**Solution:** Ensure all clients use the same `libraryPath`

### Context is nil after GetOrInitPKCS11Context
**Cause:** Initialization failed (check logs for details)  
**Solution:** Verify library path is correct and SoftHSM is installed

## Performance Impact
**Positive:** Eliminates redundant initialization attempts  
**Positive:** Reduces memory overhead (single context instead of multiple)  
**Neutral:** Minimal locking overhead (read-mostly pattern)
