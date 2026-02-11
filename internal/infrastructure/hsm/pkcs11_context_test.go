package hsm

import (
	"testing"
)

func TestGetOrInitPKCS11Context_Singleton(t *testing.T) {
	// This test verifies that GetOrInitPKCS11Context returns the same instance
	// Note: This test will fail if SoftHSM is not installed
	// In CI/CD, mock the PKCS#11 library or skip this test

	libPath := "/usr/lib/softhsm/libsofthsm2.so"

	// First call should initialize
	ctx1, err1 := GetOrInitPKCS11Context(libPath)
	if err1 != nil {
		t.Skipf("Skipping test - PKCS#11 library not available: %v", err1)
	}

	if ctx1 == nil {
		t.Fatal("Expected non-nil context")
	}

	// Second call should return the same instance
	ctx2, err2 := GetOrInitPKCS11Context(libPath)
	if err2 != nil {
		t.Fatalf("Second call failed: %v", err2)
	}

	if ctx1 != ctx2 {
		t.Error("Expected same context instance (singleton pattern)")
	}

	// Verify IsInitialized returns true
	if !IsInitialized() {
		t.Error("Expected IsInitialized() to return true")
	}

	// Verify GetLibraryPath returns correct path
	if GetLibraryPath() != libPath {
		t.Errorf("Expected library path %s, got %s", libPath, GetLibraryPath())
	}
}

func TestGetOrInitPKCS11Context_DifferentLibrary(t *testing.T) {
	// This test verifies that attempting to initialize with a different library fails
	// Note: This test assumes the context was already initialized in the previous test

	if !IsInitialized() {
		t.Skip("Context not initialized, skipping test")
	}

	differentLibPath := "/different/path/libsofthsm2.so"

	_, err := GetOrInitPKCS11Context(differentLibPath)
	if err == nil {
		t.Error("Expected error when trying to use different library path")
	}
}
