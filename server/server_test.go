package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppConfigWithClientBinaries(t *testing.T) {
	// Create dummy client binary files
	tmpDir := t.TempDir()
	x86Bin := filepath.Join(tmpDir, "client")
	arm64Bin := filepath.Join(tmpDir, "client_arm64")
	if err := os.WriteFile(x86Bin, []byte("x86-binary"), 0755); err != nil {
		t.Fatalf("failed to write dummy x86 binary: %v", err)
	}
	if err := os.WriteFile(arm64Bin, []byte("arm64-binary"), 0755); err != nil {
		t.Fatalf("failed to write dummy arm64 binary: %v", err)
	}

	pubKeyPath := filepath.Join("..", "common", "testdata", "my-signing-key.pub.gpg.asc")
	privKeyPath := filepath.Join("..", "common", "testdata", "my-signing-key.priv.gpg.asc")

	configText := strings.Join([]string{
		"api_signing_token = test-token",
		"gpg_public_key = " + pubKeyPath,
		"gpg_private_key = " + privKeyPath,
		"rpm_sign_client_binary = " + x86Bin,
		"rpm_sign_arm64_client_binary = " + arm64Bin,
	}, "\n")

	config, err := loadAppConfigFromReader(io.NopCloser(strings.NewReader(configText)))
	if err != nil {
		t.Fatalf("unexpected error loading app config: %v", err)
	}

	if config.RpmSignClientBinary[ARCH_X86] != x86Bin {
		t.Errorf("expected ARCH_X86 path to be %s, got %s", x86Bin, config.RpmSignClientBinary[ARCH_X86])
	}
	if config.RpmSignClientBinary[ARCH_ARM64] != arm64Bin {
		t.Errorf("expected ARCH_ARM64 path to be %s, got %s", arm64Bin, config.RpmSignClientBinary[ARCH_ARM64])
	}
}

func TestHandleClientDownload(t *testing.T) {
	tmpDir := t.TempDir()
	x86Bin := filepath.Join(tmpDir, "client")
	arm64Bin := filepath.Join(tmpDir, "client_arm64")
	if err := os.WriteFile(x86Bin, []byte("binary-content-x86"), 0755); err != nil {
		t.Fatalf("failed to write dummy x86 binary: %v", err)
	}
	if err := os.WriteFile(arm64Bin, []byte("binary-content-arm64"), 0755); err != nil {
		t.Fatalf("failed to write dummy arm64 binary: %v", err)
	}

	config := AppConfig{
		RpmSignClientBinary: map[Architecture]string{
			ARCH_X86:   x86Bin,
			ARCH_ARM64: arm64Bin,
		},
	}

	tests := []struct {
		name           string
		url            string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "default arch (no query param)",
			url:            "/clientDownload",
			expectedStatus: http.StatusOK,
			expectedBody:   "binary-content-x86",
		},
		{
			name:           "explicit x86 arch",
			url:            "/clientDownload?arch=x86",
			expectedStatus: http.StatusOK,
			expectedBody:   "binary-content-x86",
		},
		{
			name:           "explicit arm64 arch",
			url:            "/clientDownload?arch=arm64",
			expectedStatus: http.StatusOK,
			expectedBody:   "binary-content-arm64",
		},
		{
			name:           "case insensitive arm64",
			url:            "/clientDownload?arch=ARM64",
			expectedStatus: http.StatusOK,
			expectedBody:   "binary-content-arm64",
		},
		{
			name:           "unsupported architecture",
			url:            "/clientDownload?arch=mips",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Unsupported architecture\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()

			handleClientDownload(rec, req, config)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
			if rec.Body.String() != tc.expectedBody {
				t.Errorf("expected body %q, got %q", tc.expectedBody, rec.Body.String())
			}
		})
	}

	// Test missing architecture binary
	t.Run("missing arch binary", func(t *testing.T) {
		partialConfig := AppConfig{
			RpmSignClientBinary: map[Architecture]string{
				ARCH_X86: x86Bin,
			},
		}
		req := httptest.NewRequest(http.MethodGet, "/clientDownload?arch=arm64", nil)
		rec := httptest.NewRecorder()

		handleClientDownload(rec, req, partialConfig)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
		}
	})

	// Test empty config map
	t.Run("empty config map", func(t *testing.T) {
		emptyConfig := AppConfig{
			RpmSignClientBinary: map[Architecture]string{},
		}
		req := httptest.NewRequest(http.MethodGet, "/clientDownload", nil)
		rec := httptest.NewRecorder()

		handleClientDownload(rec, req, emptyConfig)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
		}
	})
}
