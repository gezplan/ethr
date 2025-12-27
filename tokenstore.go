package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// Keyring service name for ethr tokens
	keyringService = "ethr-hub"

	// Key names for keyring storage
	keyAccessToken  = "access_token"
	keyRefreshToken = "refresh_token"
	keyExpiresAt    = "expires_at"
	keyHubURL       = "hub_url"

	// PBKDF2 parameters for key derivation
	pbkdf2Iterations = 100000
	pbkdf2KeyLen     = 32 // AES-256
	pbkdf2SaltLen    = 16
)

// tokenData represents the token structure for storage
type tokenData struct {
	HubURL       string `json:"hub_url"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	SavedAt      int64  `json:"saved_at"`
}

// tokenStorage handles secure token persistence with keyring + encrypted file fallback
type tokenStorage struct {
	mu               sync.RWMutex
	keyringAvailable bool
	checked          bool
}

var storage = &tokenStorage{}

// checkKeyringAvailability tests if the OS keyring is accessible
func (ts *tokenStorage) checkKeyringAvailability() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.checked {
		return ts.keyringAvailable
	}

	ts.checked = true

	// Test keyring by trying to set and delete a test value
	testKey := "ethr-keyring-test"
	testValue := "test-" + fmt.Sprintf("%d", time.Now().UnixNano())

	err := keyring.Set(keyringService, testKey, testValue)
	if err != nil {
		ui.printDbg("Keyring not available: %v", err)
		ts.keyringAvailable = false
		return false
	}

	// Clean up test value
	_ = keyring.Delete(keyringService, testKey)

	ui.printDbg("Keyring available and working")
	ts.keyringAvailable = true
	return true
}

// Save stores tokens securely - tries keyring first, falls back to encrypted file
func (ts *tokenStorage) Save(serverURL, accessToken, refreshToken string, expiresIn int) error {
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second).Unix()
	hubID := getHubIdentifier(serverURL)

	if ts.checkKeyringAvailability() {
		return ts.saveToKeyring(hubID, serverURL, accessToken, refreshToken, expiresAt)
	}

	return ts.saveToEncryptedFile(serverURL, accessToken, refreshToken, expiresAt)
}

// Load retrieves tokens - tries keyring first, falls back to encrypted file
func (ts *tokenStorage) Load(serverURL string) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	hubID := getHubIdentifier(serverURL)

	if ts.checkKeyringAvailability() {
		return ts.loadFromKeyring(hubID)
	}

	return ts.loadFromEncryptedFile(serverURL)
}

// Clear removes stored tokens
func (ts *tokenStorage) Clear(serverURL string) {
	hubID := getHubIdentifier(serverURL)

	if ts.checkKeyringAvailability() {
		ts.clearFromKeyring(hubID)
	}

	// Always try to clear encrypted file as well (in case storage method changed)
	ts.clearEncryptedFile(serverURL)
}

// ListHubs returns all saved hub URLs
func (ts *tokenStorage) ListHubs() ([]string, error) {
	return ts.listHubsFromMetadata()
}

// --- Keyring Storage ---

func (ts *tokenStorage) saveToKeyring(hubID, serverURL, accessToken, refreshToken string, expiresAt int64) error {
	if err := keyring.Set(keyringService, hubID+":"+keyAccessToken, accessToken); err != nil {
		return fmt.Errorf("failed to save access token to keyring: %w", err)
	}

	if err := keyring.Set(keyringService, hubID+":"+keyRefreshToken, refreshToken); err != nil {
		return fmt.Errorf("failed to save refresh token to keyring: %w", err)
	}

	if err := keyring.Set(keyringService, hubID+":"+keyExpiresAt, fmt.Sprintf("%d", expiresAt)); err != nil {
		return fmt.Errorf("failed to save expiry to keyring: %w", err)
	}

	if err := keyring.Set(keyringService, hubID+":"+keyHubURL, serverURL); err != nil {
		return fmt.Errorf("failed to save hub URL to keyring: %w", err)
	}

	// Save metadata for hub enumeration
	if err := ts.saveHubMetadata(hubID, serverURL); err != nil {
		ui.printDbg("Warning: failed to save hub metadata: %v", err)
	}

	ui.printDbg("Tokens saved to OS keyring for hub: %s", hubID)
	return nil
}

func (ts *tokenStorage) loadFromKeyring(hubID string) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	accessToken, err = keyring.Get(keyringService, hubID+":"+keyAccessToken)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to load access token from keyring: %w", err)
	}

	refreshToken, err = keyring.Get(keyringService, hubID+":"+keyRefreshToken)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to load refresh token from keyring: %w", err)
	}

	expiresAtStr, err := keyring.Get(keyringService, hubID+":"+keyExpiresAt)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to load expiry from keyring: %w", err)
	}

	var expiresAtUnix int64
	_, err = fmt.Sscanf(expiresAtStr, "%d", &expiresAtUnix)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to parse expiry: %w", err)
	}

	ui.printDbg("Tokens loaded from OS keyring for hub: %s", hubID)
	return accessToken, refreshToken, time.Unix(expiresAtUnix, 0), nil
}

func (ts *tokenStorage) clearFromKeyring(hubID string) {
	_ = keyring.Delete(keyringService, hubID+":"+keyAccessToken)
	_ = keyring.Delete(keyringService, hubID+":"+keyRefreshToken)
	_ = keyring.Delete(keyringService, hubID+":"+keyExpiresAt)
	_ = keyring.Delete(keyringService, hubID+":"+keyHubURL)
	ts.clearHubMetadata(hubID)
	ui.printDbg("Tokens cleared from OS keyring for hub: %s", hubID)
}

// --- Encrypted File Storage (Fallback) ---

func (ts *tokenStorage) getEncryptedTokensDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".ethr_tokens"
	}
	return filepath.Join(homeDir, ".config", "ethr", "tokens")
}

func (ts *tokenStorage) getEncryptedFilePath(serverURL string) string {
	dir := ts.getEncryptedTokensDir()
	hubID := getHubIdentifier(serverURL)
	return filepath.Join(dir, hubID+".enc")
}

func (ts *tokenStorage) ensureEncryptedDir() error {
	dir := ts.getEncryptedTokensDir()
	return os.MkdirAll(dir, 0700)
}

// deriveEncryptionKey derives an encryption key using PBKDF2 from machine-specific data
func (ts *tokenStorage) deriveEncryptionKey(salt []byte) []byte {
	machineData := ts.getMachineIdentifier()
	return pbkdf2.Key([]byte(machineData), salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New)
}

// getMachineIdentifier returns a machine-specific string for key derivation
func (ts *tokenStorage) getMachineIdentifier() string {
	var parts []string

	if homeDir, err := os.UserHomeDir(); err == nil {
		parts = append(parts, homeDir)
	}

	if user := os.Getenv("USER"); user != "" {
		parts = append(parts, user)
	} else if user := os.Getenv("USERNAME"); user != "" {
		parts = append(parts, user)
	}

	if machineID := ts.getPlatformMachineID(); machineID != "" {
		parts = append(parts, machineID)
	}

	if hostname, err := os.Hostname(); err == nil {
		parts = append(parts, hostname)
	}

	parts = append(parts, runtime.GOOS, runtime.GOARCH)
	return strings.Join(parts, "|")
}

// getPlatformMachineID returns a platform-specific machine identifier
func (ts *tokenStorage) getPlatformMachineID() string {
	if runtime.GOOS == "linux" {
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if data, err := os.ReadFile(path); err == nil {
				return strings.TrimSpace(string(data))
			}
		}
	}
	return ""
}

func (ts *tokenStorage) saveToEncryptedFile(serverURL, accessToken, refreshToken string, expiresAt int64) error {
	if err := ts.ensureEncryptedDir(); err != nil {
		return fmt.Errorf("failed to create tokens directory: %w", err)
	}

	data := tokenData{
		HubURL:       serverURL,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		SavedAt:      time.Now().Unix(),
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	salt := make([]byte, pbkdf2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key := ts.deriveEncryptionKey(salt)
	ciphertext, err := ts.encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt token data: %w", err)
	}

	combined := append(salt, ciphertext...)
	encoded := base64.StdEncoding.EncodeToString(combined)

	filePath := ts.getEncryptedFilePath(serverURL)
	if err := os.WriteFile(filePath, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("failed to write encrypted token file: %w", err)
	}

	hubID := getHubIdentifier(serverURL)
	if err := ts.saveHubMetadata(hubID, serverURL); err != nil {
		ui.printDbg("Warning: failed to save hub metadata: %v", err)
	}

	ui.printDbg("Tokens saved to encrypted file (keyring unavailable) for hub: %s", serverURL)
	return nil
}

func (ts *tokenStorage) loadFromEncryptedFile(serverURL string) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	filePath := ts.getEncryptedFilePath(serverURL)

	encoded, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to read encrypted token file: %w", err)
	}

	combined, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to decode token data: %w", err)
	}

	if len(combined) < pbkdf2SaltLen+1 {
		return "", "", time.Time{}, fmt.Errorf("invalid encrypted token file format")
	}

	salt := combined[:pbkdf2SaltLen]
	ciphertext := combined[pbkdf2SaltLen:]

	key := ts.deriveEncryptionKey(salt)
	plaintext, err := ts.decrypt(ciphertext, key)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to decrypt token data: %w", err)
	}

	var data tokenData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	ui.printDbg("Tokens loaded from encrypted file for hub: %s", serverURL)
	return data.AccessToken, data.RefreshToken, time.Unix(data.ExpiresAt, 0), nil
}

func (ts *tokenStorage) clearEncryptedFile(serverURL string) {
	filePath := ts.getEncryptedFilePath(serverURL)
	_ = os.Remove(filePath)
	hubID := getHubIdentifier(serverURL)
	ts.clearHubMetadata(hubID)
}

// encrypt encrypts plaintext using AES-GCM
func (ts *tokenStorage) encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts ciphertext using AES-GCM
func (ts *tokenStorage) decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// --- Hub Metadata (for enumeration) ---

func (ts *tokenStorage) getMetadataDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".ethr_tokens"
	}
	return filepath.Join(homeDir, ".config", "ethr", "metadata")
}

func (ts *tokenStorage) saveHubMetadata(hubID, serverURL string) error {
	dir := ts.getMetadataDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	metadata := map[string]string{"hub_id": hubID, "hub_url": serverURL}
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, hubID+".meta"), data, 0600)
}

func (ts *tokenStorage) clearHubMetadata(hubID string) {
	dir := ts.getMetadataDir()
	_ = os.Remove(filepath.Join(dir, hubID+".meta"))
}

func (ts *tokenStorage) listHubsFromMetadata() ([]string, error) {
	dir := ts.getMetadataDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var hubs []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".meta") {
			filePath := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			var metadata map[string]string
			if err := json.Unmarshal(data, &metadata); err != nil {
				continue
			}

			if hubURL, ok := metadata["hub_url"]; ok {
				hubs = append(hubs, hubURL)
			}
		}
	}

	return hubs, nil
}
