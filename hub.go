//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Hub integration structures - allows ethr to be controlled by a central hub
type HubConfig struct {
	ServerURL string
	Title     string
}

type HubAuth struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	mu           sync.RWMutex
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

type AgentRegistrationRequest struct {
	Hostname     string   `json:"hostname,omitempty"`
	IpAddress    string   `json:"ipAddress,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Version      string   `json:"version,omitempty"`
	Title        string   `json:"title,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type AgentRegistrationResponse struct {
	AgentId      string `json:"agentId"`
	PollInterval int    `json:"pollInterval"`
}

type CommandResponse struct {
	HasCommand bool        `json:"hasCommand"`
	SessionId  string      `json:"sessionId,omitempty"`
	Command    TestCommand `json:"command,omitempty"`
}

type TestCommand struct {
	Mode             string            `json:"mode"`
	Protocol         string            `json:"protocol"`
	TestType         string            `json:"testType"`
	Title            string            `json:"title,omitempty"`
	Destination      string            `json:"destination,omitempty"`
	Port             int               `json:"port"`
	DurationSeconds  int               `json:"durationSeconds"`
	Threads          int               `json:"threads"`
	BufferSize       string            `json:"bufferSize,omitempty"`
	Bandwidth        string            `json:"bandwidth,omitempty"`
	Reverse          bool              `json:"reverse"`
	Tos              int               `json:"tos"`
	AdditionalParams map[string]string `json:"additionalParams,omitempty"`
}

type TestResult struct {
	Timestamp         time.Time              `json:"timestamp"`
	Source            string                 `json:"source"`
	Type              string                 `json:"type"`
	Protocol          string                 `json:"protocol,omitempty"`
	Interval          *int                   `json:"interval,omitempty"`
	BitsPerSec        *int64                 `json:"bitsPerSec,omitempty"`
	BytesTransferred  *int64                 `json:"bytesTransferred,omitempty"`
	PacketsPerSec     *int64                 `json:"packetsPerSec,omitempty"`
	ConnectionsPerSec *int64                 `json:"connectionsPerSec,omitempty"`
	LatencyMs         *float64               `json:"latencyMs,omitempty"`
	JitterMs          *float64               `json:"jitterMs,omitempty"`
	PacketLoss        *float64               `json:"packetLoss,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	// Test parameters (for display in UI)
	TestParams        *TestParameters        `json:"testParams,omitempty"`
}

type TestParameters struct {
	TestType     string `json:"testType"`
	Protocol     string `json:"protocol"`
	Threads      int    `json:"threads"`
	BufferSize   string `json:"bufferSize"`
	Duration     int    `json:"duration"`
	Bandwidth    string `json:"bandwidth,omitempty"`
	Reverse      bool   `json:"reverse"`
	Destination  string `json:"destination,omitempty"`
	Port         int    `json:"port,omitempty"`
	Title        string `json:"title,omitempty"`
	ClientName   string `json:"clientName,omitempty"`
}

type ResultSubmissionRequest struct {
	SessionId string     `json:"sessionId"`
	Result    TestResult `json:"result"`
	IsFinal   bool       `json:"isFinal"`
}

type StatusUpdateRequest struct {
	SessionId    string `json:"sessionId"`
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

type HeartbeatRequest struct {
	AgentId string `json:"agentId"`
	Status  string `json:"status"`
}

var hubAuth *HubAuth
var hubAgentId string
var hubAgentTitle string
var hubHttpClient *http.Client

// Track running tests for cancellation
var runningTests = struct {
	sync.RWMutex
	tests map[string]chan struct{} // sessionId -> cancel channel
}{tests: make(map[string]chan struct{})}

// Mutex to prevent overlapping server tests on same port
var serverTestMutex sync.Mutex

// Token persistence helpers - per-hub storage
func getTokensDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".ethr_tokens"
	}
	return homeDir + "/.ethr_tokens"
}

func getHubIdentifier(serverURL string) string {
	// Create a safe filename from the server URL
	// Remove protocol and replace special chars with underscores
	identifier := strings.TrimPrefix(serverURL, "https://")
	identifier = strings.TrimPrefix(identifier, "http://")
	identifier = strings.ReplaceAll(identifier, "/", "_")
	identifier = strings.ReplaceAll(identifier, ":", "_")
	identifier = strings.ReplaceAll(identifier, ".", "_")
	return identifier
}

func getTokenFilePath(serverURL string) string {
	dir := getTokensDir()
	hubId := getHubIdentifier(serverURL)
	return fmt.Sprintf("%s/%s.json", dir, hubId)
}

func ensureTokensDir() error {
	dir := getTokensDir()
	return os.MkdirAll(dir, 0700)
}

func saveTokens(serverURL, accessToken, refreshToken string, expiresIn int) error {
	if err := ensureTokensDir(); err != nil {
		return err
	}
	
	tokenData := map[string]interface{}{
		"hub_url":       serverURL,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_at":    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		"saved_at":      time.Now().Unix(),
	}
	
	data, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(getTokenFilePath(serverURL), data, 0600)
}

// acquireTokenLock acquires an exclusive lock on the token file to prevent
// race conditions when multiple clients try to refresh simultaneously.
// Uses cross-platform file-based locking that works on Unix, Windows, and macOS.
func acquireTokenLock(serverURL string) (string, error) {
	lockPath := getTokenFilePath(serverURL) + ".lock"
	
	// Try to create the lock file exclusively
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		// O_CREATE | O_EXCL ensures atomic creation - fails if file exists
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			// Successfully created lock file
			// Write our PID to help with debugging
			fmt.Fprintf(lockFile, "%d\n", os.Getpid())
			lockFile.Close()
			ui.printDbg("Token lock acquired")
			return lockPath, nil
		}
		
		// Lock file already exists, check if it's stale
		if info, statErr := os.Stat(lockPath); statErr == nil {
			// If lock file is older than 30 seconds, assume previous process crashed
			if time.Since(info.ModTime()) > 30*time.Second {
				ui.printDbg("Removing stale lock file")
				os.Remove(lockPath)
				continue
			}
		}
		
		// Wait and retry
		select {
		case <-timeout:
			return "", fmt.Errorf("timeout waiting for token lock")
		case <-ticker.C:
			// Continue loop
		}
	}
}

// releaseTokenLock releases the lock by removing the lock file
func releaseTokenLock(lockPath string) {
	if lockPath != "" {
		os.Remove(lockPath)
		ui.printDbg("Token lock released")
	}
}

func loadTokens(serverURL string) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	data, err := os.ReadFile(getTokenFilePath(serverURL))
	if err != nil {
		return "", "", time.Time{}, err
	}
	
	var tokenData map[string]interface{}
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return "", "", time.Time{}, err
	}
	
	accessToken, _ = tokenData["access_token"].(string)
	refreshToken, _ = tokenData["refresh_token"].(string)
	expiresAtUnix, _ := tokenData["expires_at"].(float64)
	expiresAt = time.Unix(int64(expiresAtUnix), 0)
	
	return accessToken, refreshToken, expiresAt, nil
}

func clearTokens(serverURL string) {
	os.Remove(getTokenFilePath(serverURL))
}

func listSavedHubs() ([]string, error) {
	dir := getTokensDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	
	var hubs []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			filePath := fmt.Sprintf("%s/%s", dir, entry.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			
			var tokenData map[string]interface{}
			if err := json.Unmarshal(data, &tokenData); err != nil {
				continue
			}
			
			if hubURL, ok := tokenData["hub_url"].(string); ok {
				hubs = append(hubs, hubURL)
			}
		}
	}
	
	return hubs, nil
}

func tryRefreshToken(serverURL string, refreshToken string) (*TokenResponse, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
	})
	
	ui.printDbg("Token refresh request: %s", string(reqBody))
	
	resp, err := hubHttpClient.Post(
		serverURL+"/api/token/refresh",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	
	return &tokenResp, nil
}

func runHubAgent(config HubConfig) {
	ui.printMsg("Starting hub integration mode...")
	ui.printMsg("Hub server: %s", config.ServerURL)

	// Initialize HTTP client with TLS
	hubHttpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	// Initialize auth
	hubAuth = &HubAuth{}

	// Show information about saved credentials
	savedHubs, _ := listSavedHubs()
	if len(savedHubs) > 0 {
		ui.printDbg("Found saved credentials for %d hub(s)", len(savedHubs))
		for _, hub := range savedHubs {
			if hub == config.ServerURL {
				ui.printDbg("  - %s (current)", hub)
			} else {
				ui.printDbg("  - %s", hub)
			}
		}
	}

	// Try to load saved tokens first
	loadedAccessToken, loadedRefreshToken, expiresAt, err := loadTokens(config.ServerURL)
	if err == nil && loadedRefreshToken != "" {
		ui.printMsg("Found saved credentials for this hub, attempting automatic login...")
		ui.printDbg("Loaded token expires at: %v (in %v)", expiresAt, time.Until(expiresAt))
		
		// Check if access token is still valid (with 5 minute buffer, or 30 seconds for short-lived tokens)
		bufferTime := 5 * time.Minute
		if time.Until(expiresAt) < 2*time.Minute {
			// For short-lived tokens (< 2 minutes), use 30 second buffer
			bufferTime = 30 * time.Second
		}
		
		if time.Now().Before(expiresAt.Add(-bufferTime)) {
			// Access token is still valid
			ui.printDbg("Using cached access token (valid for %v more)", time.Until(expiresAt))
			hubAuth.AccessToken = loadedAccessToken
			hubAuth.RefreshToken = loadedRefreshToken
			hubAuth.ExpiresAt = expiresAt
		} else {
			// Try to refresh the token
			ui.printDbg("Access token expired or expiring soon, refreshing...")
			ui.printDbg("Refresh token: %.20s...", loadedRefreshToken)
			tokenResp, err := tryRefreshToken(config.ServerURL, loadedRefreshToken)
			if err == nil {
				ui.printDbg("Token refreshed successfully")
				hubAuth.AccessToken = tokenResp.AccessToken
				hubAuth.RefreshToken = tokenResp.RefreshToken
				hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				
				// Save new tokens
				saveTokens(config.ServerURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
				ui.printDbg("New tokens saved, expires at: %v", hubAuth.ExpiresAt)
			} else {
				ui.printMsg("Token refresh failed: %v", err)
				ui.printMsg("Clearing saved credentials and starting new authentication...")
				clearTokens(config.ServerURL)
				// Will fall through to device auth below
				hubAuth = &HubAuth{}
			}
		}
	} else if err != nil {
		ui.printDbg("No saved credentials for this hub: %v", err)
	}

	// If no valid tokens, perform device authentication flow
	if hubAuth.AccessToken == "" {
		if err := performDeviceAuth(config.ServerURL); err != nil {
			ui.printErr("Authentication failed: %v", err)
			os.Exit(1)
		}
		
		// Save tokens after successful auth
		saveTokens(config.ServerURL, hubAuth.AccessToken, hubAuth.RefreshToken, 3600)
		ui.printMsg("Credentials saved for future use")
	}

	ui.printMsg("Authentication successful!")

	// Register agent with hub
	err = registerAgent(config.ServerURL, config.Title)
	if err != nil {
		// If registration fails with what looks like an auth error, try refreshing token
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "Unauthorized") {
			ui.printDbg("Registration failed with auth error, attempting token refresh...")
			
			hubAuth.mu.RLock()
			refreshToken := hubAuth.RefreshToken
			hubAuth.mu.RUnlock()
			
			if refreshToken != "" {
				tokenResp, refreshErr := tryRefreshToken(config.ServerURL, refreshToken)
				if refreshErr == nil {
					ui.printDbg("Token refreshed successfully, retrying registration...")
					hubAuth.mu.Lock()
					hubAuth.AccessToken = tokenResp.AccessToken
					hubAuth.RefreshToken = tokenResp.RefreshToken
					hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
					hubAuth.mu.Unlock()
					
					// Save new tokens
					saveTokens(config.ServerURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
					
					// Retry registration
					err = registerAgent(config.ServerURL, config.Title)
				} else {
					ui.printMsg("Token refresh failed: %v", refreshErr)
					ui.printMsg("Clearing saved credentials and starting new authentication...")
					clearTokens(config.ServerURL)
					if err := performDeviceAuth(config.ServerURL); err != nil {
						ui.printErr("Authentication failed: %v", err)
						os.Exit(1)
					}
					saveTokens(config.ServerURL, hubAuth.AccessToken, hubAuth.RefreshToken, 3600)
					err = registerAgent(config.ServerURL, config.Title)
				}
			}
		}
		
		if err != nil {
			ui.printErr("Agent registration failed: %v", err)
			os.Exit(1)
		}
	}

	ui.printMsg("Agent registered successfully (ID: %s)", hubAgentId)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Start token refresh goroutine
	go tokenRefreshLoop(config.ServerURL)

	// Start heartbeat goroutine
	go heartbeatLoop(config.ServerURL)

	// Start command polling loop in goroutine
	go commandLoop(config.ServerURL)
	
	// Wait for interrupt signal
	<-sigChan
	ui.printMsg("\nReceived interrupt signal, shutting down gracefully...")
	
	// Clean up and exit
	os.Exit(0)
}

func performDeviceAuth(serverURL string) error {
	// Request device code
	resp, err := hubHttpClient.Post(
		serverURL+"/api/device/code",
		"application/json",
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("device code request failed: %s", string(body))
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return fmt.Errorf("failed to decode device code response: %w", err)
	}

	// Display instructions to user
	ui.printMsg("\n" + strings.Repeat("=", 70))
	ui.printMsg("AUTHENTICATION REQUIRED")
	ui.printMsg(strings.Repeat("=", 70))
	ui.printMsg("")
	ui.printMsg("Please visit: %s", deviceCode.VerificationUri)
	ui.printMsg("")
	ui.printMsg("And enter code: %s", deviceCode.UserCode)
	ui.printMsg("")
	ui.printMsg("Or visit directly: %s", deviceCode.VerificationUriComplete)
	ui.printMsg("")
	ui.printMsg(strings.Repeat("=", 70))
	ui.printMsg("Waiting for authorization...")

	// Poll for token
	interval := time.Duration(deviceCode.Interval) * time.Second
	expiresAt := time.Now().Add(time.Duration(deviceCode.ExpiresIn) * time.Second)

	for time.Now().Before(expiresAt) {
		time.Sleep(interval)

		// Request token
		tokenReq := map[string]string{
			"device_code": deviceCode.DeviceCode,
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		}
		reqBody, _ := json.Marshal(tokenReq)

		resp, err := hubHttpClient.Post(
			serverURL+"/api/device/token",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		if err != nil {
			continue
		}

		var tokenResp TokenResponse
		json.NewDecoder(resp.Body).Decode(&tokenResp)
		resp.Body.Close()

		if tokenResp.Error == "authorization_pending" {
			continue
		} else if tokenResp.Error == "slow_down" {
			interval = interval + (5 * time.Second)
			continue
		} else if tokenResp.Error != "" {
			return fmt.Errorf("token request failed: %s", tokenResp.Error)
		}

		// Success - save tokens
		hubAuth.mu.Lock()
		hubAuth.AccessToken = tokenResp.AccessToken
		hubAuth.RefreshToken = tokenResp.RefreshToken
		hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		hubAuth.mu.Unlock()

		return nil
	}

	return fmt.Errorf("device code expired before authorization")
}

func generateFriendlyTitle() string {
	words1 := []string{
		"Swift", "Turbo", "Rapid", "Quick", "Flash",
		"Sonic", "Nitro", "Blaze", "Storm", "Thunder",
		"Rocket", "Laser", "Plasma", "Quantum", "Cyber",
		"Hyper", "Ultra", "Mega", "Super", "Alpha",
	}
	
	words2 := []string{
		"Bolt", "Dash", "Rush", "Blast", "Pulse",
		"Wave", "Spark", "Flow", "Flux", "Sync",
		"Link", "Node", "Core", "Edge", "Net",
		"Hub", "Beam", "Ray", "Peak", "Zone",
	}
	
	// Use timestamp and process ID for better randomness
	seed := time.Now().UnixNano()
	pid := os.Getpid()
	
	// Use different parts of the seed for each index
	idx1 := int((seed ^ int64(pid)) % int64(len(words1)))
	idx2 := int((seed >> 16) % int64(len(words2)))
	
	return fmt.Sprintf("%s%s", words1[idx1], words2[idx2])
}

func registerAgent(serverURL string, title string) error {
	hostname, _ := os.Hostname()
	
	// Auto-generate title if not provided
	autoGenerated := false
	if title == "" {
		title = generateFriendlyTitle()
		autoGenerated = true
	}
	
	// Store title globally for re-registration
	hubAgentTitle = title
	
	req := AgentRegistrationRequest{
		Hostname:     hostname,
		IpAddress:    getLocalIP(),
		Platform:     runtime.GOOS,
		Version:      gVersion,
		Title:        title,
		Capabilities: []string{"bandwidth", "latency", "cps", "pps"},
	}
	
	// Print session title in a box
	ui.printMsg("╔═══════════════════════════════════════════════════════════════╗")
	ui.printMsg("║  Session Title: %-46s║", title)
	ui.printMsg("╚═══════════════════════════════════════════════════════════════╝")
	if autoGenerated {
		ui.printMsg("Customize session title with -T flag")
	}

	reqBody, _ := json.Marshal(req)

	httpReq, err := http.NewRequest("POST", serverURL+"/api/cli/agent/register", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	hubAuth.mu.RLock()
	accessToken := hubAuth.AccessToken
	hubAuth.mu.RUnlock()
	
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	ui.printDbg("Registering agent with token: %s...", accessToken[:20])

	resp, err := hubHttpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	ui.printDbg("Registration response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		ui.printDbg("Registration error body: %s", string(body))
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	ui.printDbg("Registration response body: %s", string(body))

	var regResp AgentRegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	hubAgentId = regResp.AgentId
	return nil
}

func tokenRefreshLoop(serverURL string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		hubAuth.mu.RLock()
		expiresAt := hubAuth.ExpiresAt
		hubAuth.mu.RUnlock()

		// Calculate refresh buffer based on token lifetime
		timeUntilExpiry := time.Until(expiresAt)
		var refreshBuffer time.Duration
		
		if timeUntilExpiry < 2*time.Minute {
			// For short-lived tokens (< 2 minutes), refresh 30 seconds before expiry
			refreshBuffer = 30 * time.Second
		} else {
			// For longer-lived tokens, refresh 5 minutes before expiry
			refreshBuffer = 5 * time.Minute
		}
		
		timeToRefresh := timeUntilExpiry - refreshBuffer
		if timeToRefresh > 0 {
			// Token is still valid, no need to refresh yet
			continue
		}
		
		ui.printDbg("Token needs refresh (expires in %v)", timeUntilExpiry)

		// Acquire lock to prevent race conditions with multiple clients
		lockPath, err := acquireTokenLock(serverURL)
		if err != nil {
			ui.printErr("Failed to acquire token lock: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}

		// Reload tokens from disk after acquiring lock
		// Another client may have already refreshed while we were waiting
		diskAccessToken, diskRefreshToken, diskExpiresAt, err := loadTokens(serverURL)
		if err == nil && diskRefreshToken != "" {
			// Check if the token was recently refreshed by another client
			timeUntilExpiry := time.Until(diskExpiresAt)
			var refreshBuffer time.Duration
			if timeUntilExpiry < 2*time.Minute {
				refreshBuffer = 30 * time.Second
			} else {
				refreshBuffer = 5 * time.Minute
			}
			
			if timeUntilExpiry > refreshBuffer {
				// Token was already refreshed by another client, use it
				ui.printDbg("Token was already refreshed by another client (valid for %v more)", timeUntilExpiry)
				hubAuth.mu.Lock()
				hubAuth.AccessToken = diskAccessToken
				hubAuth.RefreshToken = diskRefreshToken
				hubAuth.ExpiresAt = diskExpiresAt
				hubAuth.mu.Unlock()
				releaseTokenLock(lockPath)
				continue
			}
		}

		// Still need to refresh
		refreshToken := diskRefreshToken
		if refreshToken == "" {
			// Fallback to memory if disk load failed
			hubAuth.mu.RLock()
			refreshToken = hubAuth.RefreshToken
			hubAuth.mu.RUnlock()
		}

		if refreshToken == "" {
			ui.printErr("Token refresh failed: refresh token is empty")
			releaseTokenLock(lockPath)
			time.Sleep(30 * time.Second)
			continue
		}

		reqBody, _ := json.Marshal(map[string]string{
			"refresh_token": refreshToken,
		})

		ui.printDbg("Token refresh loop - refresh token: %.20s...", refreshToken)
		ui.printDbg("Token refresh request body: %s", string(reqBody))

		resp, err := hubHttpClient.Post(
			serverURL+"/api/token/refresh",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		if err != nil {
			ui.printErr("Token refresh failed: %v", err)
			releaseTokenLock(lockPath)
			time.Sleep(30 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ui.printErr("Token refresh failed (HTTP %d): %s", resp.StatusCode, string(body))
			releaseTokenLock(lockPath)
			time.Sleep(30 * time.Second)
			continue
		}

		var tokenResp TokenResponse
		json.NewDecoder(resp.Body).Decode(&tokenResp)
		resp.Body.Close()

		if tokenResp.Error != "" {
			ui.printErr("Token refresh failed: %s", tokenResp.Error)
			releaseTokenLock(lockPath)
			time.Sleep(30 * time.Second)
			continue
		}

		hubAuth.mu.Lock()
		hubAuth.AccessToken = tokenResp.AccessToken
		hubAuth.RefreshToken = tokenResp.RefreshToken
		hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		hubAuth.mu.Unlock()

		// Save refreshed tokens to disk
		saveTokens(serverURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)

		// Release lock after saving
		releaseTokenLock(lockPath)

		ui.printDbg("Token refreshed successfully")
	}
}

func heartbeatLoop(serverURL string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ui.printDbg("Sending heartbeat...")
		reqBody, _ := json.Marshal(HeartbeatRequest{
			AgentId: hubAgentId,
			Status:  "Connected",
		})

		httpReq, err := http.NewRequest("POST", serverURL+"/api/cli/agent/heartbeat", bytes.NewBuffer(reqBody))
		if err != nil {
			ui.printDbg("Heartbeat request creation failed: %v", err)
			continue
		}

		hubAuth.mu.RLock()
		httpReq.Header.Set("Authorization", "Bearer "+hubAuth.AccessToken)
		hubAuth.mu.RUnlock()
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := hubHttpClient.Do(httpReq)
		if err != nil {
			ui.printDbg("Heartbeat failed: %v", err)
			continue
		}
		
		if resp.StatusCode == http.StatusUnauthorized {
			// Token expired, refresh immediately
			resp.Body.Close()
			ui.printDbg("Heartbeat failed with 401, refreshing token immediately...")
			
			hubAuth.mu.RLock()
			refreshToken := hubAuth.RefreshToken
			hubAuth.mu.RUnlock()
			
			tokenResp, err := tryRefreshToken(serverURL, refreshToken)
			if err != nil {
				// Refresh failed - maybe another process already refreshed?
				// Try re-reading tokens from disk before giving up
				ui.printDbg("Refresh failed, re-reading tokens from disk...")
				accessToken, refreshToken, expiresAt, loadErr := loadTokens(serverURL)
				if loadErr == nil {
					hubAuth.mu.Lock()
					hubAuth.AccessToken = accessToken
					hubAuth.RefreshToken = refreshToken
					hubAuth.ExpiresAt = expiresAt
					hubAuth.mu.Unlock()
					ui.printDbg("Loaded updated tokens from disk, will retry on next heartbeat")
					continue
				}
				
				// Still failed - refresh token is invalid (server restarted or token expired)
				// Clear tokens and re-authenticate
				ui.printMsg("Refresh token invalid, re-authenticating...")
				clearTokens(serverURL)
				
				if err := performDeviceAuth(serverURL); err != nil {
					ui.printErr("Re-authentication failed: %v", err)
					time.Sleep(30 * time.Second)
					continue
				}
				
				saveTokens(serverURL, hubAuth.AccessToken, hubAuth.RefreshToken, 3600)
				ui.printMsg("Re-authentication successful")
				
				// Also need to re-register since server may have restarted
				if err := registerAgent(serverURL, hubAgentTitle); err != nil {
					ui.printErr("Re-registration failed: %v", err)
					time.Sleep(30 * time.Second)
					continue
				}
				ui.printMsg("Re-registered successfully with new agent ID: %s", hubAgentId)
				continue
			}
			
			hubAuth.mu.Lock()
			hubAuth.AccessToken = tokenResp.AccessToken
			hubAuth.RefreshToken = tokenResp.RefreshToken
			hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
			hubAuth.mu.Unlock()
			
			saveTokens(serverURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
			ui.printDbg("Token refreshed successfully, next heartbeat will use new token")
		} else if resp.StatusCode == http.StatusNotFound {
			// Agent not found (server probably restarted), re-register
			resp.Body.Close()
			ui.printMsg("Agent not found on server (server may have restarted), re-registering...")
			
			if err := registerAgent(serverURL, hubAgentTitle); err != nil {
				ui.printErr("Re-registration failed: %v", err)
			} else {
				ui.printMsg("Re-registered successfully with new agent ID: %s", hubAgentId)
			}
		} else if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ui.printDbg("Heartbeat failed (HTTP %d): %s", resp.StatusCode, string(body))
		} else {
			resp.Body.Close()
			ui.printDbg("Heartbeat sent successfully")
		}
	}
}

func commandLoop(serverURL string) {
	ui.printMsg("Waiting for commands from hub server...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Poll for command
		httpReq, err := http.NewRequest("GET", serverURL+"/api/cli/agent/command?agentId="+hubAgentId, nil)
		if err != nil {
			ui.printErr("Failed to create command request: %v", err)
			continue
		}

		hubAuth.mu.RLock()
		httpReq.Header.Set("Authorization", "Bearer "+hubAuth.AccessToken)
		hubAuth.mu.RUnlock()

		resp, err := hubHttpClient.Do(httpReq)
		if err != nil {
			ui.printErr("Failed to poll for commands: %v", err)
			continue
		}

		var cmdResp CommandResponse
		json.NewDecoder(resp.Body).Decode(&cmdResp)
		resp.Body.Close()

		if cmdResp.HasCommand {
			// Check if this is a cancel command
			if cmdResp.Command.Mode == "cancel" {
				ui.printDbg("Received cancel command for session: %s", cmdResp.SessionId)
				cancelTest(cmdResp.SessionId)
			} else {
				ui.printMsg("Received command for session: %s", cmdResp.SessionId)
				go executeCommand(serverURL, cmdResp.SessionId, cmdResp.Command)
			}
		}
	}
}

func cancelTest(sessionId string) {
	runningTests.Lock()
	defer runningTests.Unlock()
	
	// Debug: print all running tests
	ui.printDbg("Looking for session %s to cancel. Currently running tests:", sessionId)
	for id := range runningTests.tests {
		ui.printDbg("  - %s", id)
	}
	
	if cancelChan, exists := runningTests.tests[sessionId]; exists {
		close(cancelChan)
		delete(runningTests.tests, sessionId)
		ui.printDbg("Cancelled test session: %s", sessionId)
	} else {
		ui.printDbg("No running test found for session: %s", sessionId)
	}
}

func executeCommand(serverURL string, sessionId string, cmd TestCommand) {
	ui.printMsg("Executing command: mode=%s, protocol=%s, testType=%s", cmd.Mode, cmd.Protocol, cmd.TestType)

	// Create cancel channel and register it
	cancelChan := make(chan struct{})
	runningTests.Lock()
	runningTests.tests[sessionId] = cancelChan
	runningTests.Unlock()
	
	// Update status to running
	updateSessionStatus(serverURL, sessionId, "Running", "")

	// Execute the test based on mode
	// Note: Each mode function is responsible for cleaning up the runningTests map
	if cmd.Mode == "server" {
		executeServerMode(serverURL, sessionId, cmd, cancelChan)
	} else if cmd.Mode == "client" {
		executeClientMode(serverURL, sessionId, cmd, cancelChan)
	} else if cmd.Mode == "external" {
		executeExternalMode(serverURL, sessionId, cmd, cancelChan)
	} else {
		updateSessionStatus(serverURL, sessionId, "Failed", "Invalid mode: "+cmd.Mode)
		// Clean up for invalid mode
		runningTests.Lock()
		delete(runningTests.tests, sessionId)
		runningTests.Unlock()
	}
}

func executeServerMode(serverURL string, sessionId string, cmd TestCommand, cancelChan chan struct{}) {
	// Acquire server test mutex to prevent overlapping server tests on the same port
	// This is critical when multiple agents run on the same machine
	serverTestMutex.Lock()
	defer func() {
		// Give OS extra time to fully release the port after cleanup
		time.Sleep(200 * time.Millisecond)
		serverTestMutex.Unlock()
	}()
	
	// Start ethr server
	ui.printMsg("Starting server on port %d (server mode runs indefinitely)", cmd.Port)
	
	// Set global port
	gEthrPort = uint16(cmd.Port)
	gEthrPortStr = fmt.Sprintf("%d", cmd.Port)
	
	// Send initial status
	sendResult(serverURL, sessionId, TestResult{
		Timestamp: time.Now(),
		Source:    "server",
		Type:      "status",
		Protocol:  cmd.Protocol,
		Metadata:  map[string]interface{}{"status": "starting", "port": cmd.Port},
	}, false)
	
	// Set up callback to receive stats from ethr's stats system
	var testParamsSent = make(map[string]bool) // Track if we've sent params for this remote addr
	var intervalCounters = make(map[string]int) // Track interval counter per remote addr
	var lastSessionID = make(map[string]string) // Track session ID for deterministic new test detection
	
	hubStatsCallback = func(remoteAddr string, proto EthrProtocol, bw, cps, pps, latency uint64, test *ethrTest) {
		newTestDetected := false
		
		if test != nil {
			currentSessionID := test.sessionID
			hasControlChannel := test.ctrlConn != nil || currentSessionID != ""
			
			// DETERMINISTIC: Use sessionID if control channel exists
			if hasControlChannel {
				prevSessionID := lastSessionID[remoteAddr]
				if prevSessionID != "" && prevSessionID != currentSessionID {
					newTestDetected = true
					ui.printDbg("New test session detected for %s (sessionID changed: %s -> %s)", 
						remoteAddr, prevSessionID, currentSessionID)
				}
				lastSessionID[remoteAddr] = currentSessionID
			} else {
				// HEURISTICS: Fall back to multiple detection methods for -ncc mode
				// 1. Test type or protocol changed (different test started)
				// 2. Test start time changed (same test type restarted)
				
				currentStartTime := test.startTime
				prevSessionID := lastSessionID[remoteAddr]
				
				// Check if test pointer changed
				if prevSessionID != "" && lastSessionID[remoteAddr] != "" {
					// We've seen this client before (in -ncc mode)
					
					// Check if test type or protocol changed
					if test.testID.Type != 0 { // Valid test type
						key := fmt.Sprintf("%s_%d_%d", remoteAddr, test.testID.Type, test.testID.Protocol)
						prevKey := lastSessionID[remoteAddr]
						if prevKey != "" && prevKey != key {
							newTestDetected = true
							ui.printDbg("New test session detected for %s (test type/protocol changed in -ncc mode)", remoteAddr)
						}
						lastSessionID[remoteAddr] = key
					}
					
					// Check if test start time changed (test restarted with same type)
					if !currentStartTime.IsZero() {
						startTimeKey := fmt.Sprintf("start_%s_%d", remoteAddr, currentStartTime.Unix())
						if lastSessionID[remoteAddr] != startTimeKey {
							newTestDetected = true
							ui.printDbg("New test session detected for %s (start time changed in -ncc mode)", remoteAddr)
						}
						lastSessionID[remoteAddr] = startTimeKey
					}
				} else {
					// First time seeing this client in -ncc mode
					lastSessionID[remoteAddr] = fmt.Sprintf("init_%s", remoteAddr)
				}
			}
			
			// Reset counters if new test detected
			if newTestDetected {
				intervalCounters[remoteAddr] = 0
				testParamsSent[remoteAddr] = false
			}
		}
		
		// Get or initialize interval counter for this client
		intervalCounters[remoteAddr]++
		interval := intervalCounters[remoteAddr]
		
		// Convert to the format expected by the hub
		bps := int64(bw * 8) // Convert bytes/sec to bits/sec
		bytes := int64(bw)   // Bytes transferred in this second
		pkts := int64(pps)
		cpsVal := int64(cps)
		
		result := TestResult{
			Timestamp:        time.Now(),
			Source:           "server",
			Type:             "interval",
			Protocol:         protoToString(proto),
			Interval:         &interval,
			BitsPerSec:       &bps,
			BytesTransferred: &bytes,
			PacketsPerSec:    &pkts,
		}
		
		// Include test parameters from client on first interval for each remote address
		if test != nil && !testParamsSent[remoteAddr] {
			testParamsSent[remoteAddr] = true
			
			// Build test parameters from clientParam received in handshake
			testTypeStr := "bandwidth"
			switch test.testID.Type {
			case Bandwidth:
				testTypeStr = "bandwidth"
			case Cps:
				testTypeStr = "cps"
			case Pps:
				testTypeStr = "pps"
			case Latency:
				testTypeStr = "latency"
			case Ping:
				testTypeStr = "ping"
			case TraceRoute:
				testTypeStr = "traceroute"
			case MyTraceRoute:
				testTypeStr = "mytraceroute"
			}
			
			bufferSize := fmt.Sprintf("%dKB", test.clientParam.BufferSize/1024)
			bandwidth := "unlimited"
			if test.clientParam.BwRate > 0 {
				bandwidth = fmt.Sprintf("%d bps", test.clientParam.BwRate)
			}
			
			result.TestParams = &TestParameters{
				TestType:    testTypeStr,
				Protocol:    protoToString(proto),
				Threads:     int(test.clientParam.NumThreads),
				BufferSize:  bufferSize,
				Duration:    int(test.clientParam.Duration.Seconds()),
				Bandwidth:   bandwidth,
				Reverse:     test.clientParam.Reverse,
				Destination: remoteAddr, // Client's IP from server's perspective
				ClientName:  remoteAddr, // Use client IP as name from server perspective
			}
		}
		
		if cps > 0 {
			result.ConnectionsPerSec = &cpsVal
		}
		
		if latency > 0 {
			latencyMs := float64(latency) / 1000.0 // Convert microseconds to milliseconds
			result.LatencyMs = &latencyMs
		}
		
		sendResult(serverURL, sessionId, result, false)
	}
	
	// Start the actual ethr server in a goroutine
	// This will automatically use our callback for stats reporting
	serverParam := ethrServerParam{
		showUI:    false,
		oneClient: false,
	}
	
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runServer(serverParam)
	}()
	
	// Wait for either server completion or cancellation
	select {
	case err := <-serverDone:
		hubStatsCallback = nil
		if err != nil {
			// Server failed to start or encountered an error
			ui.printMsg("Server failed: %v", err)
			sendResult(serverURL, sessionId, TestResult{
				Timestamp: time.Now(),
				Source:    "server",
				Type:      "error",
				Protocol:  cmd.Protocol,
				Metadata:  map[string]interface{}{"error": err.Error(), "status": "failed"},
			}, true) // Mark as final
			updateSessionStatus(serverURL, sessionId, "Failed", err.Error())
			return
		}
		// Server stopped gracefully (likely cancelled)
		ui.printMsg("Server stopped")
		sendResult(serverURL, sessionId, TestResult{
			Timestamp: time.Now(),
			Source:    "server",
			Type:      "status",
			Protocol:  cmd.Protocol,
			Metadata:  map[string]interface{}{"status": "stopped"},
		}, true)
		updateSessionStatus(serverURL, sessionId, "Cancelled", "Server stopped")
		
	case <-cancelChan:
		// Test was cancelled - signal server to stop
		ui.printDbg("Cancelling server for session %s", sessionId)
		if gServerCancelChan != nil {
			close(gServerCancelChan)
		}
		
		// Wait for server to actually stop (with timeout)
		select {
		case err := <-serverDone:
			if err != nil && err.Error() != "TCP server error: accept tcp" {
				ui.printMsg("Server stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			ui.printMsg("Server stop timed out")
		}
		
		hubStatsCallback = nil
		sendResult(serverURL, sessionId, TestResult{
			Timestamp: time.Now(),
			Source:    "server",
			Type:      "status",
			Protocol:  cmd.Protocol,
			Metadata:  map[string]interface{}{"status": "cancelled"},
		}, true)
		updateSessionStatus(serverURL, sessionId, "Cancelled", "Test cancelled by user")
	}
	
	// Clean up from running tests map
	runningTests.Lock()
	delete(runningTests.tests, sessionId)
	runningTests.Unlock()
}

// Helper function to build test parameters for display
func buildTestParams(cmd TestCommand, protocol EthrProtocol, testType EthrTestType) *TestParameters {
	protoStr := "tcp"
	if protocol == UDP {
		protoStr = "udp"
	} else if protocol == ICMP {
		protoStr = "icmp"
	}
	
	testTypeStr := "bandwidth"
	switch testType {
	case Bandwidth:
		testTypeStr = "bandwidth"
	case Cps:
		testTypeStr = "cps"
	case Pps:
		testTypeStr = "pps"
	case Latency:
		testTypeStr = "latency"
	case Ping:
		testTypeStr = "ping"
	case TraceRoute:
		testTypeStr = "traceroute"
	case MyTraceRoute:
		testTypeStr = "mytraceroute"
	}
	
	bufferSize := "16KB"
	if cmd.BufferSize != "" {
		bufferSize = cmd.BufferSize
	}
	
	bandwidth := "unlimited"
	if cmd.Bandwidth != "" {
		bandwidth = cmd.Bandwidth
	}
	
	// Get client hostname for display
	clientName, _ := os.Hostname()
	
	return &TestParameters{
		TestType:    testTypeStr,
		Protocol:    protoStr,
		Threads:     cmd.Threads,
		BufferSize:  bufferSize,
		Duration:    cmd.DurationSeconds,
		Bandwidth:   bandwidth,
		Reverse:     cmd.Reverse,
		Destination: cmd.Destination,
		Port:        cmd.Port,
		Title:       cmd.Title,
		ClientName:  clientName,
	}
}

func executeClientMode(serverURL string, sessionId string, cmd TestCommand, cancelChan chan struct{}) {
	// Start ethr client
	ui.printMsg("Starting client test to %s:%d", cmd.Destination, cmd.Port)
	
	// Build test ID from command
	var protocol EthrProtocol
	switch cmd.Protocol {
	case "tcp":
		protocol = TCP
	case "udp":
		protocol = UDP
	case "icmp":
		protocol = ICMP
	default:
		protocol = TCP
	}
	
	var testType EthrTestType
	switch cmd.TestType {
	case "b":
		testType = Bandwidth
	case "c":
		testType = Cps
	case "p":
		testType = Pps
	case "l":
		testType = Latency
	default:
		testType = Bandwidth
	}
	
	testID := EthrTestID{
		Type:     testType,
		Protocol: protocol,
	}
	
	// Build client parameters
	bufferSize := uint32(16 * 1024) // Default 16KB
	if cmd.BufferSize != "" {
		bufferSize = uint32(unitToNumber(cmd.BufferSize))
		if bufferSize == 0 {
			bufferSize = 16 * 1024 // Fallback to default
		}
	}
	
	bwRate := uint64(0) // Default unlimited
	if cmd.Bandwidth != "" {
		bwRate = unitToNumber(cmd.Bandwidth)
		if bwRate > 0 {
			bwRate /= 8 // Convert bits/s to bytes/s
			ui.printMsg("Bandwidth limit: %s (%d bytes/s)", cmd.Bandwidth, bwRate)
		} else {
			ui.printMsg("Warning: Invalid bandwidth value '%s', using unlimited", cmd.Bandwidth)
		}
	}
	
	clientParam := EthrClientParam{
		NumThreads: uint32(cmd.Threads),
		BufferSize: bufferSize,
		Duration:   time.Duration(cmd.DurationSeconds) * time.Second,
		Reverse:    cmd.Reverse,
		BwRate:     bwRate,
	}
	
	// Build test parameters for display (before goroutine so we can use it in results)
	testParams := buildTestParams(cmd, protocol, testType)
	
	// Create server address
	server := fmt.Sprintf("%s:%d", cmd.Destination, cmd.Port)
	
	// Run client test in a goroutine and capture stats
	go func() {
		var test *ethrTest
		var testStarted bool
		defer func() {
			// Always send summary and cleanup when test exits (normal or interrupted)
			if test != nil && testStarted {
				totalBw := atomic.LoadUint64(&test.testResult.totalBw)
				totalPps := atomic.LoadUint64(&test.testResult.totalPps)
				duration := time.Since(test.startTime).Seconds()
				
				if duration > 0 {
					avgBps := int64(float64(totalBw*8) / duration)
					
					sendResult(serverURL, sessionId, TestResult{
						Timestamp:  time.Now(),
						Source:     "client",
						Type:       "summary",
						Protocol:   cmd.Protocol,
						BitsPerSec: &avgBps,
						Metadata: map[string]interface{}{
							"totalBytes":   totalBw,
							"totalPackets": totalPps,
							"duration":     duration,
						},
						TestParams: testParams,
					}, true)
				}
				deleteTest(test)
			}
			hubStatsCallback = nil
			ui.printDbg("Test cleanup completed for session %s", sessionId)
			
			// Remove from running tests map
			runningTests.Lock()
			delete(runningTests.tests, sessionId)
			runningTests.Unlock()
		}()
		
		// Don't call initClient() as it tries to create log files
		// We're already running in hub mode with our own logging
		
		// Get server connection details
		hostName, hostIP, port, err := getServerIPandPort(server)
		if err != nil {
			ui.printErr("Failed to parse server address: %v", err)
			sendResult(serverURL, sessionId, TestResult{
				Timestamp:  time.Now(),
				Source:     "client",
				Type:       "summary",
				Protocol:   cmd.Protocol,
				Metadata:   map[string]interface{}{"error": err.Error()},
				TestParams: testParams,
			}, true)
			return
		}
		
		ui.printMsg("Using destination: %s, ip: %s, port: %s", hostName, hostIP, port)
		
		// Create test
		test, err = newTest(hostIP, testID, clientParam)
		if err != nil {
			ui.printErr("Failed to create test: %v", err)
			sendResult(serverURL, sessionId, TestResult{
				Timestamp:  time.Now(),
				Source:     "client",
				Type:       "summary",
				Protocol:   cmd.Protocol,
				TestParams: testParams,
				Metadata:  map[string]interface{}{"error": err.Error()},
			}, true)
			return
		}
		
		test.remoteAddr = server
		test.remoteIP = hostIP
		test.remotePort = port
		
		if testID.Protocol == ICMP {
			test.dialAddr = hostIP
		} else {
			test.dialAddr = fmt.Sprintf("[%s]:%s", hostIP, port)
		}
		
		// Set up stats callback to receive stats from ethr's native system
		var intervalCounter int = 1
		hubStatsCallback = func(remoteAddr string, proto EthrProtocol, bw, cps, pps, latency uint64, test *ethrTest) {
			if !test.isActive {
				return
			}
			
			bps := int64(bw * 8) // Convert bytes/sec to bits/sec
			bytesTransferred := int64(bw) // This is already per-second from printTestResult
			packetsPerSec := int64(pps)
			
			result := TestResult{
				Timestamp:        time.Now(),
				Source:           "client",
				Type:             "interval",
				Protocol:         cmd.Protocol,
				Interval:         &intervalCounter,
				BitsPerSec:       &bps,
				BytesTransferred: &bytesTransferred,
				PacketsPerSec:    &packetsPerSec,
			}
			
			// Include test parameters in the first interval result
			if intervalCounter == 1 {
				result.TestParams = testParams
			}
			
			if testType == Latency && latency > 0 {
				latencyMs := float64(latency) / 1000.0 // Convert microseconds to milliseconds
				result.LatencyMs = &latencyMs
			}
			
			sendResult(serverURL, sessionId, result, false)
			intervalCounter++
		}
		
		// Mark test as started (for defer cleanup and summary)
		testStarted = true
		
		// Run the test in a goroutine so we can monitor for cancellation
		testDone := make(chan struct{})
		go func() {
			runTest(test)
			close(testDone)
		}()
		
		// Wait for either test completion or cancellation
		select {
		case <-testDone:
			// Test completed normally
			ui.printMsg("Client test completed for session %s", sessionId)
		case <-cancelChan:
			// Test was cancelled - stop it
			ui.printDbg("Cancelling client test for session %s", sessionId)
			test.isActive = false
			// Close all connections to force the test to stop
			test.connListDo(func(ec *ethrConn) {
				if ec.conn != nil {
					ec.conn.Close()
				}
			})
			// Close control channel if it exists
			if test.ctrlConn != nil {
				test.ctrlConn.Close()
			}
			// Wait a moment for test to wind down
			select {
			case <-testDone:
			case <-time.After(2 * time.Second):
				ui.printDbg("Client test cancellation timed out")
			}
			updateSessionStatus(serverURL, sessionId, "Cancelled", "Test cancelled by user")
		}
	}()
}

func executeExternalMode(serverURL string, sessionId string, cmd TestCommand, cancelChan chan struct{}) {
	// External mode: Run ping, traceroute, or mytraceroute against any destination
	ui.printMsg("Starting external test (%s) to %s:%d", cmd.TestType, cmd.Destination, cmd.Port)
	
	// Set global flag for external mode
	gIsExternalClient = true
	
	// Build test ID from command
	var protocol EthrProtocol
	switch cmd.Protocol {
	case "tcp":
		protocol = TCP
	case "udp":
		protocol = UDP
	case "icmp":
		protocol = ICMP
	default:
		protocol = TCP
	}
	
	var testType EthrTestType
	switch cmd.TestType {
	case "pi":
		testType = Ping
	case "tr":
		testType = TraceRoute
	case "mtr":
		testType = MyTraceRoute
	default:
		ui.printErr("Invalid test type for external mode: %s (only pi, tr, mtr allowed)", cmd.TestType)
		updateSessionStatus(serverURL, sessionId, "Failed", "Invalid test type for external mode")
		return
	}
	
	testID := EthrTestID{
		Type:     testType,
		Protocol: protocol,
	}
	
	// Build client parameters
	clientParam := EthrClientParam{
		NumThreads: 1, // External tests typically use 1 thread
		Duration:   time.Duration(cmd.DurationSeconds) * time.Second,
	}
	
	// Build test parameters for display
	testParams := buildTestParams(cmd, protocol, testType)
	
	// Create server address
	server := fmt.Sprintf("%s:%d", cmd.Destination, cmd.Port)
	
	// Run external test in a goroutine
	go func() {
		var test *ethrTest
		defer func() {
			if test != nil {
				// Send summary for external tests (ping results, traceroute hops, etc.)
				sendResult(serverURL, sessionId, TestResult{
					Timestamp:  time.Now(),
					Source:     "external",
					Type:       "summary",
					Protocol:   cmd.Protocol,
					TestParams: testParams,
					Metadata: map[string]interface{}{
						"testType":    cmd.TestType,
						"destination": cmd.Destination,
						"port":        cmd.Port,
					},
				}, true)
				deleteTest(test)
			}
		}()
		
		// Get server connection details
		hostName, hostIP, port, err := getServerIPandPort(server)
		if err != nil {
			ui.printErr("Failed to parse server address: %v", err)
			sendResult(serverURL, sessionId, TestResult{
				Timestamp:  time.Now(),
				Source:     "external",
				Type:       "summary",
				Protocol:   cmd.Protocol,
				TestParams: testParams,
				Metadata:   map[string]interface{}{"error": err.Error()},
			}, true)
			return
		}
		
		ui.printMsg("Using destination: %s, ip: %s, port: %s", hostName, hostIP, port)
		
		// Create test
		test, err = newTest(hostIP, testID, clientParam)
		if err != nil {
			ui.printErr("Failed to create test: %v", err)
			sendResult(serverURL, sessionId, TestResult{
				Timestamp:  time.Now(),
				Source:     "external",
				Type:       "summary",
				Protocol:   cmd.Protocol,
				TestParams: testParams,
				Metadata:   map[string]interface{}{"error": err.Error()},
			}, true)
			return
		}
		
		test.remoteAddr = server
		test.remoteIP = hostIP
		test.remotePort = port
		
		if testID.Protocol == ICMP {
			test.dialAddr = hostIP
		} else {
			test.dialAddr = fmt.Sprintf("[%s]:%s", hostIP, port)
		}
		
		// Set up stats callback for external tests (mainly for ping latency)
		var intervalCounter int = 1
		hubStatsCallback = func(remoteAddr string, proto EthrProtocol, bw, cps, pps, latency uint64, test *ethrTest) {
			if !test.isActive {
				return
			}
			
			result := TestResult{
				Timestamp: time.Now(),
				Source:    "external",
				Type:      "interval",
				Protocol:  cmd.Protocol,
				Interval:  &intervalCounter,
			}
			
			// Include test parameters in the first interval result
			if intervalCounter == 1 {
				result.TestParams = testParams
			}
			
			// For ping tests, report latency
			if testType == Ping && latency > 0 {
				latencyMs := float64(latency) / 1000.0 // Convert microseconds to milliseconds
				result.LatencyMs = &latencyMs
			}
			
			sendResult(serverURL, sessionId, result, false)
			intervalCounter++
		}
		
		// Run the test in a goroutine so we can monitor for cancellation
		testDone := make(chan struct{})
		go func() {
			runTest(test)
			close(testDone)
		}()
		
		// Wait for either test completion or cancellation
		select {
		case <-testDone:
			// Test completed normally
			ui.printMsg("External test completed for session %s", sessionId)
		case <-cancelChan:
			// Test was cancelled - stop it
			ui.printDbg("Cancelling external test for session %s", sessionId)
			test.isActive = false
			// Close all connections to force the test to stop
			test.connListDo(func(ec *ethrConn) {
				if ec.conn != nil {
					ec.conn.Close()
				}
			})
			// Close control channel if it exists
			if test.ctrlConn != nil {
				test.ctrlConn.Close()
			}
			// Wait a moment for test to wind down
			select {
			case <-testDone:
			case <-time.After(2 * time.Second):
				ui.printDbg("External test cancellation timed out")
			}
			updateSessionStatus(serverURL, sessionId, "Cancelled", "Test cancelled by user")
		}
		
		hubStatsCallback = nil
		
		// Clean up from running tests map
		runningTests.Lock()
		delete(runningTests.tests, sessionId)
		runningTests.Unlock()
	}()
}

func sendResult(serverURL string, sessionId string, result TestResult, isFinal bool) {
	reqBody, _ := json.Marshal(ResultSubmissionRequest{
		SessionId: sessionId,
		Result:    result,
		IsFinal:   isFinal,
	})

	httpReq, err := http.NewRequest("POST", serverURL+"/api/cli/agent/result", bytes.NewBuffer(reqBody))
	if err != nil {
		ui.printErr("Failed to create result submission: %v", err)
		return
	}

	hubAuth.mu.RLock()
	httpReq.Header.Set("Authorization", "Bearer "+hubAuth.AccessToken)
	hubAuth.mu.RUnlock()
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := hubHttpClient.Do(httpReq)
	if err != nil {
		ui.printErr("Failed to submit result: %v", err)
		return
	}
	resp.Body.Close()

	if isFinal {
		ui.printMsg("Test session %s completed", sessionId)
	}
}

func updateSessionStatus(serverURL string, sessionId string, status string, errorMessage string) {
	reqBody, _ := json.Marshal(StatusUpdateRequest{
		SessionId:    sessionId,
		Status:       status,
		ErrorMessage: errorMessage,
	})

	httpReq, err := http.NewRequest("POST", serverURL+"/api/cli/agent/status", bytes.NewBuffer(reqBody))
	if err != nil {
		return
	}

	hubAuth.mu.RLock()
	httpReq.Header.Set("Authorization", "Bearer "+hubAuth.AccessToken)
	hubAuth.mu.RUnlock()
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := hubHttpClient.Do(httpReq)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func getLocalIP() string {
	// Simple implementation - could be improved
	return ""
}
