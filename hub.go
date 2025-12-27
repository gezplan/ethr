// -----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
// -----------------------------------------------------------------------------
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
	Hostname            string   `json:"hostname,omitempty"`
	IpAddress           string   `json:"ipAddress,omitempty"`
	Platform            string   `json:"platform,omitempty"`
	Version             string   `json:"version,omitempty"`
	Title               string   `json:"title,omitempty"`
	TitleIsUserSupplied bool     `json:"titleIsUserSupplied"`
	Capabilities        []string `json:"capabilities,omitempty"`
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
	Duration         string            `json:"duration"` // Duration string with format: <num>[ms|s|m|h]
	Threads          int               `json:"threads"`
	BufferSize       string            `json:"bufferSize,omitempty"`
	Bandwidth        string            `json:"bandwidth,omitempty"`
	Reverse          bool              `json:"reverse"`
	Tos              int               `json:"tos"`
	Gap              string            `json:"gap,omitempty"`              // Time interval between measurements (e.g., "1s", "100ms")
	Iterations       int               `json:"iterations,omitempty"`       // Number of iterations for latency tests
	Warmup           int               `json:"warmup,omitempty"`           // Number of warmup iterations
	ClientPort       int               `json:"clientPort,omitempty"`       // Local client port (0 = ephemeral)
	BindIp           string            `json:"bindIp,omitempty"`           // Bind to specific local IP
	NoControlChannel bool              `json:"noControlChannel,omitempty"` // Disable control channel
	AdditionalParams map[string]string `json:"additionalParams,omitempty"`
}

// parseDuration parses a duration string in ethr format: <num>[ms|s|m|h]
// Returns seconds. Defaults to seconds if no unit specified.
func parseDurationToSeconds(durationStr string) int {
	if durationStr == "" {
		return 10 // default 10 seconds
	}

	durationStr = strings.TrimSpace(durationStr)
	if durationStr == "0" {
		return 0 // run forever
	}

	// Try to parse with time.ParseDuration (supports h, m, s, ms, us, ns)
	if d, err := time.ParseDuration(durationStr); err == nil {
		return int(d.Seconds())
	}

	// Fall back: try parsing as just a number (assume seconds)
	var num int
	if _, err := fmt.Sscanf(durationStr, "%d", &num); err == nil {
		return num
	}

	return 10 // default
}

// parseDurationToTime parses a duration string and returns a time.Duration
func parseDurationToTime(durationStr string) time.Duration {
	if durationStr == "" {
		return 10 * time.Second // default
	}

	durationStr = strings.TrimSpace(durationStr)
	if durationStr == "0" {
		return 0 // run forever
	}

	// Try to parse with time.ParseDuration
	if d, err := time.ParseDuration(durationStr); err == nil {
		return d
	}

	// Fall back: try parsing as just a number (assume seconds)
	var num int
	if _, err := fmt.Sscanf(durationStr, "%d", &num); err == nil {
		return time.Duration(num) * time.Second
	}

	return 10 * time.Second // default
}

// formatBufferSize formats a buffer size in bytes to a human-readable string
func formatBufferSize(bytes uint32) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%dMB", bytes/(1024*1024))
	} else if bytes >= 1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}

type TestResult struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "client", "server", or "external"
	Type      string    `json:"type"`   // "interval", "summary", "error", "latency", "ping", "traceroute", "mytraceroute", "connection"
	Protocol  string    `json:"protocol,omitempty"`
	Interval  *int      `json:"interval,omitempty"`
	// Bandwidth test fields
	BitsPerSec       *int64 `json:"bitsPerSec,omitempty"`
	BytesTransferred *int64 `json:"bytesTransferred,omitempty"`
	PacketsPerSec    *int64 `json:"packetsPerSec,omitempty"`
	// Connection test fields
	ConnectionsPerSec *int64 `json:"connectionsPerSec,omitempty"`
	TotalConnections  *int64 `json:"totalConnections,omitempty"`
	// Latency test fields
	LatencyMs    *float64 `json:"latencyMs,omitempty"`
	LatencyAvg   *float64 `json:"latencyAvg,omitempty"`
	LatencyMin   *float64 `json:"latencyMin,omitempty"`
	LatencyMax   *float64 `json:"latencyMax,omitempty"`
	LatencyP50   *float64 `json:"latencyP50,omitempty"`
	LatencyP90   *float64 `json:"latencyP90,omitempty"`
	LatencyP95   *float64 `json:"latencyP95,omitempty"`
	LatencyP99   *float64 `json:"latencyP99,omitempty"`
	LatencyP999  *float64 `json:"latencyP999,omitempty"`
	LatencyP9999 *float64 `json:"latencyP9999,omitempty"`
	// Network quality fields
	JitterMs        *float64 `json:"jitterMs,omitempty"`
	PacketLoss      *float64 `json:"packetLoss,omitempty"`
	Retransmissions *int64   `json:"retransmissions,omitempty"`
	// Ping test fields
	PingSent        *int     `json:"pingSent,omitempty"`
	PingReceived    *int     `json:"pingReceived,omitempty"`
	PingLossPercent *float64 `json:"pingLossPercent,omitempty"`
	// Traceroute/MyTraceRoute fields
	Hops       []TracerouteHop `json:"hops,omitempty"`
	HopNumber  *int            `json:"hopNumber,omitempty"`
	HopAddress *string         `json:"hopAddress,omitempty"`
	// Connection-level statistics
	ConnectionId            *string `json:"connectionId,omitempty"`
	ConnectionBitsPerSec    *int64  `json:"connectionBitsPerSec,omitempty"`
	ConnectionPacketsPerSec *int64  `json:"connectionPacketsPerSec,omitempty"`
	// General metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// Test parameters (for display in UI)
	TestParams *TestParameters `json:"testParams,omitempty"`
}

type TracerouteHop struct {
	Hop         int      `json:"hop"`
	Address     string   `json:"address,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Sent        int      `json:"sent"`
	Received    int      `json:"received"`
	LossPercent float64  `json:"lossPercent"`
	LastMs      *float64 `json:"lastMs,omitempty"`
	AvgMs       *float64 `json:"avgMs,omitempty"`
	BestMs      *float64 `json:"bestMs,omitempty"`
	WorstMs     *float64 `json:"worstMs,omitempty"`
}

type TestParameters struct {
	TestType    string `json:"testType"`
	Protocol    string `json:"protocol"`
	Threads     int    `json:"threads"`
	BufferSize  string `json:"bufferSize"`
	Duration    int    `json:"duration"`
	Bandwidth   string `json:"bandwidth,omitempty"`
	Reverse     bool   `json:"reverse"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty"`
	Title       string `json:"title,omitempty"`
	ClientName  string `json:"clientName,omitempty"`
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
	AgentId           string   `json:"agentId"`
	Status            string   `json:"status"`
	RunningSessionIds []string `json:"runningSessionIds,omitempty"` // Sessions the agent is actively running
}

var hubAuth *HubAuth
var hubAgentId string
var hubAgentTitle string
var hubAgentTitleUserSupplied bool
var hubHttpClient *http.Client

// Track running tests for stopping
var runningTests = struct {
	sync.RWMutex
	tests map[string]chan struct{} // sessionId -> stop channel
}{tests: make(map[string]chan struct{})}

// Track whether a session should be completed gracefully (vs stopped)
var gracefulCompletions sync.Map // sessionId -> bool

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
				_ = os.Remove(lockPath)
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
		_ = os.Remove(lockPath)
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
	_, loadedRefreshToken, expiresAt, err := loadTokens(config.ServerURL)
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
			// Access token looks valid, but validate refresh token to catch server restarts
			ui.printDbg("Validating refresh token before using cached credentials...")
			tokenResp, err := tryRefreshToken(config.ServerURL, loadedRefreshToken)
			if err == nil {
				// Refresh token is valid, use the new tokens
				ui.printDbg("Refresh token validated successfully")
				hubAuth.AccessToken = tokenResp.AccessToken
				hubAuth.RefreshToken = tokenResp.RefreshToken
				hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				_ = saveTokens(config.ServerURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
			} else {
				// Refresh token is invalid (server may have restarted)
				ui.printMsg("Saved refresh token is invalid: %v", err)
				ui.printMsg("Clearing saved credentials and starting new authentication...")
				clearTokens(config.ServerURL)
				hubAuth = &HubAuth{}
				// Will fall through to device auth below
			}
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
				_ = saveTokens(config.ServerURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
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
		_ = saveTokens(config.ServerURL, hubAuth.AccessToken, hubAuth.RefreshToken, 3600)
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
					_ = saveTokens(config.ServerURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)

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
					_ = saveTokens(config.ServerURL, hubAuth.AccessToken, hubAuth.RefreshToken, 3600)
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
		_ = json.NewDecoder(resp.Body).Decode(&tokenResp)
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

	// Determine if this is initial registration or re-registration
	// If hubAgentTitle is already set, we're re-registering
	isReRegistration := hubAgentTitle != ""

	var titleIsUserSupplied bool
	if isReRegistration {
		// On re-registration, preserve the original title and user-supplied status
		title = hubAgentTitle
		titleIsUserSupplied = hubAgentTitleUserSupplied
	} else {
		// Initial registration - check if user supplied a title
		titleIsUserSupplied = title != ""
		if title == "" {
			title = generateFriendlyTitle()
		}

		// Store title and user-supplied status globally for re-registration
		hubAgentTitle = title
		hubAgentTitleUserSupplied = titleIsUserSupplied
	}

	req := AgentRegistrationRequest{
		Hostname:            hostname,
		IpAddress:           getLocalIP(),
		Platform:            runtime.GOOS,
		Version:             gVersion,
		Title:               title,
		TitleIsUserSupplied: titleIsUserSupplied,
		Capabilities:        []string{"bandwidth", "latency", "cps", "pps"},
	}

	// Print session title in a box (only on initial registration)
	if !isReRegistration {
		ui.printMsg("╔═══════════════════════════════════════════════════════════════╗")
		ui.printMsg("║  Session Title: %-46s║", title)
		ui.printMsg("╚═══════════════════════════════════════════════════════════════╝")
		if !titleIsUserSupplied {
			ui.printMsg("Customize session title with -T flag")
		}
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
		_ = json.NewDecoder(resp.Body).Decode(&tokenResp)
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
		_ = saveTokens(serverURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)

		// Release lock after saving
		releaseTokenLock(lockPath)

		ui.printDbg("Token refreshed successfully")
	}
}

func heartbeatLoop(serverURL string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Collect running session IDs
		runningTests.RLock()
		runningSessionIds := make([]string, 0, len(runningTests.tests))
		for sessionId := range runningTests.tests {
			runningSessionIds = append(runningSessionIds, sessionId)
		}
		runningTests.RUnlock()

		ui.printDbg("Sending heartbeat with %d running sessions...", len(runningSessionIds))
		reqBody, _ := json.Marshal(HeartbeatRequest{
			AgentId:           hubAgentId,
			Status:            "Connected",
			RunningSessionIds: runningSessionIds,
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
				// Try re-reading tokens from disk and validate them
				ui.printDbg("Refresh failed, re-reading tokens from disk...")
				_, diskRefreshToken, _, loadErr := loadTokens(serverURL)
				if loadErr == nil && diskRefreshToken != refreshToken {
					// Different token on disk - another process refreshed, try those
					ui.printDbg("Found different tokens on disk, validating...")
					tokenResp, err = tryRefreshToken(serverURL, diskRefreshToken)
					if err == nil {
						// Disk tokens are valid, use the refreshed ones
						hubAuth.mu.Lock()
						hubAuth.AccessToken = tokenResp.AccessToken
						hubAuth.RefreshToken = tokenResp.RefreshToken
						hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
						hubAuth.mu.Unlock()
						_ = saveTokens(serverURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
						ui.printDbg("Disk tokens validated and refreshed successfully")
						continue
					}
					// Disk tokens also invalid, fall through to re-auth
					ui.printDbg("Disk tokens also invalid")
				} else if loadErr == nil {
					// Same token on disk - tokens are truly invalid
					ui.printDbg("Same tokens on disk, need re-authentication")
				}

				// Refresh token is invalid (server restarted or token expired)
				// Clear tokens and re-authenticate
				ui.printMsg("Refresh token invalid, re-authenticating...")
				clearTokens(serverURL)

				if err := performDeviceAuth(serverURL); err != nil {
					ui.printErr("Re-authentication failed: %v", err)
					time.Sleep(30 * time.Second)
					continue
				}

				_ = saveTokens(serverURL, hubAuth.AccessToken, hubAuth.RefreshToken, 3600)
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

			_ = saveTokens(serverURL, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
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
		_ = json.NewDecoder(resp.Body).Decode(&cmdResp)
		resp.Body.Close()

		if cmdResp.HasCommand {
			// Check if this is a stop command
			if cmdResp.Command.Mode == "stop" {
				ui.printDbg("Received stop command for session: %s", cmdResp.SessionId)
				stopTest(cmdResp.SessionId, false)
			} else if cmdResp.Command.Mode == "complete" {
				ui.printDbg("Received complete command for session: %s", cmdResp.SessionId)
				stopTest(cmdResp.SessionId, true) // graceful completion
			} else {
				ui.printMsg("Received command for session: %s", cmdResp.SessionId)
				go executeCommand(serverURL, cmdResp.SessionId, cmdResp.Command)
			}
		}
	}
}

func stopTest(sessionId string, graceful bool) {
	runningTests.Lock()
	defer runningTests.Unlock()

	// Debug: print all running tests
	ui.printDbg("Looking for session %s to %s. Currently running tests:", sessionId, map[bool]string{true: "complete", false: "stop"}[graceful])
	for id := range runningTests.tests {
		ui.printDbg("  - %s", id)
	}

	if stopChan, exists := runningTests.tests[sessionId]; exists {
		// Store graceful flag for the session before closing channel
		gracefulCompletions.Store(sessionId, graceful)
		close(stopChan)
		delete(runningTests.tests, sessionId)
		if graceful {
			ui.printDbg("Gracefully completing test session: %s", sessionId)
		} else {
			ui.printDbg("Stopped test session: %s", sessionId)
		}
	} else {
		ui.printDbg("No running test found for session: %s", sessionId)
	}
}

func executeCommand(serverURL string, sessionId string, cmd TestCommand) {
	ui.printMsg("Executing command: mode=%s, protocol=%s, testType=%s", cmd.Mode, cmd.Protocol, cmd.TestType)

	// Create stop channel and register it
	stopChan := make(chan struct{})
	runningTests.Lock()
	runningTests.tests[sessionId] = stopChan
	runningTests.Unlock()

	// Update status to running
	updateSessionStatus(serverURL, sessionId, "Running", "")

	// Execute the test based on mode
	// Note: Each mode function is responsible for cleaning up the runningTests map
	if cmd.Mode == "server" {
		executeServerMode(serverURL, sessionId, cmd, stopChan)
	} else if cmd.Mode == "client" {
		executeClientMode(serverURL, sessionId, cmd, stopChan)
	} else if cmd.Mode == "external" {
		executeExternalMode(serverURL, sessionId, cmd, stopChan)
	} else {
		updateSessionStatus(serverURL, sessionId, "Failed", "Invalid mode: "+cmd.Mode)
		// Clean up for invalid mode
		runningTests.Lock()
		delete(runningTests.tests, sessionId)
		runningTests.Unlock()
	}
}

func executeServerMode(serverURL string, sessionId string, cmd TestCommand, stopChan chan struct{}) {
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

	// Set up callback for new client connections (control channel mode)
	// This is called by server.go when a new control channel is established
	hubNewClientCallback = func(remoteAddr string, proto EthrProtocol, testType EthrTestType, test *ethrTest) {
		// Build test type string
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

		// Build test parameters from clientParam received in handshake
		var params *TestParameters
		hasClientParams := test != nil && (test.clientParam.NumThreads > 0 || test.clientParam.BufferSize > 0 || test.clientParam.Duration > 0)

		if hasClientParams {
			bufferSize := formatBufferSize(test.clientParam.BufferSize)
			bandwidth := "unlimited"
			if test.clientParam.BwRate > 0 {
				bandwidth = fmt.Sprintf("%d bps", test.clientParam.BwRate)
			}

			params = &TestParameters{
				TestType:    testTypeStr,
				Protocol:    protoToString(proto),
				Threads:     int(test.clientParam.NumThreads),
				BufferSize:  bufferSize,
				Duration:    int(test.clientParam.Duration.Seconds()),
				Bandwidth:   bandwidth,
				Reverse:     test.clientParam.Reverse,
				Destination: remoteAddr,
				ClientName:  remoteAddr,
			}
		} else {
			// No client params from handshake - provide server-side defaults
			serverBufferSize := ""
			if testType == Pps {
				serverBufferSize = "1B"
			}

			params = &TestParameters{
				TestType:    testTypeStr,
				Protocol:    protoToString(proto),
				BufferSize:  serverBufferSize,
				ClientName:  remoteAddr,
				Destination: remoteAddr,
			}
		}

		// Send client_params result
		sendResult(serverURL, sessionId, TestResult{
			Timestamp:  time.Now(),
			Source:     remoteAddr, // Client IP address
			Type:       "client_params",
			Protocol:   protoToString(proto),
			TestParams: params,
		}, false)
	}

	// Set up callback to receive stats from ethr's stats system
	hubStatsCallback = func(remoteAddr string, proto EthrProtocol, testType EthrTestType,
		bw, cps, pps uint64, latencyStats *LatencyStats, hops []ethrHopData, test *ethrTest) {

		const notApplicable = ^uint64(0) // MaxUint64 means "not applicable"

		result := TestResult{
			Timestamp: time.Now(),
			Source:    remoteAddr, // Client IP address
			Protocol:  protoToString(proto),
			Type:      "interval",
		}

		// Populate metrics - MaxUint64 means "not applicable", other values (including 0) are valid
		if bw != notApplicable {
			bps := int64(bw * 8) // Convert bytes/sec to bits/sec
			bytes := int64(bw)
			result.BitsPerSec = &bps
			result.BytesTransferred = &bytes
		}

		if cps != notApplicable {
			cpsVal := int64(cps)
			result.ConnectionsPerSec = &cpsVal
		}

		if pps != notApplicable {
			pkts := int64(pps)
			result.PacketsPerSec = &pkts
		}

		if latencyStats != nil {
			result.Type = "latency"
			avgMs := float64(latencyStats.Avg.Microseconds()) / 1000.0
			minMs := float64(latencyStats.Min.Microseconds()) / 1000.0
			maxMs := float64(latencyStats.Max.Microseconds()) / 1000.0
			p50Ms := float64(latencyStats.P50.Microseconds()) / 1000.0
			p90Ms := float64(latencyStats.P90.Microseconds()) / 1000.0
			p95Ms := float64(latencyStats.P95.Microseconds()) / 1000.0
			p99Ms := float64(latencyStats.P99.Microseconds()) / 1000.0
			p999Ms := float64(latencyStats.P999.Microseconds()) / 1000.0
			p9999Ms := float64(latencyStats.P9999.Microseconds()) / 1000.0

			result.LatencyAvg = &avgMs
			result.LatencyMin = &minMs
			result.LatencyMax = &maxMs
			result.LatencyP50 = &p50Ms
			result.LatencyP90 = &p90Ms
			result.LatencyP95 = &p95Ms
			result.LatencyP99 = &p99Ms
			result.LatencyP999 = &p999Ms
			result.LatencyP9999 = &p9999Ms
		}

		// Send result if it has any data
		if result.BitsPerSec != nil || result.ConnectionsPerSec != nil ||
			result.PacketsPerSec != nil || result.LatencyAvg != nil {
			sendResult(serverURL, sessionId, result, false)
		}
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

	// Wait for either server completion or stopping
	select {
	case err := <-serverDone:
		hubStatsCallback = nil
		hubPingCallback = nil
		hubNewClientCallback = nil
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
		// Server stopped gracefully (likely stopped)
		ui.printMsg("Server stopped")
		sendResult(serverURL, sessionId, TestResult{
			Timestamp: time.Now(),
			Source:    "server",
			Type:      "status",
			Protocol:  cmd.Protocol,
			Metadata:  map[string]interface{}{"status": "stopped"},
		}, true)
		updateSessionStatus(serverURL, sessionId, "Stopped", "Server stopped")

	case <-stopChan:
		// Check if this is a graceful completion or stop
		graceful := false
		if val, ok := gracefulCompletions.Load(sessionId); ok {
			graceful = val.(bool)
			gracefulCompletions.Delete(sessionId) // Clean up
		}

		if graceful {
			ui.printMsg("Gracefully completing server for session %s", sessionId)
		} else {
			ui.printDbg("Stopping server for session %s", sessionId)
		}

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
		hubPingCallback = nil
		hubNewClientCallback = nil

		if graceful {
			sendResult(serverURL, sessionId, TestResult{
				Timestamp: time.Now(),
				Source:    "server",
				Type:      "status",
				Protocol:  cmd.Protocol,
				Metadata:  map[string]interface{}{"status": "completed"},
			}, true)
			updateSessionStatus(serverURL, sessionId, "Completed", "")
		} else {
			sendResult(serverURL, sessionId, TestResult{
				Timestamp: time.Now(),
				Source:    "server",
				Type:      "status",
				Protocol:  cmd.Protocol,
				Metadata:  map[string]interface{}{"status": "stopped"},
			}, true)
			updateSessionStatus(serverURL, sessionId, "Stopped", "Test stopped by user")
		}
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
		Duration:    parseDurationToSeconds(cmd.Duration),
		Bandwidth:   bandwidth,
		Reverse:     cmd.Reverse,
		Destination: cmd.Destination,
		Port:        cmd.Port,
		Title:       cmd.Title,
		ClientName:  clientName,
	}
}

func executeClientMode(serverURL string, sessionId string, cmd TestCommand, stopChan chan struct{}) {
	// Set global parameters from command
	if cmd.BindIp != "" {
		gLocalIP = cmd.BindIp
	}
	if cmd.ClientPort > 0 {
		gClientPort = uint16(cmd.ClientPort)
	}
	if cmd.Tos > 0 {
		gTOS = uint8(cmd.Tos)
	}

	// Start ethr client
	ui.printMsg("Starting client test to %s:%d", cmd.Destination, cmd.Port)

	// Build test ID from command
	var protocol EthrProtocol
	switch cmd.Protocol {
	case "tcp", "http", "https":
		protocol = TCP // HTTP/HTTPS use TCP under the hood
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
	case "pi":
		testType = Ping
	case "tr":
		testType = TraceRoute
	case "mtr":
		testType = MyTraceRoute
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

	// For Pkt/s tests, always override buffer size to 1 byte (matching CLI behavior)
	if testType == Pps {
		bufferSize = 1
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

	// Parse gap parameter (e.g., "1s", "100ms")
	gap := time.Second // Default 1s
	if cmd.Gap != "" {
		parsedGap, err := time.ParseDuration(cmd.Gap)
		if err == nil && parsedGap > 0 {
			gap = parsedGap
		} else {
			ui.printMsg("Warning: Invalid gap value '%s', using default 1s", cmd.Gap)
		}
	}

	// Get iterations (for latency tests)
	rttCount := uint32(1000) // Default 1000
	if cmd.Iterations > 0 {
		rttCount = uint32(cmd.Iterations)
	}

	// Get warmup count
	warmupCount := uint32(1) // Default 1
	if cmd.Warmup > 0 {
		warmupCount = uint32(cmd.Warmup)
	}

	clientParam := EthrClientParam{
		NumThreads:       uint32(cmd.Threads),
		BufferSize:       bufferSize,
		Duration:         parseDurationToTime(cmd.Duration),
		Reverse:          cmd.Reverse,
		BwRate:           bwRate,
		Gap:              gap,
		RttCount:         rttCount,
		WarmupCount:      warmupCount,
		ToS:              uint8(cmd.Tos),
		NoControlChannel: cmd.NoControlChannel,
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

					metadata := map[string]interface{}{
						"totalBytes":   totalBw,
						"totalPackets": totalPps,
						"duration":     duration,
					}

					// For PPS tests, include server-side packet stats if available
					if test.ctrlResults != nil {
						serverPackets := test.ctrlResults.Packets
						serverBytes := test.ctrlResults.Bandwidth
						metadata["serverPackets"] = serverPackets
						metadata["serverBytes"] = serverBytes

						// Calculate packet loss for UDP/PPS tests
						if totalPps > 0 && serverPackets < totalPps {
							lostPackets := totalPps - serverPackets
							lossPercent := float64(lostPackets) / float64(totalPps) * 100
							metadata["lostPackets"] = lostPackets
							metadata["lossPercent"] = lossPercent
						}
					}

					sendResult(serverURL, sessionId, TestResult{
						Timestamp:  time.Now(),
						Source:     "client",
						Type:       "summary",
						Protocol:   cmd.Protocol,
						BitsPerSec: &avgBps,
						Metadata:   metadata,
						TestParams: testParams,
					}, true)
				}
				deleteTest(test)
			}
			hubStatsCallback = nil
			hubPingCallback = nil
			hubActiveTest = nil
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
			updateSessionStatus(serverURL, sessionId, "Failed", err.Error())
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
				Metadata:   map[string]interface{}{"error": err.Error()},
			}, true)
			updateSessionStatus(serverURL, sessionId, "Failed", err.Error())
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

		// Set hubActiveTest for direct callback access in emitLatencyResults
		hubActiveTest = test

		// Set up stats callback to receive stats from ethr's native system
		var intervalCounter int = 1
		hubStatsCallback = func(remoteAddr string, proto EthrProtocol, testType EthrTestType,
			bw, cps, pps uint64, latencyStats *LatencyStats, hops []ethrHopData, test *ethrTest) {
			if !test.isActive {
				return
			}

			result := TestResult{
				Timestamp: time.Now(),
				Source:    "client",
				Protocol:  cmd.Protocol,
			}

			// Handle different test types
			switch testType {
			case Bandwidth:
				bps := int64(bw * 8)          // Convert bytes/sec to bits/sec
				bytesTransferred := int64(bw) // This is already per-second from printTestResult
				packetsPerSec := int64(pps)
				currentInterval := intervalCounter // Capture value before incrementing

				result.Type = "interval"
				result.Interval = &currentInterval
				result.BitsPerSec = &bps
				result.BytesTransferred = &bytesTransferred
				result.PacketsPerSec = &packetsPerSec

				// Include test parameters in the first interval result
				if intervalCounter == 1 {
					result.TestParams = testParams
				}
				intervalCounter++

			case Cps:
				cpsVal := int64(cps)
				currentInterval := intervalCounter // Capture value before incrementing
				result.Type = "interval"
				result.Interval = &currentInterval
				result.ConnectionsPerSec = &cpsVal

				if intervalCounter == 1 {
					result.TestParams = testParams
				}
				intervalCounter++

			case Pps:
				bps := int64(bw * 8)
				packetsPerSec := int64(pps)
				currentInterval := intervalCounter // Capture value before incrementing
				result.Type = "interval"
				result.Interval = &currentInterval
				result.BitsPerSec = &bps
				result.PacketsPerSec = &packetsPerSec

				if intervalCounter == 1 {
					result.TestParams = testParams
				}
				intervalCounter++

			case Latency:
				if latencyStats != nil {
					avgMs := float64(latencyStats.Avg.Microseconds()) / 1000.0
					minMs := float64(latencyStats.Min.Microseconds()) / 1000.0
					maxMs := float64(latencyStats.Max.Microseconds()) / 1000.0
					p50Ms := float64(latencyStats.P50.Microseconds()) / 1000.0
					p90Ms := float64(latencyStats.P90.Microseconds()) / 1000.0
					p95Ms := float64(latencyStats.P95.Microseconds()) / 1000.0
					p99Ms := float64(latencyStats.P99.Microseconds()) / 1000.0
					p999Ms := float64(latencyStats.P999.Microseconds()) / 1000.0
					p9999Ms := float64(latencyStats.P9999.Microseconds()) / 1000.0

					result.Type = "latency"
					result.LatencyAvg = &avgMs
					result.LatencyMin = &minMs
					result.LatencyMax = &maxMs
					result.LatencyP50 = &p50Ms
					result.LatencyP90 = &p90Ms
					result.LatencyP95 = &p95Ms
					result.LatencyP99 = &p99Ms
					result.LatencyP999 = &p999Ms
					result.LatencyP9999 = &p9999Ms
					result.TestParams = testParams
				}

			case MyTraceRoute:
				if len(hops) > 0 {
					result.Type = "mytraceroute"
					result.Hops = make([]TracerouteHop, 0, len(hops))

					for i, hopData := range hops {
						if hopData.addr != "" && hopData.sent > 0 {
							hop := TracerouteHop{
								Hop:      i + 1,
								Address:  hopData.addr,
								Hostname: hopData.name,
								Sent:     int(hopData.sent),
								Received: int(hopData.rcvd),
							}

							if hopData.sent > 0 {
								hop.LossPercent = float64(hopData.lost) / float64(hopData.sent) * 100
							}

							if hopData.rcvd > 0 {
								lastMs := float64(hopData.last.Microseconds()) / 1000.0
								avgMs := float64(hopData.total.Nanoseconds()/int64(hopData.rcvd)) / 1000000.0
								bestMs := float64(hopData.best.Microseconds()) / 1000.0
								worstMs := float64(hopData.worst.Microseconds()) / 1000.0

								hop.LastMs = &lastMs
								hop.AvgMs = &avgMs
								hop.BestMs = &bestMs
								hop.WorstMs = &worstMs
							}

							result.Hops = append(result.Hops, hop)
						}
					}
					result.TestParams = testParams
				}

			case Ping:
				// Ping results can come as latency stats (TCP ping) or hop data (ICMP ping)
				if latencyStats != nil {
					avgMs := float64(latencyStats.Avg.Microseconds()) / 1000.0
					minMs := float64(latencyStats.Min.Microseconds()) / 1000.0
					maxMs := float64(latencyStats.Max.Microseconds()) / 1000.0
					p50Ms := float64(latencyStats.P50.Microseconds()) / 1000.0
					p90Ms := float64(latencyStats.P90.Microseconds()) / 1000.0
					p95Ms := float64(latencyStats.P95.Microseconds()) / 1000.0
					p99Ms := float64(latencyStats.P99.Microseconds()) / 1000.0
					p999Ms := float64(latencyStats.P999.Microseconds()) / 1000.0
					p9999Ms := float64(latencyStats.P9999.Microseconds()) / 1000.0

					result.Type = "ping"
					result.LatencyAvg = &avgMs
					result.LatencyMin = &minMs
					result.LatencyMax = &maxMs
					result.LatencyP50 = &p50Ms
					result.LatencyP90 = &p90Ms
					result.LatencyP95 = &p95Ms
					result.LatencyP99 = &p99Ms
					result.LatencyP999 = &p999Ms
					result.LatencyP9999 = &p9999Ms
					result.TestParams = testParams
				} else if len(hops) == 1 {
					// ICMP ping with hop data
					hopData := hops[0]
					result.Type = "ping"
					sent := int(hopData.sent)
					rcvd := int(hopData.rcvd)
					result.PingSent = &sent
					result.PingReceived = &rcvd

					if hopData.sent > 0 {
						lossPercent := float64(hopData.lost) / float64(hopData.sent) * 100
						result.PingLossPercent = &lossPercent
					}

					if hopData.rcvd > 0 {
						avgMs := float64(hopData.total.Nanoseconds()/int64(hopData.rcvd)) / 1000000.0
						minMs := float64(hopData.best.Microseconds()) / 1000.0
						maxMs := float64(hopData.worst.Microseconds()) / 1000.0

						result.LatencyAvg = &avgMs
						result.LatencyMin = &minMs
						result.LatencyMax = &maxMs
					}
					result.TestParams = testParams
				}
			}

			// Send result if it has meaningful data
			if result.Type != "" {
				sendResult(serverURL, sessionId, result, false)
			}
		}

		// Set up individual ping callback for client mode ping tests
		var pingSequence int = 1
		hubPingCallback = func(localAddr, remoteAddr string, proto EthrProtocol, latency time.Duration, pingErr error, test *ethrTest) {
			if !test.isActive {
				return
			}

			result := TestResult{
				Timestamp:  time.Now(),
				Source:     "client",
				Protocol:   cmd.Protocol,
				Type:       "ping_result",
				TestParams: testParams,
			}

			latencyMs := float64(latency.Microseconds()) / 1000.0
			success := pingErr == nil

			result.Metadata = map[string]interface{}{
				"sequence":   pingSequence,
				"localAddr":  localAddr,
				"remoteAddr": remoteAddr,
				"latencyMs":  latencyMs,
				"success":    success,
			}

			if pingErr != nil {
				result.Metadata["error"] = pingErr.Error()
			}

			sendResult(serverURL, sessionId, result, false)
			pingSequence++
		}

		// Mark test as started (for defer cleanup and summary)
		testStarted = true

		// Run the test in a goroutine so we can monitor for cancellation
		testDone := make(chan struct{})
		go func() {
			runTest(test)
			close(testDone)
		}()

		// Wait for either test completion or stopping
		select {
		case <-testDone:
			// Test completed normally
			ui.printMsg("Client test completed for session %s", sessionId)
		case <-stopChan:
			// Check if this is a graceful completion or stop
			graceful := false
			if val, ok := gracefulCompletions.Load(sessionId); ok {
				graceful = val.(bool)
				gracefulCompletions.Delete(sessionId) // Clean up
			}

			if graceful {
				ui.printMsg("Gracefully completing client test for session %s", sessionId)
			} else {
				ui.printDbg("Stopping client test for session %s", sessionId)
			}

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
				ui.printDbg("Client test wind-down timed out")
			}

			if graceful {
				updateSessionStatus(serverURL, sessionId, "Completed", "")
			} else {
				updateSessionStatus(serverURL, sessionId, "Stopped", "Test stopped by user")
			}
		}
	}()
}

func executeExternalMode(serverURL string, sessionId string, cmd TestCommand, stopChan chan struct{}) {
	// Set global parameters from command
	if cmd.BindIp != "" {
		gLocalIP = cmd.BindIp
	}
	if cmd.ClientPort > 0 {
		gClientPort = uint16(cmd.ClientPort)
	}
	if cmd.Tos > 0 {
		gTOS = uint8(cmd.Tos)
	}

	// External mode: Run ping, traceroute, or mytraceroute against any destination
	ui.printMsg("Starting external test (%s) to %s:%d", cmd.TestType, cmd.Destination, cmd.Port)

	// Set global flag for external mode
	gIsExternalClient = true

	// Build test ID from command
	var protocol EthrProtocol
	switch cmd.Protocol {
	case "tcp", "http", "https":
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
	case "c":
		testType = Cps
	case "pi":
		testType = Ping
	case "tr":
		testType = TraceRoute
	case "mtr":
		testType = MyTraceRoute
	default:
		ui.printErr("Invalid test type for external mode: %s (only c, pi, tr, mtr allowed)", cmd.TestType)
		updateSessionStatus(serverURL, sessionId, "Failed", "Invalid test type for external mode")
		return
	}

	testID := EthrTestID{
		Type:     testType,
		Protocol: protocol,
	}

	// Parse gap parameter
	gap := time.Second // Default 1s
	if cmd.Gap != "" {
		parsedGap, err := time.ParseDuration(cmd.Gap)
		if err == nil && parsedGap > 0 {
			gap = parsedGap
		} else {
			ui.printMsg("Warning: Invalid gap value '%s', using default 1s", cmd.Gap)
		}
	}

	// Get warmup count
	warmupCount := uint32(1) // Default 1
	if cmd.Warmup > 0 {
		warmupCount = uint32(cmd.Warmup)
	}

	// Build client parameters
	clientParam := EthrClientParam{
		NumThreads:  uint32(cmd.Threads),
		Duration:    parseDurationToTime(cmd.Duration),
		Gap:         gap,
		WarmupCount: warmupCount,
		ToS:         uint8(cmd.Tos),
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
			updateSessionStatus(serverURL, sessionId, "Failed", err.Error())
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
			updateSessionStatus(serverURL, sessionId, "Failed", err.Error())
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

		// Set hubActiveTest for direct callback access in emitLatencyResults
		hubActiveTest = test

		// Set up stats callback for external tests (ping, traceroute, mytraceroute)
		var intervalCounter int = 1
		hubStatsCallback = func(remoteAddr string, proto EthrProtocol, testTypeCallback EthrTestType,
			bw, cps, pps uint64, latencyStats *LatencyStats, hops []ethrHopData, test *ethrTest) {
			if !test.isActive {
				return
			}

			result := TestResult{
				Timestamp: time.Now(),
				Source:    "external",
				Protocol:  cmd.Protocol,
			}

			// Handle different external test types
			switch testTypeCallback {
			case Ping:
				if latencyStats != nil {
					avgMs := float64(latencyStats.Avg.Microseconds()) / 1000.0
					minMs := float64(latencyStats.Min.Microseconds()) / 1000.0
					maxMs := float64(latencyStats.Max.Microseconds()) / 1000.0
					p50Ms := float64(latencyStats.P50.Microseconds()) / 1000.0
					p90Ms := float64(latencyStats.P90.Microseconds()) / 1000.0
					p95Ms := float64(latencyStats.P95.Microseconds()) / 1000.0
					p99Ms := float64(latencyStats.P99.Microseconds()) / 1000.0
					p999Ms := float64(latencyStats.P999.Microseconds()) / 1000.0
					p9999Ms := float64(latencyStats.P9999.Microseconds()) / 1000.0

					result.Type = "ping"
					result.LatencyAvg = &avgMs
					result.LatencyMin = &minMs
					result.LatencyMax = &maxMs
					result.LatencyP50 = &p50Ms
					result.LatencyP90 = &p90Ms
					result.LatencyP95 = &p95Ms
					result.LatencyP99 = &p99Ms
					result.LatencyP999 = &p999Ms
					result.LatencyP9999 = &p9999Ms
					result.TestParams = testParams
				}

			case MyTraceRoute, TraceRoute:
				if len(hops) > 0 {
					result.Type = "mytraceroute"
					result.Hops = make([]TracerouteHop, 0, len(hops))

					for i, hopData := range hops {
						if hopData.addr != "" && hopData.sent > 0 {
							hop := TracerouteHop{
								Hop:      i + 1,
								Address:  hopData.addr,
								Hostname: hopData.name,
								Sent:     int(hopData.sent),
								Received: int(hopData.rcvd),
							}

							if hopData.sent > 0 {
								hop.LossPercent = float64(hopData.lost) / float64(hopData.sent) * 100
							}

							if hopData.rcvd > 0 {
								lastMs := float64(hopData.last.Microseconds()) / 1000.0
								avgMs := float64(hopData.total.Nanoseconds()/int64(hopData.rcvd)) / 1000000.0
								bestMs := float64(hopData.best.Microseconds()) / 1000.0
								worstMs := float64(hopData.worst.Microseconds()) / 1000.0

								hop.LastMs = &lastMs
								hop.AvgMs = &avgMs
								hop.BestMs = &bestMs
								hop.WorstMs = &worstMs
							}

							result.Hops = append(result.Hops, hop)
						}
					}
					result.TestParams = testParams
				}
			}

			// Send result if it has meaningful data
			if result.Type != "" {
				sendResult(serverURL, sessionId, result, false)
			}
			intervalCounter++
		}

		// Set up individual ping callback for external ping tests
		var pingSequence int = 1
		hubPingCallback = func(localAddr, remoteAddr string, proto EthrProtocol, latency time.Duration, pingErr error, test *ethrTest) {
			if !test.isActive {
				return
			}

			result := TestResult{
				Timestamp:  time.Now(),
				Source:     "external",
				Protocol:   cmd.Protocol,
				Type:       "ping_result",
				TestParams: testParams,
			}

			latencyMs := float64(latency.Microseconds()) / 1000.0
			success := pingErr == nil

			result.Metadata = map[string]interface{}{
				"sequence":   pingSequence,
				"localAddr":  localAddr,
				"remoteAddr": remoteAddr,
				"latencyMs":  latencyMs,
				"success":    success,
			}

			if pingErr != nil {
				result.Metadata["error"] = pingErr.Error()
			}

			sendResult(serverURL, sessionId, result, false)
			pingSequence++
		}

		// Run the test in a goroutine so we can monitor for stopping
		testDone := make(chan struct{})
		go func() {
			runTest(test)
			close(testDone)
		}()

		// Wait for either test completion or stopping
		select {
		case <-testDone:
			// Test completed normally
			ui.printMsg("External test completed for session %s", sessionId)
		case <-stopChan:
			// Check if this is a graceful completion or stop
			graceful := false
			if val, ok := gracefulCompletions.Load(sessionId); ok {
				graceful = val.(bool)
				gracefulCompletions.Delete(sessionId) // Clean up
			}

			if graceful {
				ui.printMsg("Gracefully completing external test for session %s", sessionId)
			} else {
				ui.printDbg("Stopping external test for session %s", sessionId)
			}

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
				ui.printDbg("External test wind-down timed out")
			}

			if graceful {
				updateSessionStatus(serverURL, sessionId, "Completed", "")
			} else {
				updateSessionStatus(serverURL, sessionId, "Stopped", "Test stopped by user")
			}
		}

		hubStatsCallback = nil
		hubPingCallback = nil
		hubActiveTest = nil

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

	// Debug tracing: Print what we're sending (only with -debug flag)
	if result.Type == "interval" && result.Interval != nil {
		intervalNum := *result.Interval
		var bps, bytes, pkts int64
		if result.BitsPerSec != nil {
			bps = *result.BitsPerSec
		}
		if result.BytesTransferred != nil {
			bytes = *result.BytesTransferred
		}
		if result.PacketsPerSec != nil {
			pkts = *result.PacketsPerSec
		}
		ui.printDbg("[HUB] Sending interval=%d, bps=%d, bytes=%d, pps=%d, source=%s",
			intervalNum, bps, bytes, pkts, result.Source)
	}

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
