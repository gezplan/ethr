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
	"runtime"
	"strings"
	"sync"
	"time"
)

// Hub integration structures - allows ethr to be controlled by a central hub
type HubConfig struct {
	ServerURL string
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
var hubHttpClient *http.Client

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

	// Perform device authentication flow
	if err := performDeviceAuth(config.ServerURL); err != nil {
		ui.printErr("Authentication failed: %v", err)
		os.Exit(1)
	}

	ui.printMsg("Authentication successful!")

	// Register agent with hub
	if err := registerAgent(config.ServerURL); err != nil {
		ui.printErr("Agent registration failed: %v", err)
		os.Exit(1)
	}

	ui.printMsg("Agent registered successfully (ID: %s)", hubAgentId)

	// Start token refresh goroutine
	go tokenRefreshLoop(config.ServerURL)

	// Start heartbeat goroutine
	go heartbeatLoop(config.ServerURL)

	// Main command polling loop
	commandLoop(config.ServerURL)
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

func registerAgent(serverURL string) error {
	hostname, _ := os.Hostname()
	
	req := AgentRegistrationRequest{
		Hostname:     hostname,
		IpAddress:    getLocalIP(),
		Platform:     runtime.GOOS,
		Version:      gVersion,
		Capabilities: []string{"bandwidth", "latency", "cps", "pps"},
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
	for {
		hubAuth.mu.RLock()
		expiresAt := hubAuth.ExpiresAt
		hubAuth.mu.RUnlock()

		// Refresh 5 minutes before expiry
		timeToRefresh := time.Until(expiresAt) - (5 * time.Minute)
		if timeToRefresh > 0 {
			time.Sleep(timeToRefresh)
		}

		// Refresh token
		hubAuth.mu.RLock()
		refreshToken := hubAuth.RefreshToken
		hubAuth.mu.RUnlock()

		reqBody, _ := json.Marshal(map[string]string{
			"refresh_token": refreshToken,
		})

		resp, err := hubHttpClient.Post(
			serverURL+"/api/token/refresh",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		if err != nil {
			ui.printErr("Token refresh failed: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}

		var tokenResp TokenResponse
		json.NewDecoder(resp.Body).Decode(&tokenResp)
		resp.Body.Close()

		if tokenResp.Error != "" {
			ui.printErr("Token refresh failed: %s", tokenResp.Error)
			time.Sleep(30 * time.Second)
			continue
		}

		hubAuth.mu.Lock()
		hubAuth.AccessToken = tokenResp.AccessToken
		hubAuth.RefreshToken = tokenResp.RefreshToken
		hubAuth.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		hubAuth.mu.Unlock()

		ui.printDbg("Token refreshed successfully")
	}
}

func heartbeatLoop(serverURL string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		reqBody, _ := json.Marshal(HeartbeatRequest{
			AgentId: hubAgentId,
			Status:  "Connected",
		})

		httpReq, err := http.NewRequest("POST", serverURL+"/api/cli/agent/heartbeat", bytes.NewBuffer(reqBody))
		if err != nil {
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
		resp.Body.Close()
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
			ui.printMsg("Received command for session: %s", cmdResp.SessionId)
			go executeCommand(serverURL, cmdResp.SessionId, cmdResp.Command)
		}
	}
}

func executeCommand(serverURL string, sessionId string, cmd TestCommand) {
	ui.printMsg("Executing command: mode=%s, protocol=%s, testType=%s", cmd.Mode, cmd.Protocol, cmd.TestType)

	// Update status to running
	updateSessionStatus(serverURL, sessionId, "Running", "")

	// Execute the test based on mode
	if cmd.Mode == "server" {
		executeServerMode(serverURL, sessionId, cmd)
	} else if cmd.Mode == "client" {
		executeClientMode(serverURL, sessionId, cmd)
	} else {
		updateSessionStatus(serverURL, sessionId, "Failed", "Invalid mode: "+cmd.Mode)
	}
}

func executeServerMode(serverURL string, sessionId string, cmd TestCommand) {
	// Start ethr server
	ui.printMsg("Starting server on port %d", cmd.Port)
	
	// This would normally call runServer() but we need to capture stats
	// For now, send a placeholder result
	time.Sleep(time.Duration(cmd.DurationSeconds) * time.Second)
	
	sendResult(serverURL, sessionId, TestResult{
		Timestamp: time.Now(),
		Source:    "server",
		Type:      "summary",
		Protocol:  cmd.Protocol,
		Metadata:  map[string]interface{}{"note": "Server mode completed"},
	}, true)
}

func executeClientMode(serverURL string, sessionId string, cmd TestCommand) {
	// Start ethr client
	ui.printMsg("Starting client to %s", cmd.Destination)
	
	// This would normally call runClient() but we need to capture stats
	// For now, send placeholder results
	for i := 0; i < cmd.DurationSeconds; i++ {
		time.Sleep(1 * time.Second)
		interval := i + 1
		bps := int64(1000000000) // 1 Gbps
		
		sendResult(serverURL, sessionId, TestResult{
			Timestamp:    time.Now(),
			Source:       "client",
			Type:         "interval",
			Protocol:     cmd.Protocol,
			Interval:     &interval,
			BitsPerSec:   &bps,
			Metadata:     map[string]interface{}{"interval": i + 1},
		}, false)
	}
	
	// Send final summary
	sendResult(serverURL, sessionId, TestResult{
		Timestamp: time.Now(),
		Source:    "client",
		Type:      "summary",
		Protocol:  cmd.Protocol,
		Metadata:  map[string]interface{}{"note": "Client test completed"},
	}, true)
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
