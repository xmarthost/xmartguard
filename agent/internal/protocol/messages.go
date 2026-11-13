// Package protocol defines the JSON messages exchanged between the agent and
// the xPGuard portal over the agent WebSocket.
package protocol

import "encoding/json"

// Message types.
const (
	TypeChallenge = "challenge" // portal -> agent
	TypeAuth      = "auth"      // agent -> portal
	TypeWelcome   = "welcome"   // portal -> agent
	TypeInventory = "inventory" // agent -> portal
	TypeMetrics   = "metrics"   // agent -> portal
	TypeCommand   = "command"   // portal -> agent
	TypeResult    = "result"    // agent -> portal
	TypeError     = "error"     // portal -> agent
)

// Envelope is the generic frame. Only the fields relevant to Type are set.
type Envelope struct {
	Type      string          `json:"type"`
	Nonce     string          `json:"nonce,omitempty"`
	ServerID  string          `json:"server_id,omitempty"`
	Signature string          `json:"signature,omitempty"`
	Version   string          `json:"version,omitempty"`
	Protocol  int             `json:"protocol,omitempty"`
	ID        string          `json:"id,omitempty"`
	Action    string          `json:"action,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	OK        *bool           `json:"ok,omitempty"`
	Data      any             `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Config    *AgentConfig    `json:"config,omitempty"`
}

// AgentConfig is pushed by the portal on welcome.
type AgentConfig struct {
	MetricsInterval int `json:"metrics_interval"` // seconds
}

// AuthPayload returns the exact bytes the agent signs to authenticate a
// WebSocket session.
func AuthPayload(nonce, serverID string) []byte {
	return []byte("xg-auth-v1:" + nonce + ":" + serverID)
}

// UnenrollPayload returns the bytes signed when the agent unenrolls.
func UnenrollPayload(serverID, ts string) []byte {
	return []byte("xg-unenroll-v1:" + serverID + ":" + ts)
}

// TransferPayload is what an agent signs to move its server to the account
// of an enrollment token (tokenHash: the token's SHA-256, hex), so the
// signed request works with that token only.
func TransferPayload(serverID, tokenHash, ts string) []byte {
	return []byte("xg-transfer-v1:" + serverID + ":" + tokenHash + ":" + ts)
}

// VisitorPayload is what an agent signs for a visitor it passes on to the
// portal (header X-XPGuard-Visitor: "<ip> <ts> <server_id> <signature>").
// CaptchaLinkPayload is what a server signs in a link it sends a visitor
// to the portal's check with (t: Unix time, kind: "fw" or ""): the portal
// accepts the link for five minutes and once solved, not again (owner,
// 2026-11-13: an old reported link must expire by itself).
func CaptchaLinkPayload(serverID, ip, host, t, kind string) []byte {
	return []byte("xg-captcha-link-v1:" + serverID + ":" + ip + ":" + host + ":" + t + ":" + kind)
}

func VisitorPayload(serverID, ip, ts string) []byte {
	return []byte("xg-visitor-v1:" + serverID + ":" + ip + ":" + ts)
}
