// Package protocol defines the JSON messages exchanged between the agent and
// the XMart Guard portal over the agent WebSocket.
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
