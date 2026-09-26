// Package version holds build metadata injected at link time.
package version

// Version is overridden with -ldflags "-X .../version.Version=x.y.z".
var Version = "0.6.0-dev"

// ProtocolVersion is the agent<->portal wire protocol version.
const ProtocolVersion = 1
