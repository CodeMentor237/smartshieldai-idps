#!/bin/bash

# Exit on error
set -e

# Output directory for binaries
OUTPUT_DIR="./build/binaries"
AGENT_SRC_PATH="./agent"
# If your agent's main package is elsewhere, e.g., ./agent/cmd/agent, adjust AGENT_SRC_PATH accordingly

echo "Creating output directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo "Building native binaries for SmartShieldAI Agent..."

# --- Linux --- #
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o "$OUTPUT_DIR/agent-linux-amd64" "$AGENT_SRC_PATH"
# Placeholder for Linux signing (e.g., GPG)
# Ensure gpg is installed and your key is available.
# Example: gpg --detach-sign --armor "$OUTPUT_DIR/agent-linux-amd64"
echo "Linux (amd64) agent built. Remember to sign it."
echo "Note: This binary will likely require root privileges or specific capabilities (e.g., CAP_NET_RAW, CAP_NET_ADMIN via setcap) to capture network traffic and access all system logs."

echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o "$OUTPUT_DIR/agent-linux-arm64" "$AGENT_SRC_PATH"
# Placeholder for Linux signing (e.g., GPG)
# Example: gpg --detach-sign --armor "$OUTPUT_DIR/agent-linux-arm64"
echo "Linux (arm64) agent built. Remember to sign it."
echo "Note: This binary will likely require root privileges or specific capabilities (e.g., CAP_NET_RAW, CAP_NET_ADMIN via setcap) to capture network traffic and access all system logs."


# --- Windows --- #
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o "$OUTPUT_DIR/agent-windows-amd64.exe" "$AGENT_SRC_PATH"
# Placeholder for Windows signing (e.g., signtool)
# Ensure signtool.exe is in your PATH and you have your .pfx certificate and password.
# Example: signtool sign /f YourCert.pfx /p YourPassword /t http://timestamp.digicert.com "$OUTPUT_DIR/agent-windows-amd64.exe"
echo "Windows (amd64) agent built. Remember to sign it."
echo "Note: This binary will likely require Administrator privileges to capture network traffic (via npcap/winpcap) and access all system logs. Consider running as a Windows Service with appropriate permissions."


# --- macOS --- #
echo "Building for macOS (amd64 - Intel)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o "$OUTPUT_DIR/agent-darwin-amd64" "$AGENT_SRC_PATH"
# Placeholder for macOS signing (codesign)
# Ensure you have a valid Apple Developer ID certificate installed in your keychain.
# Example: codesign --force --sign "Developer ID Application: Your Name (TEAMID)" --timestamp "$OUTPUT_DIR/agent-darwin-amd64"
echo "macOS (amd64) agent built. Remember to sign it."
echo "Note: This binary will likely require root privileges (e.g., run with sudo) to capture network traffic and access all system logs. Consider running as a launchd daemon with appropriate permissions."

echo "Building for macOS (arm64 - Apple Silicon)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o "$OUTPUT_DIR/agent-darwin-arm64" "$AGENT_SRC_PATH"
# Placeholder for macOS signing (codesign)
# Example: codesign --force --sign "Developer ID Application: Your Name (TEAMID)" --timestamp "$OUTPUT_DIR/agent-darwin-arm64"
echo "macOS (arm64) agent built. Remember to sign it."
echo "Note: This binary will likely require root privileges (e.g., run with sudo) to capture network traffic and access all system logs. Consider running as a launchd daemon with appropriate permissions."

echo "-----------------------------------------------------"
echo "Native binary build process complete."
echo "Binaries are located in: $OUTPUT_DIR"
echo "Remember to replace placeholder signing commands with your actual signing process!"
echo "-----------------------------------------------------"

# Make the script executable
chmod +x build-native.sh 