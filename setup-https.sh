#!/bin/bash

# Setup HTTPS for the E-Voting System
echo "Setting up HTTPS for the E-Voting System..."

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "mkcert is not installed. Please install it first:"
    echo "  Ubuntu/Debian: sudo apt install mkcert"
    echo "  macOS: brew install mkcert"
    echo "  Windows: choco install mkcert"
    exit 1
fi

# Install the local CA
echo "Installing local CA..."
mkcert -install

# Generate certificates for localhost
echo "Generating certificates for localhost..."
mkcert localhost 127.0.0.1 ::1

echo "✅ HTTPS setup complete!"
echo "📜 Certificate files created:"
echo "   - Certificate: ./localhost+2.pem"
echo "   - Private Key: ./localhost+2-key.pem"
echo ""
echo "🚀 Start the server with: npm start"
echo "🌐 Access the application at: https://localhost:3000"
echo ""
echo "⚠️  Note: The browser may show a security warning for the first visit."
echo "   This is normal for locally generated certificates." 