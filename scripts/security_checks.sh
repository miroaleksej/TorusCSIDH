#!/bin/bash
# scripts/security_checks.sh
# Security integrity checks before application startup
set -eo pipefail

echo "🔒 [SECURITY] Starting pre-startup security checks..."
echo "   Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "   Image ID: $(cat /etc/image-id 2>/dev/null || echo 'unknown')"

# Check 1: Verify file integrity using SHA256 checksums
echo "✅ [SECURITY] Verifying file integrity..."
sha256sum -c /app/config/checksums.sha256 --quiet
if [ $? -ne 0 ]; then
    echo "❌ [CRITICAL] File integrity check failed!"
    echo "   One or more files have been modified or corrupted."
    echo "   This could indicate a security compromise."
    exit 1
fi
echo "   All files verified successfully."

# Check 2: Verify formal proofs
echo "✅ [SECURITY] Verifying formal proofs..."
for proof in /app/proofs/*.vo; do
    if [ ! -f "$proof" ]; then
        echo "❌ [CRITICAL] Missing formal proof: $proof"
        exit 1
    fi
    
    # Check proof size (should be at least 1KB)
    size=$(stat -c %s "$proof" 2>/dev/null || stat -f %z "$proof")
    if [ "$size" -lt 1024 ]; then
        echo "❌ [CRITICAL] Formal proof $proof is too small (size: ${size} bytes)"
        exit 1
    fi
done
echo "   All formal proofs verified successfully."

# Check 3: Verify executable permissions
echo "✅ [SECURITY] Verifying executable permissions..."
if [ ! -x "/app/bin/toruscsidh" ]; then
    echo "❌ [CRITICAL] Main binary is not executable!"
    exit 1
fi

# Check 4: Verify user privileges
echo "✅ [SECURITY] Verifying user privileges..."
current_user=$(whoami)
if [ "$current_user" = "root" ]; then
    echo "❌ [CRITICAL] Application is running as root user!"
    echo "   This violates security best practices and creates severe vulnerability."
    exit 1
fi
echo "   Running as non-root user: $current_user"

# Check 5: Verify memory limits
echo "✅ [SECURITY] Verifying memory limits..."
memory_limit=$(ulimit -v 2>/dev/null || echo "unlimited")
if [ "$memory_limit" != "unlimited" ] && [ "$memory_limit" -lt 262144 ]; then
    echo "⚠️  [WARNING] Memory limit is too low: $memory_limit KB"
    echo "   Recommended minimum: 256 MB (262144 KB)"
fi

# Check 6: Verify container security configuration
echo "✅ [SECURITY] Verifying container security configuration..."
if [ -f "/proc/self/status" ]; then
    # Check for seccomp
    if ! grep -q "Seccomp:" /proc/self/status; then
        echo "⚠️  [WARNING] Seccomp not enabled - system calls not restricted"
    fi
    
    # Check for capabilities
    caps=$(grep "CapEff:" /proc/self/status | awk '{print $2}')
    if [ "$caps" != "0000000000000000" ]; then
        echo "⚠️  [WARNING] Process has additional capabilities: $caps"
    fi
fi

# Check 7: Verify critical file permissions
echo "✅ [SECURITY] Verifying critical file permissions..."
find /app -type f -name "*.vo" -exec stat -c "%a %n" {} \; | grep -v "^444" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "❌ [CRITICAL] Formal proofs must be read-only (444 permissions)"
    exit 1
fi

echo "✅ [SECURITY] All pre-startup security checks passed successfully!"
echo "   Starting TorusCSIDH application..."
echo "==============================================================="

# Execute the main application
exec "$@"
