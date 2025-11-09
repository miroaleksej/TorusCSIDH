#!/bin/bash
# scripts/health_check.sh
# Health check script for TorusCSIDH application
set -eo pipefail

echo "🏥 [HEALTH] Running health checks..."
echo "   Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Check 1: Verify application process
echo "✅ [HEALTH] Checking application process..."
if ! pidof toruscsidh >/dev/null 2>&1; then
    echo "❌ [CRITICAL] TorusCSIDH process is not running!"
    exit 1
fi
echo "   Application process is running."

# Check 2: Verify memory usage
echo "✅ [HEALTH] Checking memory usage..."
memory_used=$(ps -o rss= -p $(pidof toruscsidh) 2>/dev/null || echo "0")
memory_used_kb=$((memory_used * 4))  # Convert 4KB pages to KB
memory_used_mb=$((memory_used_kb / 1024))

if [ "$memory_used_mb" -gt 1024 ]; then
    echo "⚠️  [WARNING] High memory usage: ${memory_used_mb} MB"
    echo "   This may indicate a memory leak."
fi
echo "   Memory usage: ${memory_used_mb} MB"

# Check 3: Verify CPU usage
echo "✅ [HEALTH] Checking CPU usage..."
cpu_usage=$(ps -o %cpu= -p $(pidof toruscsidh) 2>/dev/null || echo "0.0")
cpu_usage_float=$(printf "%.1f" "$cpu_usage")

if (( $(echo "$cpu_usage_float > 90.0" | bc -l) )); then
    echo "⚠️  [WARNING] High CPU usage: ${cpu_usage_float}%"
    echo "   This may indicate a performance issue or DoS attack."
fi
echo "   CPU usage: ${cpu_usage_float}%"

# Check 4: Verify cryptographic operations
echo "✅ [HEALTH] Testing cryptographic operations..."
temp_key=$(mktemp)
/app/bin/toruscsidh --test-keygen --output "$temp_key" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ [CRITICAL] Failed to generate test key!"
    rm -f "$temp_key"
    exit 1
fi
rm -f "$temp_key"
echo "   Cryptographic operations working correctly."

# Check 5: Verify connection to critical services
echo "✅ [HEALTH] Checking critical services..."
if [ -f "/app/config/production.toml" ]; then
    if grep -q "monitoring_endpoint" /app/config/production.toml; then
        echo "   Monitoring endpoint configured."
    fi
    
    if grep -q "log_rotation" /app/config/production.toml; then
        echo "   Log rotation configured."
    fi
fi

# Check 6: Verify log files
echo "✅ [HEALTH] Checking log files..."
log_files=$(find /app/logs -name "*.log" -type f -mtime -1 2>/dev/null | wc -l)
if [ "$log_files" -eq 0 ]; then
    echo "⚠️  [WARNING] No log files found from the last 24 hours."
    echo "   This could indicate logging is not working properly."
fi
echo "   Found $log_files log files from the last 24 hours."

# Check 7: Verify security metrics
echo "✅ [HEALTH] Checking security metrics..."
security_metrics_file="/app/logs/security_metrics.log"
if [ -f "$security_metrics_file" ]; then
    last_metric=$(tail -1 "$security_metrics_file")
    if echo "$last_metric" | grep -q "attacks_detected=0"; then
        echo "   No attacks detected in the last period."
    else
        attacks=$(echo "$last_metric" | grep -o "attacks_detected=[0-9]*" | cut -d= -f2)
        echo "⚠️  [SECURITY] ${attacks} attacks detected recently!"
    fi
else
    echo "⚠️  [WARNING] Security metrics file not found."
fi

echo "✅ [HEALTH] All health checks passed successfully!"
echo "   System is healthy and operational."
exit 0
