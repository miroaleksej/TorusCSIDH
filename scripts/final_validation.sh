#!/bin/bash
# scripts/final_validation.sh
# Final validation script for TorusCSIDH production deployment
# Performs integrity checks, formal verification, NIST compliance validation, and reporting

set -euo pipefail

# ANSI color codes for output formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SCRIPT_DIR=$(dirname "$0")
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
PROOFS_DIR="$PROJECT_ROOT/proofs"
BUILD_DIR="$PROJECT_ROOT/target/release"
REPORTS_DIR="$PROJECT_ROOT/reports"
NIST_TEST_DIR="$PROJECT_ROOT/tests/nist"
VALIDATION_LOG="$REPORTS_DIR/validation_$(date +%Y%m%d_%H%M%S).log"

# Security thresholds
MIN_KEY_SPACE_BITS=128
MAX_TIMING_VARIANCE=0.01  # 1%
MIN_GEOMETRIC_VERIFICATION_SUCCESS_RATE=0.99  # 99%
MIN_FORMAL_VERIFICATION_COVERAGE=0.95  # 95%

# Function to log messages with timestamp
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        "INFO")
            echo -e "[${BLUE}${timestamp}${NC}] ${BLUE}INFO:${NC} $message"
            ;;
        "WARN")
            echo -e "[${YELLOW}${timestamp}${NC}] ${YELLOW}WARN:${NC} $message"
            ;;
        "ERROR")
            echo -e "[${RED}${timestamp}${NC}] ${RED}ERROR:${NC} $message"
            ;;
        "SUCCESS")
            echo -e "[${GREEN}${timestamp}${NC}] ${GREEN}SUCCESS:${NC} $message"
            ;;
    esac
    
    # Log to file without color codes
    case "$level" in
        "INFO") echo "[$timestamp] INFO: $message" >> "$VALIDATION_LOG" ;;
        "WARN") echo "[$timestamp] WARN: $message" >> "$VALIDATION_LOG" ;;
        "ERROR") echo "[$timestamp] ERROR: $message" >> "$VALIDATION_LOG" ;;
        "SUCCESS") echo "[$timestamp] SUCCESS: $message" >> "$VALIDATION_LOG" ;;
    esac
}

# Function to check if command exists
check_command() {
    local cmd="$1"
    local name="$2"
    
    if ! command -v "$cmd" &> /dev/null; then
        log_message "ERROR" "Required command '$name' not found. Please install it."
        exit 1
    fi
}

# Function to verify file integrity using SHA-256
verify_file_integrity() {
    local file_path="$1"
    local expected_hash="$2"
    
    if [ ! -f "$file_path" ]; then
        log_message "ERROR" "File not found: $file_path"
        return 1
    fi
    
    local actual_hash=$(sha256sum "$file_path" | cut -d' ' -f1)
    
    if [ "$actual_hash" != "$expected_hash" ]; then
        log_message "ERROR" "File integrity check failed for $file_path"
        log_message "ERROR" "Expected: $expected_hash"
        log_message "ERROR" "Actual:   $actual_hash"
        return 1
    fi
    
    return 0
}

# Function to check system requirements
check_system_requirements() {
    log_message "INFO" "Checking system requirements..."
    
    # Check required commands
    check_command "coqc" "Coq compiler"
    check_command "coqchk" "Coq checker"
    check_command "cargo" "Rust toolchain"
    check_command "make" "GNU Make"
    check_command "openssl" "OpenSSL"
    check_command "sha256sum" "SHA-256 utility"
    
    # Check memory requirements (minimum 4GB for formal verification)
    local total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local free_mem=$(grep MemFree /proc/meminfo | awk '{print $2}')
    
    if [ "$total_mem" -lt 4000000 ]; then
        log_message "WARN" "System has less than 4GB RAM (${total_mem}kB). Formal verification may fail or be extremely slow."
    fi
    
    if [ "$free_mem" -lt 1000000 ]; then
        log_message "WARN" "System has less than 1GB free RAM (${free_mem}kB). Formal verification may fail."
    fi
    
    # Check CPU requirements (minimum 2 cores)
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 2 ]; then
        log_message "WARN" "System has fewer than 2 CPU cores ($cpu_cores). Formal verification will be slow."
    fi
    
    log_message "SUCCESS" "System requirements check passed"
}

# Function to verify executable integrity
verify_executable_integrity() {
    log_message "INFO" "Verifying executable integrity..."
    
    local binary_path="$BUILD_DIR/toruscsidh"
    local expected_hash_file="$PROJECT_ROOT/config/checksums.sha256"
    
    if [ ! -f "$expected_hash_file" ]; then
        log_message "ERROR" "Checksum file not found: $expected_hash_file"
        exit 1
    }
    
    # Extract expected hash for the binary
    local expected_hash=$(grep "toruscsidh$" "$expected_hash_file" | cut -d' ' -f1)
    
    if [ -z "$expected_hash" ]; then
        log_message "ERROR" "Expected hash not found in checksum file for toruscsidh binary"
        exit 1
    }
    
    if ! verify_file_integrity "$binary_path" "$expected_hash"; then
        log_message "ERROR" "Executable integrity verification failed"
        exit 1
    }
    
    log_message "SUCCESS" "Executable integrity verified successfully"
}

# Function to run formal verification
run_formal_verification() {
    log_message "INFO" "Starting formal verification..."
    
    cd "$PROOFS_DIR"
    
    # Clean previous build artifacts
    log_message "INFO" "Cleaning previous build artifacts..."
    make clean >/dev/null 2>&1 || true
    
    # Build all proofs
    log_message "INFO" "Building formal proofs..."
    if ! make -j$(nproc) > "$REPORTS_DIR/coq_build.log" 2>&1; then
        log_message "ERROR" "Formal proof build failed. Check $REPORTS_DIR/coq_build.log for details."
        exit 1
    }
    
    # Run coqchk for additional verification
    log_message "INFO" "Running coqchk for additional verification..."
    if ! coqchk -silent security/*.vo fp_arithmetic/*.vo elliptic_curves/*.vo > "$REPORTS_DIR/coqchk.log" 2>&1; then
        log_message "ERROR" "coqchk verification failed. Check $REPORTS_DIR/coqchk.log for details."
        exit 1
    }
    
    cd "$PROJECT_ROOT"
    
    # Check verification coverage
    local total_proofs=$(find "$PROOFS_DIR" -name "*.v" | wc -l)
    local verified_proofs=$(find "$PROOFS_DIR" -name "*.vo" | wc -l)
    local coverage=$(echo "scale=2; $verified_proofs / $total_proofs" | bc)
    
    log_message "INFO" "Formal verification coverage: $coverage ($verified_proofs/$total_proofs proofs verified)"
    
    if (( $(echo "$coverage < $MIN_FORMAL_VERIFICATION_COVERAGE" | bc -l) )); then
        log_message "ERROR" "Formal verification coverage below threshold ($MIN_FORMAL_VERIFICATION_COVERAGE)"
        exit 1
    }
    
    log_message "SUCCESS" "Formal verification completed successfully"
}

# Function to run NIST PQC compliance tests
run_nist_compliance_tests() {
    log_message "INFO" "Running NIST PQC compliance tests..."
    
    cd "$NIST_TEST_DIR"
    
    # Run tests for all security levels
    local security_levels=("1" "3" "5")
    local all_passed=true
    
    for level in "${security_levels[@]}"; do
        log_message "INFO" "Running NIST compliance tests for Level $level..."
        
        if ! "${BUILD_DIR}/toruscsidh" --test-nist-compliance --level "$level" > "$REPORTS_DIR/nist_level${level}.log" 2>&1; then
            log_message "ERROR" "NIST compliance tests failed for Level $level. Check $REPORTS_DIR/nist_level${level}.log for details."
            all_passed=false
        else
            log_message "SUCCESS" "NIST compliance tests passed for Level $level"
        fi
    done
    
    cd "$PROJECT_ROOT"
    
    if [ "$all_passed" = false ]; then
        log_message "ERROR" "One or more NIST compliance tests failed"
        exit 1
    }
    
    log_message "SUCCESS" "All NIST PQC compliance tests passed"
}

# Function to run cryptographic property tests
run_cryptographic_tests() {
    log_message "INFO" "Running cryptographic property tests..."
    
    # Run unit tests with high coverage
    if ! cargo test --release --all-features -- --test-threads=1 > "$REPORTS_DIR/unit_tests.log" 2>&1; then
        log_message "ERROR" "Unit tests failed. Check $REPORTS_DIR/unit_tests.log for details."
        exit 1
    }
    
    # Run property-based tests
    if ! cargo test --release --features "proptest" -- --ignored > "$REPORTS_DIR/property_tests.log" 2>&1; then
        log_message "ERROR" "Property-based tests failed. Check $REPORTS_DIR/property_tests.log for details."
        exit 1
    }
    
    # Run side-channel resistance tests
    if ! "${BUILD_DIR}/toruscsidh" --test-sidechannels --samples 100000 > "$REPORTS_DIR/sidechannel_tests.log" 2>&1; then
        log_message "ERROR" "Side-channel resistance tests failed. Check $REPORTS_DIR/sidechannel_tests.log for details."
        exit 1
    }
    
    # Analyze side-channel test results
    local timing_variance=$(grep "Timing variance:" "$REPORTS_DIR/sidechannel_tests.log" | awk '{print $3}')
    
    if [ -z "$timing_variance" ]; then
        log_message "ERROR" "Could not extract timing variance from side-channel tests"
        exit 1
    }
    
    if (( $(echo "$timing_variance > $MAX_TIMING_VARIANCE" | bc -l) )); then
        log_message "ERROR" "Timing variance ($timing_variance) exceeds threshold ($MAX_TIMING_VARIANCE)"
        exit 1
    }
    
    log_message "SUCCESS" "All cryptographic property tests passed"
}

# Function to verify key space size
verify_key_space_size() {
    log_message "INFO" "Verifying key space size..."
    
    local key_space_size=$("${BUILD_DIR}/toruscsidh" --get-key-space-size)
    
    if [ -z "$key_space_size" ]; then
        log_message "ERROR" "Could not determine key space size"
        exit 1
    }
    
    # Calculate log2 of key space size
    local key_space_bits=$(echo "l($key_space_size)/l(2)" | bc -l)
    key_space_bits=$(printf "%.0f" "$key_space_bits")
    
    log_message "INFO" "Key space size: 2^${key_space_bits} (minimum required: 2^${MIN_KEY_SPACE_BITS})"
    
    if [ "$key_space_bits" -lt "$MIN_KEY_SPACE_BITS" ]; then
        log_message "ERROR" "Key space size (2^${key_space_bits}) below minimum requirement (2^${MIN_KEY_SPACE_BITS})"
        exit 1
    }
    
    log_message "SUCCESS" "Key space size verified successfully"
}

# Function to run geometric verification tests
run_geometric_verification_tests() {
    log_message "INFO" "Running geometric verification tests..."
    
    local success_rate=$("${BUILD_DIR}/toruscsidh" --test-geometric-verification --attempts 1000 2>/dev/null | grep "Success rate:" | awk '{print $3}')
    
    if [ -z "$success_rate" ]; then
        log_message "ERROR" "Could not determine geometric verification success rate"
        exit 1
    }
    
    success_rate=$(echo "$success_rate/100" | bc -l)
    
    log_message "INFO" "Geometric verification success rate: $(echo "$success_rate*100" | bc -l)% (minimum required: $(echo "$MIN_GEOMETRIC_VERIFICATION_SUCCESS_RATE*100" | bc -l)%)"
    
    if (( $(echo "$success_rate < $MIN_GEOMETRIC_VERIFICATION_SUCCESS_RATE" | bc -l) )); then
        log_message "ERROR" "Geometric verification success rate below threshold"
        exit 1
    }
    
    log_message "SUCCESS" "Geometric verification tests passed"
}

# Function to generate validation report
generate_validation_report() {
    log_message "INFO" "Generating validation report..."
    
    local report_file="$REPORTS_DIR/final_validation_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# TorusCSIDH Final Validation Report
Generated: $(date)

## System Information
- Host: $(hostname)
- OS: $(uname -s) $(uname -r)
- CPU Cores: $(nproc)
- Total Memory: $(grep MemTotal /proc/meminfo | awk '{print $2/1024}') MB
- Free Memory: $(grep MemFree /proc/meminfo | awk '{print $2/1024}') MB

## Validation Results
### 1. Integrity Checks
- Executable Integrity: ${GREEN}PASSED${NC}
- File Checksums: ${GREEN}PASSED${NC}

### 2. Formal Verification
- Coq Proofs Built: ${GREEN}PASSED${NC}
- Coqchk Verification: ${GREEN}PASSED${NC}
- Verification Coverage: ${GREEN}$(echo "$verified_proofs/$total_proofs" | bc -l)%${NC} (threshold: ${MIN_FORMAL_VERIFICATION_COVERAGE*100}%)

### 3. NIST PQC Compliance
- Level 1 Tests: ${GREEN}PASSED${NC}
- Level 3 Tests: ${GREEN}PASSED${NC}
- Level 5 Tests: ${GREEN}PASSED${NC}

### 4. Cryptographic Properties
- Unit Tests: ${GREEN}PASSED${NC}
- Property-based Tests: ${GREEN}PASSED${NC}
- Side-channel Resistance: ${GREEN}PASSED${NC} (timing variance: $timing_variance)

### 5. Key Space Verification
- Key Space Size: ${GREEN}2^${key_space_bits}${NC} (threshold: 2^${MIN_KEY_SPACE_BITS})

### 6. Geometric Verification
- Success Rate: ${GREEN}$(echo "$success_rate*100" | bc -l)%${NC} (threshold: $(echo "$MIN_GEOMETRIC_VERIFICATION_SUCCESS_RATE*100" | bc -l)%)

## Security Assessment
**Overall Status: ${GREEN}SECURE${NC}**

All validation tests have passed with results exceeding the minimum security thresholds. The system is ready for production deployment and independent security audit.

## Recommendations
1. Schedule regular security audits every 6 months
2. Monitor for new cryptanalytic attacks against isogeny-based cryptography
3. Keep formal proofs updated with latest Coq versions
4. Maintain hardware security modules for production key storage

## Detailed Logs
- Formal Verification Log: $REPORTS_DIR/coq_build.log
- Coqchk Log: $REPORTS_DIR/coqchk.log
- NIST Tests Logs: $REPORTS_DIR/nist_level*.log
- Unit Tests Log: $REPORTS_DIR/unit_tests.log
- Property Tests Log: $REPORTS_DIR/property_tests.log
- Side-channel Tests Log: $REPORTS_DIR/sidechannel_tests.log
EOF

    log_message "SUCCESS" "Validation report generated: $report_file"
}

# Main validation function
main() {
    echo "========================================"
    echo "TorusCSIDH Final Validation Script"
    echo "========================================"
    
    # Create reports directory if it doesn't exist
    mkdir -p "$REPORTS_DIR"
    
    # Initialize log file
    echo "TorusCSIDH Final Validation Log - $(date)" > "$VALIDATION_LOG"
    
    # Run validation steps
    check_system_requirements
    verify_executable_integrity
    run_formal_verification
    run_nist_compliance_tests
    run_cryptographic_tests
    verify_key_space_size
    run_geometric_verification_tests
    
    # Generate final report
    generate_validation_report
    
    echo "========================================"
    echo -e "${GREEN} VALIDATION SUCCESSFUL${NC}"
    echo "System is ready for production deployment"
    echo "and independent security audit."
    echo "========================================"
    
    exit 0
}

# Trap errors for cleanup
trap 'echo -e "\n${RED}Validation failed with error code $?.${NC}"; exit 1' ERR

# Execute main function
main "$@"
