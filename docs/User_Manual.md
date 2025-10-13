# TorusCSIDH: User Manual

## Version 1.0

**Date:** October 14, 2025

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Installation Guide](#3-installation-guide)
4. [Configuration](#4-configuration)
5. [Basic Operations](#5-basic-operations)
   - [Key Generation](#key-generation)
   - [Signing Messages](#signing-messages)
   - [Verifying Signatures](#verifying-signatures)
   - [Address Generation](#address-generation)
6. [Advanced Features](#6-advanced-features)
   - [Geometric Verification](#geometric-verification)
   - [Self-Recovery System](#self-recovery-system)
   - [Code Integrity Protection](#code-integrity-protection)
7. [Integration with Bitcoin](#7-integration-with-bitcoin)
8. [Troubleshooting](#8-troubleshooting)
9. [Security Best Practices](#9-security-best-practices)
10. [API Reference](#10-api-reference)

---

## 1. Introduction

TorusCSIDH is a post-quantum cryptographic system designed as a replacement for ECDSA in Bitcoin. It builds upon the CSIDH (Commutative Supersingular Isogeny Diffie-Hellman) protocol but introduces a critical innovation: a **geometric verification layer** that analyzes the structural properties of the isogeny graph to detect and prevent sophisticated attacks.

Unlike traditional cryptographic systems that rely solely on algebraic properties, TorusCSIDH provides dual-layer security:

1. **Algebraic Layer**: The standard CSIDH protocol with proven security against known attacks
2. **Geometric Layer**: Analysis of the structural properties of the isogeny graph to detect anomalous curves

This manual provides comprehensive instructions for using TorusCSIDH in your applications, with a focus on practical implementation and integration.

---

## 2. System Requirements

### Hardware Requirements
- CPU with AES-NI instruction set (for optimal performance)
- TPM 2.0 chip (recommended for production environments)
- Minimum 2GB RAM
- 50MB disk space

### Software Dependencies
- C++17 compatible compiler (GCC 9+, Clang 10+, MSVC 2019+)
- Required libraries:
  - Boost 1.65+ (system, graph components)
  - Eigen 3.3+
  - RELIC 0.3+
  - OpenSSL 1.1.1+
  - Libsodium 1.0.18+
  - GMP 6.2.0+
  - TSS2 (for TPM integration)

### Operating System Support
- Linux (Ubuntu 20.04+, Debian 10+)
- macOS 10.15+
- Windows 10+ (with WSL2 recommended)

---

## 3. Installation Guide

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config libssl-dev libsodium-dev libgmp-dev libboost-system-dev libboost-graph-dev libeigen3-dev

# Install RELIC (required)
git clone https://github.com/relic-toolkit/relic.git
cd relic
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_MULTI=OFF -DWITH_CUDA=OFF -DALLOC=STACK -DLANG=C -DSHLIB=ON -DSTBIN=ON -DTIMER=HREAL -DCHECK=off -DVERBS=off -DDEBUG=off -DARITH=x64-asm-25519 -DCurve=ED25519 -DMEMORY=INT -DFP_PRIME=255 ..
make
sudo make install

# Build TorusCSIDH
cd /path/to/toruscsidh
mkdir build
cd build
cmake ..
make
sudo make install
```

### macOS

```bash
# Install dependencies using Homebrew
brew install cmake pkg-config openssl libsodium gmp boost eigen

# Install RELIC (required)
git clone https://github.com/relic-toolkit/relic.git
cd relic
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_MULTI=OFF -DWITH_CUDA=OFF -DALLOC=STACK -DLANG=C -DSHLIB=ON -DSTBIN=ON -DTIMER=HREAL -DCHECK=off -DVERBS=off -DDEBUG=off -DARITH=x64-asm-25519 -DCurve=ED25519 -DMEMORY=INT -DFP_PRIME=255 ..
make
sudo make install

# Build TorusCSIDH
cd /path/to/toruscsidh
mkdir build
cd build
cmake -DOPENSSL_ROOT_DIR=$(brew --prefix openssl) ..
make
```

### Windows (using WSL2)

```bash
# In WSL2 (Ubuntu)
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config libssl-dev libsodium-dev libgmp-dev libboost-system-dev libboost-graph-dev libeigen3-dev

# Install RELIC as above for Linux

# Build TorusCSIDH
cd /mnt/c/path/to/toruscsidh
mkdir build
cd build
cmake ..
make
```

---

## 4. Configuration

TorusCSIDH can be configured through environment variables and configuration files:

### Environment Variables
- `TORUSCSIDH_SECURITY_LEVEL`: Security level (128, 192, or 256) - default: 128
- `TORUSCSIDH_STORAGE_DIR`: Directory for secure storage - default: `secure_storage`
- `TORUSCSIDH_BACKUP_DIR`: Directory for backups - default: `backup`
- `TORUSCSIDH_LOG_LEVEL`: Logging level (1-5) - default: 2

### Configuration File

Create `toruscsidh.conf` in your application directory:

```ini
# Security configuration
security_level = 128
max_anomaly_count = 5
anomaly_window_seconds = 60
block_duration_seconds = 300

# Geometric verification parameters
geometric_threshold = 0.85
max_radius = 3

# Logging configuration
log_file = toruscsidh_audit.log
log_level = 2

# TPM configuration
tpm_enabled = true
tpm_persistent_handle = 0x81000001
```

### Initialization Code

```cpp
#include "toruscsidh.h"
#include <iostream>

int main() {
    try {
        // Initialize with default security level (128-bit)
        TorusCSIDH csidh;
        
        // Or specify security level explicitly
        // TorusCSIDH csidh(SecurityLevel::LEVEL_192);
        
        std::cout << "TorusCSIDH system initialized successfully!" << std::endl;
        std::cout << "Security level: ";
        switch(csidh.get_security_level()) {
            case SecurityLevel::LEVEL_128: std::cout << "128-bit"; break;
            case SecurityLevel::LEVEL_192: std::cout << "192-bit"; break;
            case SecurityLevel::LEVEL_256: std::cout << "256-bit"; break;
        }
        std::cout << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Initialization error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## 5. Basic Operations

### Key Generation

```cpp
#include "toruscsidh.h"
#include <iostream>

int main() {
    try {
        // Create system with 128-bit security level
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        
        // Generate key pair
        csidh.generate_key_pair();
        
        std::cout << "Key pair generated successfully!" << std::endl;
        
        // Get public curve information
        std::cout << "Public curve j-invariant: " 
                  << csidh.get_public_curve().compute_j_invariant().get_str() 
                  << std::endl;
                  
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Key generation error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Signing Messages

```cpp
#include "toruscsidh.h"
#include <iostream>
#include <vector>
#include <string>

int main() {
    try {
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        csidh.generate_key_pair();
        
        // Message to sign
        std::string message = "Hello TorusCSIDH!";
        std::vector<unsigned char> message_bytes(message.begin(), message.end());
        
        // Sign the message
        auto signature = csidh.sign(message_bytes);
        
        std::cout << "Message signed successfully!" << std::endl;
        std::cout << "Signature size: " << signature.size() << " bytes" << std::endl;
        
        // Display signature in hex format
        std::cout << "Signature (hex): ";
        for (auto b : signature) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(b);
        }
        std::cout << std::dec << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Signing error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Verifying Signatures

```cpp
#include "toruscsidh.h"
#include <iostream>
#include <vector>
#include <string>

int main() {
    try {
        // Create two instances - one for signing, one for verification
        TorusCSIDH signer(SecurityLevel::LEVEL_128);
        TorusCSIDH verifier(SecurityLevel::LEVEL_128);
        
        // Generate key pair for signer
        signer.generate_key_pair();
        
        // Message to sign
        std::string message = "Hello TorusCSIDH!";
        std::vector<unsigned char> message_bytes(message.begin(), message.end());
        
        // Sign the message
        auto signature = signer.sign(message_bytes);
        
        // Verify the signature
        bool is_valid = verifier.verify(
            message_bytes,
            signature,
            signer.get_public_curve()
        );
        
        std::cout << "Signature verification: " 
                  << (is_valid ? "SUCCESS" : "FAILED") << std::endl;
        
        // Test with a modified signature to demonstrate security
        if (signature.size() > 0) {
            signature[0] ^= 0x01; // Modify one byte
            
            bool is_valid_modified = verifier.verify(
                message_bytes,
                signature,
                signer.get_public_curve()
            );
            
            std::cout << "Modified signature verification: " 
                      << (is_valid_modified ? "SUCCESS (VULNERABLE!)" : "FAILED (SECURE)") 
                      << std::endl;
        }
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Verification error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Address Generation

```cpp
#include "toruscsidh.h"
#include <iostream>

int main() {
    try {
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        csidh.generate_key_pair();
        
        // Generate Bitcoin address
        std::string address = csidh.generate_address();
        
        std::cout << "Generated Bitcoin address: " << address << std::endl;
        std::cout << "Address format: Bech32m with prefix 'tcidh'" << std::endl;
        
        // Example output: tcidh1q7m3x9v2k8r4n6p0s5t1u7w9y2a4c6e8g0j3l5n7p9r1t3v5x7z9b2d4f
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Address generation error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## 6. Advanced Features

### Geometric Verification

TorusCSIDH's key innovation is the geometric verification layer. You can directly interact with this feature:

```cpp
#include "toruscsidh.h"
#include <iostream>
#include <iomanip>

int main() {
    try {
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        csidh.generate_key_pair();
        
        // Get the public curve
        const MontgomeryCurve& public_curve = csidh.get_public_curve();
        
        // Build isogeny subgraph with radius 3
        int radius = 3;
        IsogenyGraph subgraph = csidh.build_isogeny_subgraph(public_curve, radius);
        
        // Compute geometric verification scores
        double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
        
        bool is_valid = csidh.validate_curve(
            public_curve,
            subgraph,
            cyclomatic_score,
            spectral_score,
            clustering_score,
            entropy_score,
            distance_score
        );
        
        // Display results
        std::cout << "Geometric Verification Results:" << std::endl;
        std::cout << "  Cyclomatic Number: " << std::fixed << std::setprecision(4) << cyclomatic_score << std::endl;
        std::cout << "  Spectral Gap:      " << std::fixed << std::setprecision(4) << spectral_score << std::endl;
        std::cout << "  Clustering Coeff:  " << std::fixed << std::setprecision(4) << clustering_score << std::endl;
        std::cout << "  Degree Entropy:    " << std::fixed << std::setprecision(4) << entropy_score << std::endl;
        std::cout << "  Distance to Base:  " << std::fixed << std::setprecision(4) << distance_score << std::endl;
        std::cout << "  Overall Score:     " << std::fixed << std::setprecision(4) 
                  << (0.15*cyclomatic_score + 0.30*spectral_score + 
                      0.20*clustering_score + 0.20*entropy_score + 
                      0.15*distance_score) << std::endl;
        std::cout << "  Verification:      " << (is_valid ? "PASSED" : "FAILED") << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Geometric verification error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Self-Recovery System

TorusCSIDH includes a self-recovery system that automatically restores integrity after anomalies:

```cpp
#include "toruscsidh.h"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    try {
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        
        // Check if system is ready
        std::cout << "System status: " << (csidh.is_system_ready() ? "READY" : "BLOCKED") << std::endl;
        
        // Simulate an anomaly (in real system, this would be detected automatically)
        csidh.get_code_integrity().handle_anomaly("file_modified", "toruscsidh.cpp was modified");
        csidh.get_code_integrity().handle_anomaly("file_modified", "toruscsidh.h was modified");
        csidh.get_code_integrity().handle_anomaly("file_modified", "velu_formulas.cpp was modified");
        
        // Check status again
        std::cout << "System status after anomalies: " 
                  << (csidh.is_system_ready() ? "READY" : "BLOCKED") << std::endl;
        
        // Attempt recovery
        std::cout << "Attempting system recovery..." << std::endl;
        bool recovery_success = csidh.get_code_integrity().self_recovery();
        
        std::cout << "Recovery status: " << (recovery_success ? "SUCCESS" : "FAILED") << std::endl;
        std::cout << "Final system status: " 
                  << (csidh.is_system_ready() ? "READY" : "BLOCKED") << std::endl;
        
        // If recovery failed, check logs for details
        if (!recovery_success) {
            std::cout << "Recovery failed. Check audit logs for details." << std::endl;
        }
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Self-recovery test error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Code Integrity Protection

The code integrity protection system monitors critical modules:

```cpp
#include "toruscsidh.h"
#include <iostream>
#include <fstream>

int main() {
    try {
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        auto& code_integrity = csidh.get_code_integrity();
        
        // Check system integrity
        std::cout << "Running integrity check..." << std::endl;
        bool is_intact = code_integrity.system_integrity_check();
        std::cout << "Integrity status: " << (is_intact ? "OK" : "COMPROMISED") << std::endl;
        
        // Simulate a file modification (for testing only)
        std::string test_file = "test_module.cpp";
        std::ofstream test_file_stream(test_file);
        test_file_stream << "// Modified content for testing" << std::endl;
        test_file_stream.close();
        
        // Check integrity of the modified file
        std::vector<unsigned char> module_data;
        bool loaded = code_integrity.load_module(test_file, module_data);
        bool intact = true;
        
        if (loaded) {
            intact = code_integrity.verify_module_integrity(test_file, module_data.data(), module_data.size());
        }
        
        std::cout << "Test module integrity: " << (intact ? "OK" : "COMPROMISED") << std::endl;
        
        // Clean up test file
        std::remove(test_file.c_str());
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Integrity protection test error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## 7. Integration with Bitcoin

### Bitcoin Core Configuration

To enable TorusCSIDH in Bitcoin Core:

1. Add to `bitcoin.conf`:
```
# Enable TorusCSIDH support
toruscsidh=1
toruscsidh_security=128
```

2. Restart Bitcoin Core:
```bash
bitcoind -daemon
```

### Creating a TorusCSIDH Transaction

```cpp
#include "toruscsidh.h"
#include <iostream>
#include <vector>
#include <string>

// This is a simplified example - real Bitcoin transactions are more complex
int main() {
    try {
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        csidh.generate_key_pair();
        
        // Generate address
        std::string address = csidh.generate_address();
        std::cout << "TorusCSIDH Bitcoin address: " << address << std::endl;
        
        // Create a transaction (simplified)
        std::string transaction_data = "Send 1 BTC to Bob";
        std::vector<unsigned char> tx_bytes(transaction_data.begin(), transaction_data.end());
        
        // Sign the transaction
        auto signature = csidh.sign(tx_bytes);
        
        // Prepare the witness data for Bitcoin
        // In real Bitcoin, this would be part of the witness program
        std::vector<unsigned char> witness_data;
        
        // Witness version (0x01 for TorusCSIDH)
        witness_data.push_back(0x01);
        
        // Public key (j-invariant)
        GmpRaii j_invariant = csidh.get_public_curve().compute_j_invariant();
        std::string j_str = j_invariant.get_str();
        witness_data.insert(witness_data.end(), j_str.begin(), j_str.end());
        
        // Signature
        witness_data.insert(witness_data.end(), signature.begin(), signature.end());
        
        std::cout << "Transaction ready for broadcast!" << std::endl;
        std::cout << "Witness program size: " << witness_data.size() << " bytes" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Bitcoin integration error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Verifying TorusCSIDH Transactions in Bitcoin

Bitcoin nodes verify TorusCSIDH transactions using a custom opcode:

```
# Pseudocode for Bitcoin transaction verification
def verify_toruscsidh(tx, pubkey, sig):
    # Extract components
    j_invariant = pubkey[0:64]  # j-invariant of public curve
    ephemeral_j = sig[0:32]     # j-invariant of ephemeral curve
    s = sig[32:64]              # s value
    
    # Create curves
    base_curve = get_base_curve()
    public_curve = curve_from_j(j_invariant)
    eph_curve = curve_from_j(ephemeral_j)
    
    # Verify geometric properties
    if not verify_geometric_properties(eph_curve):
        return False
    
    # Verify signature equation
    # [s]E_0 + [hash(m)]E_A = [k]E_0
    return verify_signature_equation(base_curve, public_curve, eph_curve, s, tx.hash)
```

---

## 8. Troubleshooting

### Common Issues and Solutions

#### Issue: System integrity check fails on startup
**Symptoms**: `System integrity check failed and recovery unsuccessful` error
**Solution**:
1. Check if critical files have been modified:
   ```bash
   ls -l secure_storage/*.enc
   ```
2. Attempt manual recovery:
   ```cpp
   TorusCSIDH csidh;
   csidh.get_code_integrity().self_recovery();
   ```
3. If recovery fails, reinstall the system

#### Issue: Geometric verification fails for valid curves
**Symptoms**: `Geometric validation failed for ephemeral curve` error
**Solution**:
1. Check the geometric scores to identify which criterion is failing
2. Adjust the security level if necessary:
   ```cpp
   TorusCSIDH csidh(SecurityLevel::LEVEL_192); // Try higher security level
   ```
3. Ensure the system clock is synchronized (geometric verification uses time-based parameters)

#### Issue: Performance is slower than expected
**Symptoms**: Signing/verification operations take longer than expected
**Solution**:
1. Ensure you're using the correct security level for your needs
2. Verify hardware acceleration is enabled:
   ```cpp
   // Check if RELIC is using assembly optimizations
   if (ep_curve_is_twisted()) {
       std::cout << "Using optimized curve operations" << std::endl;
   }
   ```
3. For production environments, ensure TPM is properly configured

#### Issue: Address generation produces unexpected format
**Symptoms**: Generated address doesn't match Bech32m format
**Solution**:
1. Verify the prefix is correct (`tcidh` for mainnet)
2. Check for library version mismatches
3. Ensure OpenSSL and Libsodium are up to date

### Debugging Tips

1. Enable verbose logging:
   ```cpp
   SecureAuditLogger::get_instance().set_log_level(5);
   ```
   
2. Run the self-test suite:
   ```cpp
   TorusCSIDH csidh;
   bool all_tests_passed = csidh.self_test();
   ```
   
3. Check geometric verification details:
   ```cpp
   double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
   bool is_valid = csidh.validate_curve(
       csidh.get_public_curve(),
       csidh.build_isogeny_subgraph(csidh.get_public_curve(), 3),
       cyclomatic_score,
       spectral_score,
       clustering_score,
       entropy_score,
       distance_score
   );
   ```

---

## 9. Security Best Practices

### System Deployment

1. **Always use TPM**: For production environments, ensure TPM 2.0 is configured
   ```bash
   sudo tpm2_ptool addtoken --pid=1 --sopin=123456 --userpin=123456 --label=toruscsidh
   ```

2. **Regular backups**: Schedule regular backups of secure storage
   ```cpp
   code_integrity.save_recovery_state();
   ```

3. **File permissions**: Restrict access to critical files
   ```bash
   chmod 700 secure_storage
   chmod 600 secure_storage/*.enc
   ```

### Key Management

1. **Key rotation**: Implement regular key rotation
   ```cpp
   // Rotate keys every 90 days
   if (days_since_last_rotation > 90) {
       new_csidh.generate_key_pair();
       migrate_to_new_keys();
   }
   ```

2. **Secure key storage**: Never store private keys in plaintext
   ```cpp
   // Use system keychain or hardware security module
   secure_storage.store_private_key(encrypted_private_key);
   ```

3. **Key validation**: Always validate keys before use
   ```cpp
   if (!csidh.get_public_curve().is_valid_for_csidh()) {
       throw std::runtime_error("Invalid public curve");
   }
   ```

### Operational Security

1. **Monitor anomaly count**: Set up alerts for integrity issues
   ```cpp
   if (code_integrity.get_anomaly_count() > 3) {
       send_alert("Multiple integrity anomalies detected");
   }
   ```

2. **Regular audits**: Run self-tests periodically
   ```cpp
   if (!csidh.self_test()) {
       initiate_security_audit();
   }
   ```

3. **Update criteria**: Stay current with security criteria updates
   ```cpp
   // Schedule criteria update for next maintenance window
   time_t future_time = time(nullptr) + 24 * 60 * 60;
   code_integrity.update_criteria_version(2, 1, future_time);
   ```

---

## 10. API Reference

### Main Class: `TorusCSIDH`

```cpp
class TorusCSIDH {
public:
    // Constructor with optional security level
    explicit TorusCSIDH(SecurityLevel level = SecurityLevel::LEVEL_128);
    
    // Generate a new key pair
    void generate_key_pair();
    
    // Sign a message
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    // Verify a signature
    bool verify(const std::vector<unsigned char>& message,
               const std::vector<unsigned char>& signature,
               const MontgomeryCurve& public_curve);
    
    // Generate a Bitcoin address in Bech32m format
    std::string generate_address() const;
    
    // Print system information
    void print_info() const;
    
    // Run self-tests
    bool self_test();
    
    // Get public curve
    const MontgomeryCurve& get_public_curve() const;
    
    // Get base curve
    const MontgomeryCurve& get_base_curve() const;
    
    // Get private key (exponents)
    const std::vector<short>& get_private_key() const;
    
    // Get prime numbers used in CSIDH
    const std::vector<GmpRaii>& get_primes() const;
    
    // Get RFC 6979 RNG
    const Rfc6979Rng& get_rfc6979_rng() const;
    
    // Get code integrity protection system
    CodeIntegrityProtection& get_code_integrity();
    
    // Get audit logger
    SecureAuditLogger& get_audit_logger();
    
    // Get network state
    const std::map<std::string, int>& get_network_state() const;
    
    // Check if system is ready for operation
    bool is_system_ready() const;
    
    // Get radius for geometric verification
    int get_radius() const;
    
    // Build isogeny subgraph
    IsogenyGraph build_isogeny_subgraph(const MontgomeryCurve& curve, int radius) const;
    
    // Validate curve geometrically
    bool validate_curve(const MontgomeryCurve& curve,
                       const IsogenyGraph& subgraph,
                       double& cyclomatic_score,
                       double& spectral_score,
                       double& clustering_score,
                       double& entropy_score,
                       double& distance_score) const;
    
    // Compute isogeny
    MontgomeryCurve compute_isogeny(const MontgomeryCurve& curve,
                                  const EllipticCurvePoint& kernel_point,
                                  unsigned int prime_degree) const;
    
    // Verify isogeny
    bool verify_isogeny(const MontgomeryCurve& curve1,
                       const MontgomeryCurve& curve2,
                       unsigned int prime_degree) const;
};
```

### Security Levels

```cpp
enum class SecurityLevel {
    LEVEL_128,  // 128-bit security (recommended for most applications)
    LEVEL_192,  // 192-bit security (for high-security applications)
    LEVEL_256   // 256-bit security (for maximum security)
};
```

### Geometric Verification Results

The geometric verification returns five scores, each between 0.0 and 1.0:

| Score | Description | Target Value |
|-------|-------------|--------------|
| Cyclomatic | Measures number of independent cycles | ≥ 0.15 |
| Spectral | Measures spectral gap properties | ≥ 0.30 |
| Clustering | Measures vertex clustering | ≥ 0.20 |
| Entropy | Measures degree distribution randomness | ≥ 0.20 |
| Distance | Measures distance to base curve | ≥ 0.15 |

The overall verification passes if the weighted sum ≥ 0.85.

---

## Appendix A: Complete Example

```cpp
#include "toruscsidh.h"
#include <iostream>

int main() {
    try {
        std::cout << "=== TorusCSIDH: Post-Quantum Cryptographic System for Bitcoin ===" << std::endl;
        std::cout << "Initializing system..." << std::endl;
        
        // Create system with 128-bit security level
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        
        // Run self-tests
        std::cout << "Running self-tests..." << std::endl;
        if (csidh.self_test()) {
            std::cout << "Self-tests passed successfully!" << std::endl;
        } else {
            std::cout << "WARNING: Some tests failed!" << std::endl;
        }
        
        // Display system information
        std::cout << "\nSystem Information:" << std::endl;
        csidh.print_info();
        
        // Generate key pair
        std::cout << "\nGenerating key pair..." << std::endl;
        csidh.generate_key_pair();
        
        // Generate Bitcoin address
        std::string address = csidh.generate_address();
        std::cout << "Generated Bitcoin address: " << address << std::endl;
        
        // Sign a message
        std::string message = "Example Bitcoin transaction";
        std::cout << "Signing message: " << message << std::endl;
        auto signature = csidh.sign(std::vector<unsigned char>(message.begin(), message.end()));
        
        // Verify the signature
        std::cout << "Verifying signature..." << std::endl;
        bool is_valid = csidh.verify(
            std::vector<unsigned char>(message.begin(), message.end()),
            signature,
            csidh.get_public_curve()
        );
        std::cout << "Signature verification: " << (is_valid ? "SUCCESS" : "FAILURE") << std::endl;
        
        // Check geometric properties
        std::cout << "\nChecking geometric properties..." << std::endl;
        IsogenyGraph subgraph = csidh.build_isogeny_subgraph(csidh.get_public_curve(), 3);
        
        double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
        bool geometric_valid = csidh.validate_curve(
            csidh.get_public_curve(),
            subgraph,
            cyclomatic_score,
            spectral_score,
            clustering_score,
            entropy_score,
            distance_score
        );
        
        std::cout << "Geometric verification: " << (geometric_valid ? "PASSED" : "FAILED") << std::endl;
        std::cout << "  Cyclomatic: " << cyclomatic_score << std::endl;
        std::cout << "  Spectral:   " << spectral_score << std::endl;
        std::cout << "  Clustering: " << clustering_score << std::endl;
        std::cout << "  Entropy:    " << entropy_score << std::endl;
        std::cout << "  Distance:   " << distance_score << std::endl;
        
        std::cout << "\nTorusCSIDH is ready for use in post-quantum Bitcoin applications!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## Copyright Notice

Copyright (c) 2025 TorusCSIDH Development Team

This document is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License.
