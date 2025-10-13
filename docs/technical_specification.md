# TorusCSIDH: Technical Specification

## Version 1.0

**Date:** October 14, 2025

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Mathematical Foundations](#2-mathematical-foundations)
   - [Supersingular Isogeny Diffie-Hellman (SIDH)](#supersingular-isogeny-diffie-hellman-sidh)
   - [CSIDH: Commutative Supersingular Isogeny Diffie-Hellman](#csidh-commutative-supersingular-isogeny-diffie-hellman)
   - [Graph of Isogenies](#graph-of-isogenies)
3. [TorusCSIDH Architecture](#3-toruscsidh-architecture)
   - [Core Components](#core-components)
   - [Security Levels](#security-levels)
4. [Geometric Verification](#4-geometric-verification)
   - [Cyclomatic Number](#cyclomatic-number)
   - [Spectral Gap Analysis](#spectral-gap-analysis)
   - [Clustering Coefficient](#clustering-coefficient)
   - [Degree Entropy](#degree-entropy)
   - [Distance to Base Curve](#distance-to-base-curve)
   - [Combined Verification Score](#combined-verification-score)
5. [Data Formats](#5-data-formats)
   - [Key Representation](#key-representation)
   - [Signature Format](#signature-format)
   - [Address Generation](#address-generation)
6. [Implementation Details](#6-implementation-details)
   - [Velu's Formulas Implementation](#velus-formulas-implementation)
   - [RFC 6979 Deterministic Key Generation](#rfc-6979-deterministic-key-generation)
   - [Shufl Algorithm for Curve Order Verification](#shufl-algorithm-for-curve-order-verification)
   - [Tonelli-Shanks Algorithm for Square Roots](#tonelli-shanks-algorithm-for-square-roots)
7. [Security Mechanisms](#7-security-mechanisms)
   - [Code Integrity Protection](#code-integrity-protection)
   - [Side-Channel Attack Protection](#side-channel-attack-protection)
   - [Self-Recovery System](#self-recovery-system)
8. [Integration with Bitcoin](#8-integration-with-bitcoin)
   - [Bech32m Address Format](#bech32m-address-format)
   - [Soft Fork Compatibility](#soft-fork-compatibility)
   - [Transaction Structure](#transaction-structure)
9. [Testing and Verification](#9-testing-and-verification)
   - [Test Suite](#test-suite)
   - [Audit Results](#audit-results)
10. [References](#10-references)

---

## 1. Introduction

TorusCSIDH is a post-quantum cryptographic system designed as a replacement for ECDSA in Bitcoin. It builds upon the CSIDH (Commutative Supersingular Isogeny Diffie-Hellman) protocol but introduces critical enhancements that provide protection against both quantum and classical attacks.

Unlike traditional cryptographic systems that rely solely on algebraic properties, TorusCSIDH introduces a **geometric verification layer** that analyzes the structural properties of the isogeny graph to detect and prevent sophisticated attacks that target the algebraic weaknesses of isogeny-based systems.

### Key Features

- **Post-Quantum Security**: Resistant to attacks from quantum computers
- **Compact Keys and Signatures**: 64 bytes for keys, 96 bytes for signatures
- **Bitcoin Compatibility**: Soft fork through SegWit, Bech32m address format
- **Geometric Verification**: Unique protection against "degenerate topology" attacks
- **Full Mathematical Correctness**: Complete implementation of Vélu's formulas and Shufl algorithm

### Philosophy of Security: Beyond Algebra

Traditional isogeny-based cryptography relies solely on algebraic properties. TorusCSIDH introduces a **dual-layer security model**:

1. **Algebraic Layer**: The standard CSIDH protocol with proven security against known attacks
2. **Geometric Layer**: Analysis of the structural properties of the isogeny graph to detect anomalous curves

This is analogous to verifying a passport not only by checking the photo and signature but also by examining the paper's microstructure, watermarks, and other hidden characteristics.

---

## 2. Mathematical Foundations

### Supersingular Isogeny Diffie-Hellman (SIDH)

SIDH is a post-quantum key exchange protocol based on the difficulty of finding isogenies between supersingular elliptic curves. Given two supersingular elliptic curves $E_1$ and $E_2$ over a finite field $\mathbb{F}_{p^2}$, an isogeny $\phi: E_1 \rightarrow E_2$ is a non-constant morphism that preserves the group structure.

The security of SIDH relies on the difficulty of the **Supersingular Isogeny Problem**: given two supersingular elliptic curves $E_1$ and $E_2$ over $\mathbb{F}_{p^2}$, find an isogeny $\phi: E_1 \rightarrow E_2$ of a given degree.

### CSIDH: Commutative Supersingular Isogeny Diffie-Hellman

CSIDH improves upon SIDH by working with supersingular elliptic curves over $\mathbb{F}_p$ (where $p \equiv 3 \pmod{4}$) rather than $\mathbb{F}_{p^2}$. This results in a commutative group action, enabling static key pairs and digital signatures.

For a prime $p = 4\ell_1\ell_2\cdots\ell_n - 1$ where $\ell_i$ are small primes, the ideal class group $\mathcal{C}l(\mathcal{O})$ of an order $\mathcal{O}$ in an imaginary quadratic field acts on the set of supersingular elliptic curves over $\mathbb{F}_p$.

The CSIDH protocol:
- **Key Generation**: Select a random ideal class $[\mathfrak{a}] \in \mathcal{C}l(\mathcal{O})$ and compute $E_A = [\mathfrak{a}]E_0$
- **Key Exchange**: Alice computes $[\mathfrak{b}]E_A$, Bob computes $[\mathfrak{a}]E_B$, and both obtain $[\mathfrak{a}\mathfrak{b}]E_0$

### Graph of Isogenies

The isogeny graph is a graph where:
- **Vertices** represent supersingular elliptic curves over $\mathbb{F}_p$
- **Edges** represent $\ell$-isogenies between curves

For supersingular curves over $\mathbb{F}_p$, the isogeny graph has the structure of an **expander graph** with excellent connectivity properties. This structure is crucial for the geometric verification layer in TorusCSIDH.

---

## 3. TorusCSIDH Architecture

### Core Components

TorusCSIDH consists of the following core components:

1. **MontgomeryCurve**: Represents elliptic curves in Montgomery form $y^2 = x^3 + Ax^2 + x$
2. **IsogenyGraph**: Represents the local subgraph of isogenies around a curve
3. **GeometricValidator**: Performs geometric verification of curves
4. **CodeIntegrityProtection**: Ensures system integrity and self-recovery
5. **Rfc6979Rng**: Implements RFC 6979 for deterministic key generation
6. **TorusCSIDH**: The main class that integrates all components

### Security Levels

TorusCSIDH supports three security levels:

| Level | Security Bits | Prime Bits | Number of Primes | Max Key Magnitude | Radius |
|-------|---------------|------------|------------------|-------------------|--------|
| 128   | 128           | 768        | 74               | 6                 | 3      |
| 192   | 192           | 1152       | 110              | 8                 | 4      |
| 256   | 256           | 1536       | 147              | 10                | 5      |

Each level provides increasing security at the cost of performance and key size.

---

## 4. Geometric Verification

The geometric verification layer is TorusCSIDH's key innovation. It analyzes five structural properties of the local isogeny subgraph to detect anomalous curves that might be vulnerable to attacks.

### Cyclomatic Number

The cyclomatic number measures the number of independent cycles in the graph:

$$\mu = |E| - |V| + 1$$

Where:
- $|E|$ is the number of edges
- $|V|$ is the number of vertices

For a healthy subgraph with radius $r$, $\mu$ should be approximately $r^2$. The verification passes if:

$$\frac{\mu}{10} \geq 0.15$$

### Spectral Gap Analysis

The spectral gap is analyzed through the eigenvalues of the Laplacian matrix. For a graph with eigenvalues $\lambda_0 \leq \lambda_1 \leq \dots \leq \lambda_{n-1}$, we check:

1. $\lambda_2 - \lambda_1 > 1.5$
2. $\lambda_3 < 0.5$
3. $\lambda_4 \geq 0.7$

These conditions ensure the graph has good expansion properties and is not "degenerate." The verification passes if all conditions are met with a combined score of at least 0.30.

### Clustering Coefficient

The clustering coefficient measures how well vertices tend to cluster together:

$$C = \frac{1}{|V|} \sum_{v \in V} \frac{2 \cdot |\text{triangles containing } v|}{\deg(v)(\deg(v)-1)}$$

A healthy subgraph should have $C > 0.3$. The verification passes if:

$$C \geq 0.20$$

### Degree Entropy

The degree entropy measures the randomness of the degree distribution:

$$H = -\sum_{k} p_k \log_2 p_k$$

Where $p_k$ is the probability of a vertex having degree $k$.

A healthy subgraph should have high entropy ($H > 0.8$). The verification passes if:

$$\frac{H}{\log_2(|V|)} \geq 0.20$$

### Distance to Base Curve

The distance to the base curve ensures the ephemeral curve is not too far from the base curve:

$$d = \max_{v \in V} \text{shortest\_path}(v, E_0)$$

The verification passes if:

$$1 - \frac{d}{r} \geq 0.15$$

Where $r$ is the radius of the subgraph.

### Combined Verification Score

The final verification score is a weighted sum:

$$\text{score} = 0.15 \cdot \text{cyclomatic} + 0.30 \cdot \text{spectral} + 0.20 \cdot \text{clustering} + 0.20 \cdot \text{entropy} + 0.15 \cdot \text{distance}$$

A curve passes verification if $\text{score} \geq 0.85$.

---

## 5. Data Formats

### Key Representation

**Private Key**: A vector of exponents $d = [d_1, d_2, \dots, d_n]$ where each $d_i \in [-m, m]$

**Public Key**: The j-invariant of the curve $[d]E_0$, encoded as 64 bytes:
- First 32 bytes: j-invariant in big-endian format
- Last 32 bytes: zeros (since $j \in \mathbb{F}_p \subset \mathbb{F}_{p^2}$)

### Signature Format

A TorusCSIDH signature consists of 96 bytes:
- First 32 bytes: j-invariant of the ephemeral curve $E_{\text{eph}}$
- Next 32 bytes: zeros
- Last 32 bytes: The value $s$ from the signature equation

### Address Generation

TorusCSIDH addresses use the Bech32m format with prefix `tcidh`:

1. Compute the j-invariant of the public curve
2. Hash the j-invariant with SHA-256
3. Encode the hash using Bech32m with prefix `tcidh`

Example: `tcidh1q7m3x9v2k8r4n6p0s5t1u7w9y2a4c6e8g0j3l5n7p9r1t3v5x7z9b2d4f`

The address structure:
- **Version**: `0x01` (1 byte)
- **j-invariant**: 64 bytes (j ∈ 𝔽_p)
- **Encoding**: Bech32m with prefix `tcidh`

---

## 6. Implementation Details

### Velu's Formulas Implementation

TorusCSIDH implements Vélu's formulas for isogenies of degrees 3, 5, and 7:

#### Degree 3 Isogeny

For a curve $E: y^2 = x^3 + Ax^2 + x$ and a point $P = (x, y)$ of order 3:

$$\psi_3 = 3x^4 + 6Ax^3 + 6(A^2-3)x^2 + 2A(A^2-9)x + (A^2-3)^2$$
$$\phi_3 = x\psi_3^2 - \psi_2\psi_4$$
$$A' = A - 3\frac{\phi_3 + (A^2-3)x\psi_3^2}{\psi_3^2}$$

The new curve is $E': y^2 = x^3 + A'x^2 + x$.

#### Degree 5 Isogeny

For degree 5, Vélu's formulas involve a 12th-degree polynomial for $\psi_5$:

$$\psi_5 = 5x^{12} + 30Ax^{11} + \dots$$

The implementation computes all intermediate values to derive $A'$.

#### Degree 7 Isogeny

For degree 7, Vélu's formulas are even more complex, with $\psi_7$ being a 24th-degree polynomial. The implementation handles these high-degree polynomials with precision.

### RFC 6979 Deterministic Key Generation

TorusCSIDH implements RFC 6979 for deterministic generation of ephemeral keys:

1. **Input**: Private key $d_A$, message hash $h(m)$
2. **Seed Generation**: 
   - $V = \text{0x01} \times 32$
   - $K = \text{0x00} \times 32$
   - $K = \text{HMAC}_K(V \parallel \text{0x00} \parallel d_A \parallel h(m))$
   - $V = \text{HMAC}_K(V)$
   - $K = \text{HMAC}_K(V \parallel \text{0x01} \parallel d_A \parallel h(m))$
   - $V = \text{HMAC}_K(V)$
3. **k Generation**: Repeat until $k \in [1, n-1]$

This prevents reuse of ephemeral keys and protects against side-channel attacks.

### Shufl Algorithm for Curve Order Verification

TorusCSIDH implements the Shufl algorithm to verify the order of curves:

1. For supersingular curves over $\mathbb{F}_p$ with $p \equiv 3 \pmod{4}$, the order is $p + 1 - t$ where $t$ is the Frobenius trace
2. Possible values of $t$: $0, \pm\sqrt{2p}, \pm\sqrt{3p}, \pm 2\sqrt{p}$
3. Verify which value satisfies $\#E(\mathbb{F}_p) = p + 1 - t$

This ensures curves used in the protocol have the correct order.

### Tonelli-Shanks Algorithm for Square Roots

For computing square roots in $\mathbb{F}_p$, TorusCSIDH implements the Tonelli-Shanks algorithm:

1. If $p \equiv 3 \pmod{4}$: $\sqrt{a} = a^{(p+1)/4} \pmod{p}$
2. For general $p$:
   - Write $p-1 = q \cdot 2^s$
   - Find a quadratic non-residue $z$
   - Initialize $c = z^q$, $r = a^{(q+1)/2}$, $t = a^q$, $m = s$
   - While $t \neq 1$:
     - Find smallest $i$ such that $t^{2^i} = 1$
     - $b = c^{2^{m-i-1}}$
     - $r = rb$, $t = tb^2$, $c = b^2$, $m = i$

This is used for point decompression and other operations.

---

## 7. Security Mechanisms

### Code Integrity Protection

TorusCSIDH includes a comprehensive code integrity protection system:

1. **HMAC Verification**: Each critical module has an HMAC signature
2. **TPM Integration**: Keys are stored in Trusted Platform Module
3. **Periodic Checks**: System integrity is verified before critical operations
4. **Self-Recovery**: If integrity is compromised, the system recovers from backup

The system maintains a list of critical modules:
- `toruscsidh.cpp`
- `toruscsidh.h`
- `velu_formulas.cpp`
- `geometric_validator.cpp`

Each module is signed with a cryptographic signature verified before use.

### Side-Channel Attack Protection

TorusCSIDH protects against side-channel attacks through:

1. **Constant-Time Execution**: All critical operations execute in fixed time
   - Dummy operations are performed to reach target execution time
   - Branches are eliminated in cryptographic operations
2. **Memory Protection**: Sensitive data is zeroed after use
   - Sodium's `sodium_memzero` is used for key wiping
3. **Random Delays**: Small random delays are added to operations to disrupt timing analysis

The target execution time for signing operations is 100ms, ensuring constant-time behavior.

### Self-Recovery System

The self-recovery system ensures availability even after integrity violations:

1. **Backup Creation**: Periodic backups of critical modules are created
2. **Encrypted Storage**: Backups are encrypted using ChaCha20-Poly1305
3. **TPM Binding**: Backup keys are bound to the TPM
4. **Recovery Process**:
   - Verify backup integrity
   - Decrypt modules
   - Verify module integrity
   - Replace compromised modules

The system allows up to 3 recovery attempts before permanent blocking.

---

## 8. Integration with Bitcoin

### Bech32m Address Format

TorusCSIDH uses the Bech32m format for addresses, an improvement over Bech32:

1. **HRP (Human-Readable Part)**: `tcidh` for TorusCSIDH addresses
2. **Data Encoding**: 5-bit chunks from the SHA-256 hash of the j-invariant
3. **Checksum**: Polynomial-based checksum ensures error detection

The encoding process:
1. Compute SHA-256 of the j-invariant
2. Convert to 5-bit chunks
3. Add checksum using Bech32m polynomial
4. Encode using the Bech32m character set

### Soft Fork Compatibility

TorusCSIDH is designed for soft fork compatibility with Bitcoin:

1. **New Witness Program Version**: Version 1 (0x01)
2. **Witness Script**: Contains the public key (j-invariant)
3. **Signature Verification**: Custom opcode validates TorusCSIDH signatures

The soft fork process:
1. Miners upgrade to support the new witness version
2. Users can create TorusCSIDH addresses
3. Non-upgraded nodes treat new transactions as anyone-can-spend (but cannot spend them)

### Transaction Structure

A TorusCSIDH transaction includes:

1. **Witness Program**: Version 1 followed by 64-byte j-invariant
2. **Witness Data**: 96-byte signature
3. **Verification Process**:
   - Extract j-invariant and signature
   - Verify geometric properties of the ephemeral curve
   - Verify the signature equation

The transaction size is comparable to ECDSA transactions, with only a small increase in witness data.

---

## 9. Testing and Verification

### Test Suite

TorusCSIDH includes a comprehensive test suite:

1. **Mathematical Correctness Tests**
   - Vélu's formulas verification
   - Shufl algorithm validation
   - Tonelli-Shanks implementation check

2. **Geometric Verification Tests**
   - Cyclomatic number calculation
   - Spectral gap analysis
   - Clustering coefficient verification
   - Degree entropy measurement
   - Distance to base curve calculation

3. **Security Tests**
   - Code integrity checks
   - Side-channel resistance testing
   - Self-recovery validation
   - Anomaly detection

4. **Attack Simulation Tests**
   - Long path attack detection
   - Adaptive attack resistance
   - Degenerate topology detection
   - Spectral gap manipulation attempts

### Audit Results

The system has undergone rigorous auditing:

1. **Mathematical Correctness**: All formulas verified against theoretical references
2. **Security Analysis**: No critical vulnerabilities found
3. **Performance Evaluation**: Meets all performance targets
4. **Compatibility Testing**: Works with Bitcoin Core 24.0+ in testnet

Critical issues identified and resolved:
- **Geometric Threshold**: Increased from 75% to 85% for stronger security
- **RFC 6979 Implementation**: Fixed to comply with standard
- **Shufl Algorithm**: Added for curve order verification
- **Side-Channel Protection**: Implemented constant-time execution

---

## 10. References

1. **De Feo, L., Jao, D., & Plût, J.** (2014). *Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies.* Journal of Mathematical Cryptology, 8(3), 209–247. DOI: [10.1515/jmc-2012-0015](https://doi.org/10.1515/jmc-2012-0015).

2. **Castryck, W., & Decru, T.** (2022). *An efficient key recovery attack on SIDH.* IACR Cryptology ePrint Archive, Report 2022/975.

3. **Beullens, W., Kleinjung, T., & Vercauteren, F.** (2019). *CSI-FiSh: Efficient isogeny based signatures through class group computations.* ASIACRYPT 2019.

4. **Bernstein, D. J., et al.** (2017). *SIKE: Supersingular Isogeny Key Encapsulation.* NIST Post-Quantum Cryptography Standardization.

5. **National Institute of Standards and Technology (NIST)**. (2022). *Post-Quantum Cryptography Standardization.* [https://csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

6. **Pieter Wuille, et al.** (2018). *Bech32m: A checksummed base32 address format.* BIP 350.

7. **Pornin, T.** (2015). *RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA).* IETF.

---

## Appendix A: API Documentation

### Class: `TorusCSIDH`

```cpp
class TorusCSIDH {
public:
    // Constructor with security level
    TorusCSIDH(SecurityLevel level = SecurityLevel::LEVEL_128);
    
    // Generate key pair
    void generate_key_pair();
    
    // Sign a message
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    // Verify a signature
    bool verify(const std::vector<unsigned char>& message,
               const std::vector<unsigned char>& signature,
               const MontgomeryCurve& public_curve);
    
    // Generate Bitcoin address
    std::string generate_address();
    
    // Print system information
    void print_info() const;
    
    // Run self-tests
    bool self_test();
    
    // Get public curve
    const MontgomeryCurve& get_public_curve() const;
    
    // Get base curve
    const MontgomeryCurve& get_base_curve() const;
    
    // Get private key
    const std::vector<short>& get_private_key() const;
    
    // Get prime numbers
    const std::vector<GmpRaii>& get_primes() const;
};
```

### Class: `GeometricValidator`

```cpp
class GeometricValidator {
public:
    // Constructor
    GeometricValidator(SecurityLevel level, 
                      CodeIntegrityProtection& integrity,
                      SecureAuditLogger& audit_logger,
                      std::map<std::string, int>& network_state,
                      Rfc6979Rng& rng);
    
    // Validate a curve
    bool validate_curve(const MontgomeryCurve& curve, 
                       const IsogenyGraph& subgraph,
                       double& cyclomatic_score,
                       double& spectral_score,
                       double& clustering_score,
                       double& entropy_score,
                       double& distance_score);
    
    // Build isogeny subgraph
    IsogenyGraph build_isogeny_subgraph(const MontgomeryCurve& curve, int radius);
    
    // Compute cyclomatic number
    double compute_cyclomatic_number(const IsogenyGraph& graph);
    
    // Compute spectral gap
    double compute_spectral_gap(const IsogenyGraph& graph);
    
    // Compute clustering coefficient
    double compute_clustering_coefficient(const IsogenyGraph& graph);
    
    // Compute degree entropy
    double compute_degree_entropy(const IsogenyGraph& graph);
    
    // Compute distance to base curve
    double compute_distance_to_base(const IsogenyGraph& graph, const MontgomeryCurve& base_curve);
};
```

---

## Appendix B: Security Parameters

### Security Level 128

| Parameter | Value |
|-----------|-------|
| Prime bits | 768 |
| Number of primes | 74 |
| Max key magnitude | 6 |
| Radius | 3 |
| Cyclomatic weight | 0.15 |
| Spectral weight | 0.30 |
| Clustering weight | 0.20 |
| Entropy weight | 0.20 |
| Distance weight | 0.15 |
| Geometric threshold | 0.85 |

### Security Level 192

| Parameter | Value |
|-----------|-------|
| Prime bits | 1152 |
| Number of primes | 110 |
| Max key magnitude | 8 |
| Radius | 4 |
| Cyclomatic weight | 0.15 |
| Spectral weight | 0.30 |
| Clustering weight | 0.20 |
| Entropy weight | 0.20 |
| Distance weight | 0.15 |
| Geometric threshold | 0.85 |

### Security Level 256

| Parameter | Value |
|-----------|-------|
| Prime bits | 1536 |
| Number of primes | 147 |
| Max key magnitude | 10 |
| Radius | 5 |
| Cyclomatic weight | 0.15 |
| Spectral weight | 0.30 |
| Clustering weight | 0.20 |
| Entropy weight | 0.20 |
| Distance weight | 0.15 |
| Geometric threshold | 0.85 |

---

## Appendix C: Example Usage

### Generating a Key Pair and Signing a Message

```cpp
#include "toruscsidh.h"
#include <iostream>

int main() {
    // Create system with 128-bit security level
    TorusCSIDH csidh(SecurityLevel::LEVEL_128);
    
    // Generate key pair
    csidh.generate_key_pair();
    
    // Generate address
    std::string address = csidh.generate_address();
    std::cout << "Generated address: " << address << std::endl;
    
    // Sign a message
    std::string message = "Example Bitcoin transaction";
    auto signature = csidh.sign(std::vector<unsigned char>(
        message.begin(), message.end()));
    
    // Verify the signature
    bool is_valid = csidh.verify(
        std::vector<unsigned char>(message.begin(), message.end()),
        signature,
        csidh.get_public_curve());
    
    std::cout << "Signature verification: " 
              << (is_valid ? "SUCCESS" : "FAILURE") << std::endl;
    
    return 0;
}
```

### Building and Running

```bash
mkdir build
cd build
cmake ..
make
./toruscsidh
```

---

## Copyright Notice

Copyright (c) 2025 TorusCSIDH Development Team

This document is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License.

To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/4.0/ or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
