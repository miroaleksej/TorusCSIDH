# TorusCSIDH: Post-Quantum Cryptographic System for Bitcoin

![image](https://github.com/user-attachments/assets/8401e7fb-fa41-41ff-829b-9be70a0bb80b)

![C++](https://img.shields.io/badge/C++-17/20-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Development Status](https://img.shields.io/badge/Status-In_Development-orange?style=for-the-badge)

[![Visitor Count](https://profile-counter.glitch.me/toruscsidh/count.svg)](https://profile-counter.glitch.me/toruscsidh)

>## ⚠️ Development Status
**This project is currently in active development and should not be used in production environments.** The current implementation represents a research prototype of the TorusCSIDH post-quantum cryptographic system. While the mathematical foundations are sound and the code has been designed with security in mind, **this implementation has not yet undergone comprehensive security audits or testing** required for production use. Production deployment should only occur after thorough independent verification and when an official stable release is published.

The system is in the **verification and debugging stage** - no formal testing has been conducted yet. We welcome researchers, cryptographers, and developers to contribute to the project through code review, mathematical verification, and collaborative development.

## Introduction

TorusCSIDH is a post-quantum cryptographic system designed as a replacement for ECDSA in Bitcoin. It builds upon the CSIDH (Commutative Supersingular Isogeny Diffie-Hellman) protocol but introduces a critical innovation: a **geometric verification layer** that analyzes the structural properties of the isogeny graph to detect and prevent sophisticated attacks.

Unlike traditional cryptographic systems that rely solely on algebraic properties, TorusCSIDH provides dual-layer security:

1. **Algebraic Layer**: The standard CSIDH protocol with proven security against known attacks
2. **Geometric Layer**: Analysis of the structural properties of the isogeny graph to detect anomalous curves

> "Как в музыке гармония возникает не из отдельных нот, а из их соотношений, безопасность в TorusCSIDH возникает не из отдельных криптографических свойств, а из их структурных соотношений."

## Key Features

- **Post-Quantum Security**: Resistant to attacks from quantum computers
- **Compact Keys and Signatures**: 64 bytes for keys, 96 bytes for signatures
- **Bitcoin Compatibility**: Soft fork through SegWit, Bech32m address format
- **Geometric Verification**: Unique protection against "degenerate topology" attacks
- **Full Mathematical Correctness**: Complete implementation of Vélu's formulas and Shufl algorithm

## Innovation: Geometric Verification

TorusCSIDH introduces a geometric verification layer that analyzes five structural properties of the isogeny graph:

1. **Cyclomatic Number**: μ = |E| - |V| + 1 ≥ 2
2. **Spectral Gap Analysis**: λ₂ - λ₁ > 1.5, λ₃ < 0.5, λ₄ ≥ 0.7
3. **Clustering Coefficient**: C > 0.3
4. **Degree Entropy**: H > 0.8
5. **Distance to Base Curve**: d < 3

These criteria work together with a threshold of 85% for accepting a curve as secure.

## Technical Details

### Security Levels

| Level | Security Bits | Prime Bits | Number of Primes | Max Key Magnitude | Radius |
|-------|---------------|------------|------------------|-------------------|--------|
| 128   | 128           | 768        | 74               | 6                 | 3      |
| 192   | 192           | 1152       | 110              | 8                 | 4      |
| 256   | 256           | 1536       | 147              | 10                | 5      |

### Data Formats

- **Private Key**: Vector of exponents d = [d₁, d₂, ..., dₙ] where each dᵢ ∈ [-m, m]
- **Public Key**: j-invariant of the curve [d]E₀, encoded as 64 bytes
- **Signature**: 96 bytes (j-invariant of Eₑₚₕ + s value)
- **Address Format**: Bech32m with prefix `tcidh`

## Requirements

- C++17 compatible compiler (GCC 9+, Clang 10+, MSVC 2019+)
- Required libraries:
  - Boost 1.65+ (system, graph components)
  - Eigen 3.3+
  - RELIC 0.3+
  - OpenSSL 1.1.1+
  - Libsodium 1.0.18+
  - GMP 6.2.0+
  - TSS2 (for TPM integration)
- Operating System Support:
  - Linux (Ubuntu 20.04+, Debian 10+)
  - macOS 10.15+
  - Windows 10+ (with WSL2 recommended)

## Installation

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

## Usage Example

```cpp
#include "toruscsidh.h"
#include <iostream>

int main() {
    try {
        // Create system with 128-bit security level
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        
        // Generate key pair
        csidh.generate_key_pair();
        
        // Generate Bitcoin address
        std::string address = csidh.generate_address();
        std::cout << "Generated address: " << address << std::endl;
        
        // Sign a message
        std::string message = "Example Bitcoin transaction";
        auto signature = csidh.sign(std::vector<unsigned char>(message.begin(), message.end()));
        
        // Verify the signature
        bool is_valid = csidh.verify(std::vector<unsigned char>(message.begin(), message.end()),
                                    signature,
                                    csidh.get_public_curve());
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

## Contributing

We welcome researchers, cryptographers, and developers to contribute to the project through:

- Mathematical verification of algorithms
- Code review and security analysis
- Implementation improvements
- Testing and benchmarking

Please see our [contribution guidelines](CONTRIBUTING.md) for details on how to participate in this important effort to secure Bitcoin against quantum threats.

## Contact

For collaboration opportunities or technical inquiries, please contact:

**miro-aleksej@yandex.ru**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**TorusCSIDH — Защита Bitcoin от квантовых угроз через структурную гармонию графа изогений.**

## Keywords

post-quantum-cryptography, csidh, isogeny-based-cryptography, bitcoin-security, quantum-resistant-cryptography, elliptic-curve-cryptography, geometric-verification, toruscsidh, supersingular-isogeny, bech32m, soft-fork, bitcoin-upgrade, cryptographic-signatures, bitcoin-core, quantum-computing, blockchain-security, montgomery-curve, velu-formulas, shufl-algorithm, side-channel-protection
