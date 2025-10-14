# TorusCSIDH 2.0 - Post-Quantum Cryptographic System

## Overview

TorusCSIDH is a post-quantum cryptographic system based on the Commutative Supersingular Isogeny Diffie-Hellman (CSIDH) protocol. This implementation provides quantum-resistant cryptographic operations designed to withstand attacks from future quantum computers while maintaining compatibility with existing infrastructure.

Unlike traditional cryptographic systems that rely on integer factorization or discrete logarithm problems (which are vulnerable to Shor's algorithm), TorusCSIDH leverages the mathematical complexity of isogenies between supersingular elliptic curves, representing one of the most promising approaches to post-quantum cryptography.

## Key Features

- **Post-quantum security**: Designed to resist attacks from both classical and quantum computers
- **Geometric security validation**: Implements advanced graph theory analysis of isogeny graphs to detect potential vulnerabilities
- **Constant-time execution**: Protection against timing side-channel attacks through rigorous constant-time implementation
- **Self-integrity verification**: Built-in system integrity checks with recovery mechanisms
- **RFC 6979 compliant**: Deterministic signature generation that prevents private key leakage
- **Bitcoin integration**: Generates addresses in Bech32m format for potential post-quantum Bitcoin applications
- **Multiple security levels**: Support for 128-bit, 192-bit, and 256-bit security levels

## System Requirements

- CMake 3.10 or higher
- Boost 1.65 (system and graph components)
- Eigen3 3.3
- RELIC 0.3
- OpenSSL
- Libsodium
- GMP
- C++17 compatible compiler

## Build Instructions

1. Clone the repository:
```
git clone https://github.com/yourusername/toruscsidh.git
cd toruscsidh
```

2. Create build directory and compile:
```
mkdir -p build
cd build
cmake ..
make
```

3. Run the example application:
```
./toruscsidh
```

## Development Status

This is version 2.0 of the TorusCSIDH implementation. Please note that this system is currently in active development. The following important considerations apply:

- No comprehensive test suite has been implemented yet
- The implementation should be considered experimental
- Not recommended for production use at this stage
- Security analysis is ongoing

## Security Considerations

While TorusCSIDH is designed with multiple layers of security, this implementation is still under development and has not undergone formal security audits. The geometric validation system provides an additional security layer beyond standard CSIDH implementations, but users should exercise caution when considering this for any security-critical applications.

## Contributing

Contributions to improve the security, performance, and documentation of TorusCSIDH are welcome. Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

When contributing, please ensure your code follows the existing style and includes appropriate documentation.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions, suggestions, or security concerns regarding TorusCSIDH, please contact:

miro-aleksej@yandex.ru

Please note that as this is a development version, responses to technical inquiries may be delayed while the implementation is being refined.

## Acknowledgments

- The CSIDH protocol authors
- The developers of RELIC, Libsodium, and other cryptographic libraries used in this implementation
- The post-quantum cryptography research community for their valuable contributions to the field

---

*This is a development version. Use at your own risk. Not suitable for production environments.*
