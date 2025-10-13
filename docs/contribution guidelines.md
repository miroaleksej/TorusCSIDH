# Contributing to TorusCSIDH

Thank you for your interest in contributing to TorusCSIDH! This document outlines our contribution process and guidelines. As a cryptographic project designed to secure Bitcoin against quantum threats, we take contributions seriously and have established clear processes to maintain the highest standards of security and quality.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Pull Request Guidelines](#pull-request-guidelines)
- [License](#license)

## Code of Conduct

All contributors are expected to follow our [Code of Conduct](https://github.com/miroaleksej/TorusCSIDH/blob/main/docs/Code%20of%20Conduct.md). Please review it before contributing to ensure a respectful and collaborative environment.

## Getting Started

### Prerequisites
Before contributing, ensure you have the required dependencies installed:
- C++17 compatible compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- Boost 1.65+ (system, graph components)
- Eigen 3.3+
- RELIC 0.3+
- OpenSSL 1.1.1+
- Libsodium 1.0.18+
- GMP 6.2.0+
- TSS2 (for TPM integration)

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/toruscsidh.git
   cd toruscsidh
   ```
3. Install dependencies (see [README](README.md) for detailed instructions)
4. Build the project:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```
5. Run the self-test suite:
   ```bash
   ./toruscsidh_tests
   ```

### Understanding the Codebase

Key components to familiarize yourself with:
- `toruscsidh.h`/`toruscsidh.cpp`: Core implementation
- `geometric_validator.*`: Geometric verification layer
- `velu_formulas.*`: Vélu's formulas implementation
- `rfc6979_rng.*`: Deterministic key generation
- `code_integrity.*`: System integrity protection

## Reporting Issues

### Bug Reports
When reporting bugs, please include:
- Detailed description of the issue
- Steps to reproduce
- Expected behavior vs. actual behavior
- System information (OS, compiler version, dependencies)
- Relevant code snippets or error logs

### Feature Requests
For feature requests:
- Explain the problem you're trying to solve
- Describe your proposed solution
- Include any relevant research or references
- Note potential security implications

### Mathematical Verification Requests
As a cryptographic project, we welcome mathematical verification:
- Clearly identify which aspect needs verification (e.g., Vélu's formulas, geometric criteria)
- Reference relevant academic papers
- Provide counterexamples if challenging our implementation
- Note any potential improvements to our mathematical approach

## Security Vulnerabilities

**IMPORTANT:** If you discover a security vulnerability, **DO NOT** open a public issue. Instead, follow our responsible disclosure process:

1. Email security@toruscsidh.org with details of the vulnerability
2. Include:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
3. We will acknowledge receipt within 48 hours
4. We will work with you to fix the issue and coordinate disclosure

We follow a 90-day disclosure timeline unless otherwise agreed upon with the reporter.

## Development Process

TorusCSIDH follows a structured development process:

1. **Issue Creation**: All work should be tied to an issue
2. **Branch Creation**: Create a feature branch from `develop`
3. **Implementation**: Follow coding and testing standards
4. **Testing**: Run all relevant tests and add new tests as needed
5. **Documentation**: Update documentation for new features
6. **Pull Request**: Submit against the `develop` branch
7. **Review**: Address feedback from maintainers
8. **Merge**: Approved PRs are merged into `develop`

## Coding Standards

### C++ Style
- Follow Google C++ Style Guide with these exceptions:
  - Use `constexpr` where appropriate
  - Prefer `std::unique_ptr` over raw pointers
  - All cryptographic operations must be constant-time
  - No exceptions in critical paths (use error codes)
  - All sensitive data must be zeroed after use

### Naming Conventions
- Classes: `PascalCase` (e.g., `MontgomeryCurve`)
- Functions: `snake_case` (e.g., `compute_isogeny`)
- Variables: `snake_case` (e.g., `j_invariant`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `GEOMETRIC_THRESHOLD`)

### Security-Specific Requirements
- All cryptographic operations must execute in constant time
- Sensitive data must be zeroed using `sodium_memzero`
- No branching on secret data
- All modular arithmetic must use constant-time implementations
- Key derivation must follow RFC 6979
- All critical modules must be signed and verified

### Code Documentation
- All public APIs must have Doxygen comments
- Complex algorithms should include references to academic papers
- Security-critical code must explain why it's secure
- Mathematical formulas should be documented with LaTeX

Example:
```cpp
/**
 * @brief Computes the isogeny of degree 3 using Vélu's formulas
 * 
 * For a curve E: y^2 = x^3 + Ax^2 + x and a point P = (x, y) of order 3:
 * \f[
 * \psi_3 = 3x^4 + 6Ax^3 + 6(A^2-3)x^2 + 2A(A^2-9)x + (A^2-3)^2
 * \f]
 * \f[
 * \phi_3 = x\psi_3^2 - \psi_2\psi_4
 * \f]
 * \f[
 * A' = A - 3\frac{\phi_3 + (A^2-3)x\psi_3^2}{\psi_3^2}
 * \f]
 * 
 * @param curve The input curve E: y^2 = x^3 + Ax^2 + x
 * @param kernel_point A point of order 3 on the curve
 * @return MontgomeryCurve The isogenous curve E': y^2 = x^3 + A'x^2 + x
 * 
 * @note This implementation is constant-time to prevent side-channel attacks
 * @see "Elliptic curves and their applications to cryptography: an introduction" by A. Menezes
 */
MontgomeryCurve compute_isogeny_degree_3(const MontgomeryCurve& curve, 
                                       const EllipticCurvePoint& kernel_point) const;
```

## Testing Requirements

### Types of Tests Required
1. **Unit Tests**: For all new functionality
2. **Mathematical Verification**: Confirm correctness against reference implementations
3. **Security Tests**: Verify constant-time execution and side-channel resistance
4. **Geometric Verification Tests**: Validate all geometric criteria
5. **Integration Tests**: With Bitcoin Core components

### Test Coverage
- Minimum 90% code coverage for critical components
- 100% coverage for cryptographic operations
- All edge cases must be tested

### Running Tests
```bash
cd build
make test
./toruscsidh_tests --gtest_filter=GeometricValidator.*
```

### Adding New Tests
1. Create a new test file in `tests/` directory
2. Name it according to the component being tested (e.g., `geometric_validator_test.cpp`)
3. Include comprehensive test cases:
   - Normal operation
   - Edge cases
   - Error conditions
   - Security boundary cases
   - Performance benchmarks

## Documentation Standards

### Technical Documentation
- All mathematical concepts must be explained with references
- Include LaTeX formulas for all critical equations
- Document assumptions and limitations
- Explain the rationale behind design decisions

### User Documentation
- Provide clear examples for all major functionality
- Include performance characteristics
- Document security properties and limitations
- Explain how to integrate with Bitcoin applications

### API Documentation
- All public APIs must have complete Doxygen documentation
- Include examples of usage
- Document error conditions
- Note security implications

## Pull Request Guidelines

### Before Submitting
- Ensure all tests pass
- Verify code follows style guidelines
- Update documentation as needed
- Run static analysis tools (Clang-Tidy, etc.)
- Sign the [Developer Certificate of Origin](https://developercertificate.org/)

### Pull Request Content
- Reference the related issue (e.g., "Fixes #123")
- Include a clear description of changes
- Explain the rationale for the changes
- Note any security implications
- Include relevant test results

### Review Process
- All PRs require at least two approvals from maintainers
- Security-critical changes require cryptographic review
- Mathematical changes require verification by experts
- PRs will be reviewed within 7 business days

### Common Reasons for Rejection
- Incomplete tests
- Insufficient documentation
- Failure to follow coding standards
- Security vulnerabilities
- Lack of mathematical justification
- Inadequate performance analysis

## License

By contributing to TorusCSIDH, you agree that your contributions will be licensed under the MIT License as found in the [LICENSE](LICENSE) file.

When adding new files, include the following license header:

```cpp
// Copyright (c) 2025 TorusCSIDH Development Team
// 
// This file is part of TorusCSIDH.
// 
// TorusCSIDH is free software: you can redistribute it and/or modify
// it under the terms of the MIT License.
// 
// TorusCSIDH is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// MIT License for more details.
```

---

**Thank you for contributing to TorusCSIDH! Your expertise helps secure Bitcoin against quantum threats.**

For questions about contributing, contact miro-aleksej@yandex.ru 
