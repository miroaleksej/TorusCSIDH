# Создание тестов для TorusCSIDH
cmake_minimum_required(VERSION 3.14)
project(TorusCSIDHTests)

# Поиск Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Добавление тестов
add_executable(toruscsidh_tests
    test_geometric_validator.cpp
    test_elliptic_curve.cpp
    test_postquantum_hash.cpp
    test_rfc6979_rng.cpp
    test_code_integrity.cpp
    test_secure_audit_logger.cpp
    test_security_constants.cpp
    test_toruscsidh.cpp
    test_bech32m.cpp
)

# Связывание с библиотеками
target_link_libraries(toruscsidh_tests
    toruscsidh
    ${GTEST_LIBRARIES}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARIES}
    gmp
    gmpxx
    m
    pthread
    rt
)

# Добавление тестов в CTest
add_test(NAME geometric_validator_test COMMAND toruscsidh_tests --gtest_filter=GeometricValidatorTest.*)
add_test(NAME elliptic_curve_test COMMAND toruscsidh_tests --gtest_filter=EllipticCurveTest.*)
add_test(NAME postquantum_hash_test COMMAND toruscsidh_tests --gtest_filter=PostQuantumHashTest.*)
add_test(NAME rfc6979_rng_test COMMAND toruscsidh_tests --gtest_filter=Rfc6979RngTest.*)
add_test(NAME code_integrity_test COMMAND toruscsidh_tests --gtest_filter=CodeIntegrityTest.*)
add_test(NAME secure_audit_logger_test COMMAND toruscsidh_tests --gtest_filter=SecureAuditLoggerTest.*)
add_test(NAME security_constants_test COMMAND toruscsidh_tests --gtest_filter=SecurityConstantsTest.*)
add_test(NAME toruscsidh_test COMMAND toruscsidh_tests --gtest_filter=TorusCSIDHTest.*)
add_test(NAME bech32m_test COMMAND toruscsidh_tests --gtest_filter=Bech32mTest.*)
