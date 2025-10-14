cmake_minimum_required(VERSION 3.10)
project(TorusCSIDH)

# Установка C++17 как минимальной версии
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Найти пакеты
find_package(PkgConfig REQUIRED)
find_package(Boost 1.65 COMPONENTS system graph REQUIRED)
find_package(Eigen3 3.3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Libsodium REQUIRED)
find_package(GMP REQUIRED)

# Включить директории
include_directories(
    ${Boost_INCLUDE_DIRS}
    ${EIGEN3_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${GMP_INCLUDE_DIRS}
)

# Добавить исполняемый файл
add_executable(toruscsidh
    security_constants.h security_constants.cpp
    secure_random.h secure_random.cpp
    postquantum_hash.h postquantum_hash.cpp
    rfc6979_rng.h rfc6979_rng.cpp
    elliptic_curve.h elliptic_curve.cpp
    geometric_validator.h geometric_validator.cpp
    code_integrity.h code_integrity.cpp
    secure_audit_logger.h secure_audit_logger.cpp
    toruscsidh.h toruscsidh.cpp
    main.cpp
    bech32m.h bech32m.cpp
)

# Ссылка на библиотеки
target_link_libraries(toruscsidh
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARIES}
    gmp
    gmpxx
    m
)
