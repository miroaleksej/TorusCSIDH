cmake_minimum_required(VERSION 3.10)
project(TorusCSIDH VERSION 1.0.0 LANGUAGES CXX)

# Установка C++17 как минимальной версии
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Настройки сборки
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Опции сборки
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(ENABLE_SECURITY_CHECKS "Enable security checks" ON)

# Найти пакеты
find_package(PkgConfig REQUIRED)
find_package(Boost 1.65 COMPONENTS system graph REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(GMP REQUIRED)
find_package(Eigen3 3.3 REQUIRED)
find_package(sodium REQUIRED)

# Поиск BLAKE3
find_path(BLAKE3_INCLUDE_DIR NAMES blake3.h)
find_library(BLAKE3_LIBRARY NAMES blake3)
if(BLAKE3_INCLUDE_DIR AND BLAKE3_LIBRARY)
    include_directories(${BLAKE3_INCLUDE_DIR})
else()
    # Если BLAKE3 не найден, используем встроенную реализацию
    set(BLAKE3_BUNDLED TRUE)
    set(BLAKE3_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3/include)
    set(BLAKE3_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3/lib/libblake3.a)
    include_directories(${BLAKE3_INCLUDE_DIR})
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/third_party/blake3)
    add_custom_command(
        OUTPUT ${BLAKE3_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3/lib/libblake3.a ${BLAKE3_LIBRARY}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3/lib/libblake3.a
        COMMENT "Copying BLAKE3 library"
    )
    add_custom_target(bundled_blake3 ALL DEPENDS ${BLAKE3_LIBRARY})
endif()

# Создание интерфейсной библиотеки для BLAKE3
add_library(blake3 INTERFACE)
target_include_directories(blake3 INTERFACE ${BLAKE3_INCLUDE_DIR})
if(BLAKE3_BUNDLED)
    target_link_libraries(blake3 INTERFACE ${BLAKE3_LIBRARY})
    add_dependencies(blake3 bundled_blake3)
else()
    target_link_libraries(blake3 INTERFACE ${BLAKE3_LIBRARY})
endif()

# Настройка флагов компиляции для безопасности
if(ENABLE_SECURITY_CHECKS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -fPIC -ftrapv")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now,-z,noexecstack")
endif()

# Добавляем директории с заголовками
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${GMP_INCLUDE_DIR}
    ${EIGEN3_INCLUDE_DIR}
)

# Создаем статическую библиотеку TorusCSIDH
add_library(toruscsidh STATIC
    src/security_constants.cpp
    src/secure_random.cpp
    src/postquantum_hash.cpp
    src/rfc6979_rng.cpp
    src/elliptic_curve.cpp
    src/geometric_validator.cpp
    src/code_integrity_protection.cpp
    src/secure_audit_logger.cpp
    src/bech32m.cpp
    src/toruscsidh.cpp
)

# Устанавливаем свойства библиотеки
set_target_properties(toruscsidh PROPERTIES
    OUTPUT_NAME "toruscsidh"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)

# Связываем библиотеку с зависимостями
target_link_libraries(toruscsidh PRIVATE
    Boost::system
    Boost::graph
    OpenSSL::SSL
    OpenSSL::Crypto
    sodium
    blake3
    ${GMP_LIBRARIES}
    m
)

# Устанавливаем интерфейсные в
