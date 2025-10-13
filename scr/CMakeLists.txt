cmake_minimum_required(VERSION 3.10)
project(TorusCSIDH)

# Установка C++17 как минимальной версии
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Найти пакеты
find_package(PkgConfig REQUIRED)
find_package(Boost 1.65 COMPONENTS system graph REQUIRED)
find_package(Eigen3 3.3 REQUIRED)
find_package(RELIC 0.3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Libsodium REQUIRED)
find_package(GMP REQUIRED)
find_package(TSS2 REQUIRED)

# Включить директории
include_directories(
    ${Boost_INCLUDE_DIRS}
    ${EIGEN3_INCLUDE_DIR}
    ${RELIC_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${TSS2_INCLUDE_DIRS}
    ${GMP_INCLUDE_DIRS}
)

# Добавить исполняемый файл
add_executable(toruscsidh
    toruscsidh.h
    toruscsidh.cpp
    main.cpp
)

# Ссылка на библиотеки
target_link_libraries(toruscsidh
    ${Boost_LIBRARIES}
    ${RELIC_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARIES}
    ${TSS2_LIBRARIES}
    gmp
    gmpxx
    m
)

# Установка флагов компиляции
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(toruscsidh PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -O3
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    target_link_options(toruscsidh PRIVATE
        -pie
        -Wl,-z,relro,-z,now
    )
endif()

# Установка правил установки
install(TARGETS toruscsidh
    RUNTIME DESTINATION bin
)
