cmake_minimum_required(VERSION 3.10)
project(TorusCSIDH)

# Установка стандарта C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -Wall -Wextra")

# Поиск необходимых пакетов
find_package(PkgConfig REQUIRED)
find_package(Eigen3 3.3 REQUIRED NO_MODULE)
find_package(OpenSSL REQUIRED)
find_package(GMP REQUIRED)

# Проверка наличия MPFR
pkg_check_modules(MPFR QUIET mpfr)
if(MPFR_FOUND)
    include_directories(${MPFR_INCLUDE_DIRS})
    link_libraries(${MPFR_LIBRARIES})
else()
    message(WARNING "MPFR не найден. Некоторые функции могут быть ограничены.")
endif()

# Включение поддержки OpenMP для параллельных вычислений
find_package(OpenMP)
if(OPENMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

# Добавление исполняемого файла
add_executable(toruscsidh 
    src/main.cpp
    src/math/big_integer.cpp
    src/math/galois_field.cpp
    src/math/field_extension.cpp
    src/math/elliptic_curve.cpp
    src/csidh/isogeny_engine.cpp
    src/csidh/geometric_verifier.cpp
    src/csidh/toruscsidh.cpp
)

# Подключение заголовочных файлов
include_directories(
    ${EIGEN3_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    include
)

# Связывание с библиотеками
target_link_libraries(toruscsidh
    ${GMP_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

# Установка правила для генерации документации
add_custom_target(doc
    doxygen Doxyfile
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Генерация документации Doxygen"
)

# Создание правила для запуска тестов
add_custom_target(test
    COMMAND ${CMAKE_BINARY_DIR}/toruscsidh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Запуск тестов TorusCSIDH"
)

# Создание правила для очистки
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/CMakeFiles/Makefile.cmake clean
    COMMAND rm -rf ${CMAKE_BINARY_DIR}/doc
    COMMENT "Полная очистка проекта"
)
