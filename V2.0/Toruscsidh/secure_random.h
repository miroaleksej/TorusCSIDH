#ifndef SECURE_RANDOM_H
#define SECURE_RANDOM_H

#include <vector>
#include <sodium.h>
#include <chrono>
#include <cstdint>
#include <gmpxx.h>
#include "security_constants.h"

/**
 * @brief Класс для безопасной генерации случайных чисел
 * 
 * Обеспечивает криптографически безопасную генерацию случайных чисел
 * с защитой от атак по побочным каналам.
 */
class SecureRandom {
public:
    /**
     * @brief Конструктор
     */
    SecureRandom();
    
    /**
     * @brief Деструктор
     */
    ~SecureRandom();
    
    /**
     * @brief Инициализация генератора
     * @return true, если инициализация прошла успешно
     */
    bool initialize();
    
    /**
     * @brief Генерация криптографически безопасного случайного числа
     * @param max Максимальное значение (не включая)
     * @return Случайное число в диапазоне [0, max)
     */
    GmpRaii random_uint(const GmpRaii& max);
    
    /**
     * @brief Генерация криптографически безопасного случайного числа в диапазоне
     * @param min Минимальное значение (включая)
     * @param max Максимальное значение (не включая)
     * @return Случайное число в диапазоне [min, max)
     */
    int random_int(int min, int max);
    
    /**
     * @brief Генерация криптографически безопасного случайного байта
     * @return Случайный байт
     */
    unsigned char random_byte();
    
    /**
     * @brief Генерация криптографически безопасного случайного массива байтов
     * @param output Выходной буфер
     */
    void random_bytes(std::vector<unsigned char>& output);
    
    /**
     * @brief Генерация криптографически безопасного случайного массива байтов заданного размера
     * @param size Размер буфера
     * @return Случайный массив байтов
     */
    std::vector<unsigned char> random_bytes(size_t size);
    
    /**
     * @brief Безопасная очистка памяти
     * @param ptr Указатель на память
     * @param size Размер памяти
     */
    static void secure_clean_memory(void* ptr, size_t size);
    
    /**
     * @brief Получение текущего времени в наносекундах (для соли)
     * @return Текущее время в наносекундах
     */
    static uint64_t get_current_time_ns();

private:
    bool initialized;  ///< Флаг инициализации
};

SecureRandom::SecureRandom() : initialized(false) {
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    initialized = true;
}

SecureRandom::~SecureRandom() {
    // Нет необходимости в очистке, libsodium обрабатывает это автоматически
}

bool SecureRandom::initialize() {
    if (initialized) return true;
    
    if (sodium_init() < 0) {
        return false;
    }
    
    initialized = true;
    return true;
}

GmpRaii SecureRandom::random_uint(const GmpRaii& max) {
    if (!initialized) {
        throw std::runtime_error("SecureRandom not initialized");
    }
    
    if (max <= GmpRaii(0)) {
        throw std::invalid_argument("Max value must be positive");
    }
    
    // Генерация случайного числа в безопасном диапазоне
    size_t bits = mpz_sizeinbase(max.get_mpz_t(), 2);
    std::vector<unsigned char> random_bytes((bits + 7) / 8);
    
    // Используем криптографически безопасный RNG
    randombytes_buf(random_bytes.data(), random_bytes.size());
    
    // Создаем GMP число из случайных байтов
    GmpRaii result;
    mpz_import(result.get_mpz_t(), random_bytes.size(), 1, 1, 0, 0, random_bytes.data());
    
    // Обеспечиваем, что число в пределах диапазона
    result %= max;
    
    // Добавляем дополнительную защиту от атак по времени
    if (result == GmpRaii(0) && max > GmpRaii(1)) {
        result = random_uint(max);
    }
    
    return result;
}

int SecureRandom::random_int(int min, int max) {
    if (!initialized) {
        throw std::runtime_error("SecureRandom not initialized");
    }
    
    if (min >= max) {
        throw std::invalid_argument("Invalid range for random_int");
    }
    
    int range = max - min;
    if (range <= 0) {
        throw std::invalid_argument("Invalid range for random_int");
    }
    
    // Генерация случайного числа в диапазоне [0, range)
    std::vector<unsigned char> random_data(sizeof(int));
    randombytes_buf(random_data.data(), random_data.size());
    
    // Преобразуем в целое число
    int rand_value;
    memcpy(&rand_value, random_data.data(), sizeof(int));
    
    // Делаем значение положительным и в пределах диапазона
    rand_value = std::abs(rand_value) % range;
    
    return min + rand_value;
}

unsigned char SecureRandom::random_byte() {
    if (!initialized) {
        throw std::runtime_error("SecureRandom not initialized");
    }
    
    unsigned char byte;
    randombytes_buf(&byte, 1);
    return byte;
}

void SecureRandom::random_bytes(std::vector<unsigned char>& output) {
    if (!initialized) {
        throw std::runtime_error("SecureRandom not initialized");
    }
    
    if (output.empty()) {
        return;
    }
    
    randombytes_buf(output.data(), output.size());
}

std::vector<unsigned char> SecureRandom::random_bytes(size_t size) {
    if (!initialized) {
        throw std::runtime_error("SecureRandom not initialized");
    }
    
    std::vector<unsigned char> output(size);
    randombytes_buf(output.data(), size);
    return output;
}

void SecureRandom::secure_clean_memory(void* ptr, size_t size) {
    if (ptr == nullptr || size == 0) return;
    
    volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; i++) {
        vptr[i] = static_cast<unsigned char>(randombytes_random() % 256);
    }
    
    // Дополнительная очистка с использованием sodium
    sodium_memzero(ptr, size);
}

uint64_t SecureRandom::get_current_time_ns() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

#endif // SECURE_RANDOM_H
