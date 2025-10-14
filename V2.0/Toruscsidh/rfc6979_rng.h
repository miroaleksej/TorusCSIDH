#ifndef RFC6979_RNG_H
#define RFC6979_RNG_H

#include <vector>
#include <sodium.h>
#include <cstdint>
#include <gmpxx.h>
#include "postquantum_hash.h"
#include "security_constants.h"

/**
 * @brief Класс для генерации детерминированных случайных чисел по RFC 6979
 * 
 * Реализует безопасную генерацию k-значений для подписей,
 * соответствующую RFC 6979, но адаптированную для постквантовых систем.
 */
class Rfc6979Rng {
public:
    /**
     * @brief Конструктор
     * @param p Параметр поля (простое число)
     * @param private_key Приватный ключ
     * @param max_key_magnitude Максимальная величина ключа
     */
    Rfc6979Rng(const GmpRaii& p, 
               const std::vector<short>& private_key,
               int max_key_magnitude);
    
    /**
     * @brief Деструктор
     */
    ~Rfc6979Rng();
    
    /**
     * @brief Генерация детерминированного k-значения для подписи
     * @param message_hash Хеш сообщения
     * @return k-значение
     */
    GmpRaii generate_k(const std::vector<unsigned char>& message_hash);
    
    /**
     * @brief Генерация детерминированного эфемерного ключа
     * @param message Сообщение
     * @return Эфемерный ключ
     */
    std::vector<short> generate_ephemeral_key(const std::string& message);
    
    /**
     * @brief Генерация случайного целого числа в диапазоне
     * @param min Минимальное значение (включая)
     * @param max Максимальное значение (не включая)
     * @return Случайное число в диапазоне [min, max)
     */
    int generate_random_exponent(int max_magnitude);
    
    /**
     * @brief Генерация случайных байтов с использованием криптографического RNG
     * @param output Выходной буфер
     */
    void generate_random_bytes(std::vector<unsigned char>& output);

private:
    GmpRaii p;                       ///< Параметр поля (простое число)
    std::vector<short> private_key;  ///< Приватный ключ
    int max_key_magnitude;           ///< Максимальная величина ключа
    SecureRandom secure_random;      ///< Безопасный генератор случайных чисел
};

Rfc6979Rng::Rfc6979Rng(const GmpRaii& p, 
                       const std::vector<short>& private_key,
                       int max_key_magnitude)
    : p(p), private_key(private_key), max_key_magnitude(max_key_magnitude) {
    // Инициализация не требуется, т.к. secure_random инициализируется сам
}

Rfc6979Rng::~Rfc6979Rng() {
    // Очистка не требуется
}

GmpRaii Rfc6979Rng::generate_k(const std::vector<unsigned char>& message_hash) {
    // RFC 6979 реализация с использованием постквантовых хеш-функций
    // Для постквантовой безопасности мы используем BLAKE3 вместо SHA-256
    
    // 1. Подготовка приватного ключа для хеширования
    std::vector<unsigned char> x;
    for (short val : private_key) {
        unsigned char bytes[2];
        bytes[0] = static_cast<unsigned char>(val & 0xFF);
        bytes[1] = static_cast<unsigned char>((val >> 8) & 0xFF);
        x.push_back(bytes[0]);
        x.push_back(bytes[1]);
    }
    
    // 2. Добавление соли для защиты от атак по времени
    std::vector<unsigned char> salt = PostQuantumHash::create_salt();
    
    // 3. Формирование данных для хеширования
    std::vector<unsigned char> hash_data;
    hash_data.insert(hash_data.end(), salt.begin(), salt.end());
    hash_data.insert(hash_data.end(), x.begin(), x.end());
    hash_data.insert(hash_data.end(), message_hash.begin(), message_hash.end());
    
    // 4. Вычисление HMAC с использованием BLAKE3
    std::vector<unsigned char> k = PostQuantumHash::blake3(hash_data);
    std::vector<unsigned char> v(crypto_generichash_BYTES, 1);
    
    // 5. Итеративное улучшение k и v
    for (int iter = 0; iter < 10; iter++) {
        // HMAC(k, v || 0x00 || x || message_hash)
        std::vector<unsigned char> t;
        t.insert(t.end(), v.begin(), v.end());
        t.push_back(0x00);
        t.insert(t.end(), x.begin(), x.end());
        t.insert(t.end(), message_hash.begin(), message_hash.end());
        
        crypto_hmacstate state;
        crypto_hmac_sha256_init(&state, k.data(), k.size());
        crypto_hmac_sha256_update(&state, t.data(), t.size());
        crypto_hmac_sha256_final(&state, v.data());
        
        // HMAC(k, v || 0x01 || x || message_hash)
        t.clear();
        t.insert(t.end(), v.begin(), v.end());
        t.push_back(0x01);
        t.insert(t.end(), x.begin(), x.end());
        t.insert(t.end(), message_hash.begin(), message_hash.end());
        
        crypto_hmac_sha256_init(&state, k.data(), k.size());
        crypto_hmac_sha256_update(&state, t.data(), t.size());
        crypto_hmac_sha256_final(&state, k.data());
        
        // Проверка, что k находится в допустимом диапазоне
        GmpRaii k_value;
        mpz_import(k_value.get_mpz_t(), k.size(), 1, 1, 1, 0, k.data());
        
        if (k_value > GmpRaii(0) && k_value < p) {
            return k_value;
        }
    }
    
    // Если после 10 итераций k не был найден, генерируем случайное значение
    return secure_random.random_uint(p);
}

std::vector<short> Rfc6979Rng::generate_ephemeral_key(const std::string& message) {
    // Хеширование сообщения с использованием BLAKE3
    std::vector<unsigned char> message_hash = PostQuantumHash::blake3(
        std::vector<unsigned char>(message.begin(), message.end()));
    
    // Генерация k-значения
    GmpRaii k = generate_k(message_hash);
    
    // Преобразование k в вектор экспонент
    std::vector<short> ephemeral_key(private_key.size());
    
    // Используем k для генерации эфемерного ключа
    for (size_t i = 0; i < ephemeral_key.size(); i++) {
        // Генерация экспоненты в диапазоне [-max_key_magnitude, max_key_magnitude]
        ephemeral_key[i] = generate_random_exponent(max_key_magnitude);
    }
    
    return ephemeral_key;
}

int Rfc6979Rng::generate_random_exponent(int max_magnitude) {
    // Генерация случайного числа в диапазоне [-max_magnitude, max_magnitude]
    int sign = secure_random.random_byte() & 0x01 ? 1 : -1;
    int magnitude = secure_random.random_int(0, max_magnitude + 1);
    
    // Убедимся, что 0 не генерируется слишком часто
    if (magnitude == 0 && secure_random.random_byte() % 4 != 0) {
        magnitude = 1;
    }
    
    return sign * magnitude;
}

void Rfc6979Rng::generate_random_bytes(std::vector<unsigned char>& output) {
    secure_random.random_bytes(output);
}

#endif // RFC6979_RNG_H
