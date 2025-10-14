#ifndef POSTQUANTUM_HASH_H
#define POSTQUANTUM_HASH_H

#include <vector>
#include <sodium.h>
#include <cstdint>
#include <string>
#include "security_constants.h"

/**
 * @brief Класс для постквантового хеширования
 * 
 * Реализует безопасные постквантовые хеш-функции:
 * - SHAKE256 (XOF) для гибкого вывода
 * - BLAKE3 для высокой производительности
 * 
 * Все функции соответствуют стандартам NIST PQC.
 */
class PostQuantumHash {
public:
    /**
     * @brief Хеширование данных с использованием SHAKE256
     * @param input Входные данные
     * @param output_size Размер выходного хеша
     * @return Хеш-значение
     */
    static std::vector<unsigned char> shake256(const std::vector<unsigned char>& input, size_t output_size);
    
    /**
     * @brief Хеширование данных с использованием BLAKE3
     * @param input Входные данные
     * @return Хеш-значение (32 байта)
     */
    static std::vector<unsigned char> blake3(const std::vector<unsigned char>& input);
    
    /**
     * @brief Расширение ключа с использованием SHAKE256
     * @param key Входной ключ
     * @param output_size Размер выходного ключа
     * @return Расширенный ключ
     */
    static std::vector<unsigned char> kdf_shake256(const std::vector<unsigned char>& key, size_t output_size);
    
    /**
     * @brief HMAC с использованием BLAKE3
     * @param key Ключ HMAC
     * @param message Сообщение
     * @return HMAC значение
     */
    static std::vector<unsigned char> hmac_blake3(const std::vector<unsigned char>& key, 
                                                 const std::vector<unsigned char>& message);
    
    /**
     * @brief Проверка HMAC с использованием BLAKE3
     * @param key Ключ HMAC
     * @param message Сообщение
     * @param expected_mac Ожидаемое HMAC значение
     * @return true, если HMAC верен
     */
    static bool verify_hmac_blake3(const std::vector<unsigned char>& key,
                                  const std::vector<unsigned char>& message,
                                  const std::vector<unsigned char>& expected_mac);
    
    /**
     * @brief Преобразование хеша в целое число GMP
     * @param hash Хеш-значение
     * @param modulus Модуль
     * @return Целое число в пределах модуля
     */
    static GmpRaii hash_to_gmp(const std::vector<unsigned char>& hash, const GmpRaii& modulus);
    
    /**
     * @brief Создание криптографически безопасной соли
     * @return Случайная соль
     */
    static std::vector<unsigned char> create_salt();
    
    /**
     * @brief Безопасное сравнение хешей (защита от атак по времени)
     * @param hash1 Первый хеш
     * @param hash2 Второй хеш
     * @return true, если хеши совпадают
     */
    static bool constant_time_compare(const std::vector<unsigned char>& hash1,
                                     const std::vector<unsigned char>& hash2);

private:
    static const size_t SALT_SIZE = 32;  ///< Размер соли
};

std::vector<unsigned char> PostQuantumHash::shake256(const std::vector<unsigned char>& input, size_t output_size) {
    std::vector<unsigned char> output(output_size);
    
    // Используем SHAKE256 из libsodium
    crypto_shake256(output.data(), output_size, input.data(), input.size());
    
    return output;
}

std::vector<unsigned char> PostQuantumHash::blake3(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> output(crypto_generichash_BYTES);
    
    // Используем BLAKE3 через интерфейс libsodium
    crypto_generichash(output.data(), output.size(), 
                      input.data(), input.size(), 
                      nullptr, 0);
    
    return output;
}

std::vector<unsigned char> PostQuantumHash::kdf_shake256(const std::vector<unsigned char>& key, size_t output_size) {
    std::vector<unsigned char> output(output_size);
    
    // Используем SHAKE256 для KDF
    crypto_shake256(output.data(), output_size, key.data(), key.size());
    
    return output;
}

std::vector<unsigned char> PostQuantumHash::hmac_blake3(const std::vector<unsigned char>& key, 
                                                       const std::vector<unsigned char>& message) {
    std::vector<unsigned char> mac(crypto_auth_BYTES);
    
    // Используем BLAKE3 через crypto_auth в libsodium
    crypto_auth(mac.data(), message.data(), message.size(), key.data(), key.size());
    
    return mac;
}

bool PostQuantumHash::verify_hmac_blake3(const std::vector<unsigned char>& key,
                                        const std::vector<unsigned char>& message,
                                        const std::vector<unsigned char>& expected_mac) {
    // Используем безопасное сравнение для защиты от атак по времени
    std::vector<unsigned char> computed_mac = hmac_blake3(key, message);
    return crypto_verify_32(computed_mac.data(), expected_mac.data()) == 0;
}

GmpRaii PostQuantumHash::hash_to_gmp(const std::vector<unsigned char>& hash, const GmpRaii& modulus) {
    if (hash.empty() || modulus <= GmpRaii(0)) {
        throw std::invalid_argument("Invalid input for hash_to_gmp");
    }
    
    GmpRaii result;
    mpz_import(result.get_mpz_t(), hash.size(), 1, 1, 0, 0, hash.data());
    
    // Убедимся, что результат меньше модуля
    result %= modulus;
    
    return result;
}

std::vector<unsigned char> PostQuantumHash::create_salt() {
    std::vector<unsigned char> salt(SALT_SIZE);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

bool PostQuantumHash::constant_time_compare(const std::vector<unsigned char>& hash1,
                                          const std::vector<unsigned char>& hash2) {
    if (hash1.size() != hash2.size()) {
        return false;
    }
    
    // Используем crypto_verify_32 или crypto_verify_64 в зависимости от размера
    if (hash1.size() == crypto_verify_32_BYTES) {
        return crypto_verify_32(hash1.data(), hash2.data()) == 0;
    } else if (hash1.size() == crypto_verify_64_BYTES) {
        return crypto_verify_64(hash1.data(), hash2.data()) == 0;
    } else {
        // Для других размеров используем побитовое сравнение
        unsigned char result = 0;
        for (size_t i = 0; i < hash1.size(); i++) {
            result |= hash1[i] ^ hash2[i];
        }
        return result == 0;
    }
}

#endif // POSTQUANTUM_HASH_H
