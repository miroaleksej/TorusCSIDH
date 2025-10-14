#ifndef TORUSCSIDH_POSTQUANTUM_HASH_H
#define TORUSCSIDH_POSTQUANTUM_HASH_H

#include <vector>
#include <string>
#include <gmpxx.h>
#include <sodium.h>
#include "security_constants.h"

namespace toruscsidh {

/**
 * @brief Класс для постквантового хеширования
 * 
 * Реализует постквантовые хеш-функции, безопасные против квантовых атак.
 * Включает BLAKE3, SHAKE256 и HMAC на их основе.
 */
class PostQuantumHash {
public:
    /**
     * @brief Хеширование данных с использованием BLAKE3
     * 
     * @param input Входные данные
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> blake3(const std::vector<unsigned char>& input, 
                                           size_t output_size = crypto_generichash_blake2b_BYTES);
    
    /**
     * @brief Хеширование строки с использованием BLAKE3
     * 
     * @param input Входная строка
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> blake3_string(const std::string& input, 
                                                  size_t output_size = crypto_generichash_blake2b_BYTES);
    
    /**
     * @brief Хеширование GMP числа с использованием BLAKE3
     * 
     * @param input Входное GMP число
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> blake3_gmp(const GmpRaii& input, 
                                               size_t output_size = crypto_generichash_blake2b_BYTES);
    
    /**
     * @brief Хеширование данных с использованием SHAKE256
     * 
     * @param input Входные данные
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> shake256(const std::vector<unsigned char>& input, 
                                             size_t output_size = 64);
    
    /**
     * @brief Хеширование строки с использованием SHAKE256
     * 
     * @param input Входная строка
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> shake256_string(const std::string& input, 
                                                    size_t output_size = 64);
    
    /**
     * @brief Хеширование GMP числа с использованием SHAKE256
     * 
     * @param input Входное GMP число
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> shake256_gmp(const GmpRaii& input, 
                                                 size_t output_size = 64);
    
    /**
     * @brief Вычисление HMAC с использованием BLAKE3
     * 
     * @param key Ключ HMAC
     * @param message Сообщение
     * @return HMAC значение
     */
    static std::vector<unsigned char> hmac_blake3(const std::vector<unsigned char>& key,
                                                const std::vector<unsigned char>& message);
    
    /**
     * @brief Вычисление HMAC с использованием SHAKE256
     * 
     * @param key Ключ HMAC
     * @param message Сообщение
     * @return HMAC значение
     */
    static std::vector<unsigned char> hmac_shake256(const std::vector<unsigned char>& key,
                                                  const std::vector<unsigned char>& message);
    
    /**
     * @brief Проверка HMAC с постоянным временем
     * 
     * @param expected Ожидаемое HMAC значение
     * @param actual Фактическое HMAC значение
     * @param max_time Максимальное время выполнения
     * @return true, если HMAC совпадает
     */
    static bool verify_hmac_constant_time(const std::vector<unsigned char>& expected,
                                        const std::vector<unsigned char>& actual,
                                        const std::chrono::microseconds& max_time);
    
    /**
     * @brief Генерация ключа с использованием HKDF
     * 
     * @param ikm Входной ключевой материал
     * @param salt Соль
     * @param info Информационная строка
     * @param output_size Размер выхода
     * @return Сгенерированный ключ
     */
    static std::vector<unsigned char> hkdf(const std::vector<unsigned char>& ikm,
                                         const std::vector<unsigned char>& salt,
                                         const std::string& info,
                                         size_t output_size);
    
    /**
     * @brief Генерация ключа с использованием HKDF-SHAKE256
     * 
     * @param ikm Входной ключевой материал
     * @param salt Соль
     * @param info Информационная строка
     * @param output_size Размер выхода
     * @return Сгенерированный ключ
     */
    static std::vector<unsigned char> hkdf_shake256(const std::vector<unsigned char>& ikm,
                                                  const std::vector<unsigned char>& salt,
                                                  const std::string& info,
                                                  size_t output_size);
    
    /**
     * @brief Генерация ключа с использованием HKDF-BLAKE3
     * 
     * @param ikm Входной ключевой материал
     * @param salt Соль
     * @param info Информационная строка
     * @param output_size Размер выхода
     * @return Сгенерированный ключ
     */
    static std::vector<unsigned char> hkdf_blake3(const std::vector<unsigned char>& ikm,
                                                const std::vector<unsigned char>& salt,
                                                const std::string& info,
                                                size_t output_size);
    
    /**
     * @brief Проверка, что хеш соответствует постквантовым требованиям
     * 
     * @param hash Хеш для проверки
     * @return true, если хеш соответствует требованиям
     */
    static bool is_postquantum_hash(const std::vector<unsigned char>& hash);
    
    /**
     * @brief Проверка, что HMAC соответствует постквантовым требованиям
     * 
     * @param hmac HMAC для проверки
     * @return true, если HMAC соответствует требованиям
     */
    static bool is_postquantum_hmac(const std::vector<unsigned char>& hmac);
    
    /**
     * @brief Вычисление хеш-суммы для строки
     * 
     * @param input Входная строка
     * @param output_size Размер выхода
     * @return Хеш-сумма
     */
    static std::vector<unsigned char> hash_string(const std::string& input, 
                                                size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Вычисление хеш-суммы для данных
     * 
     * @param input Входные данные
     * @param output_size Размер выхода
     * @return Хеш-сумма
     */
    static std::vector<unsigned char> hash(const std::vector<unsigned char>& input, 
                                         size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Вычисление хеш-суммы для GMP числа
     * 
     * @param input Входное GMP число
     * @param output_size Размер выхода
     * @return Хеш-сумма
     */
    static std::vector<unsigned char> hash_gmp(const GmpRaii& input, 
                                             size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Проверка, что хеш имеет достаточную длину для постквантовой безопасности
     * 
     * @param hash Хеш для проверки
     * @param security_level Уровень безопасности
     * @return true, если хеш имеет достаточную длину
     */
    static bool has_sufficient_length(const std::vector<unsigned char>& hash,
                                    SecurityConstants::SecurityLevel security_level);
    
    /**
     * @brief Вычисление хеша для последовательности данных
     * 
     * @param inputs Последовательность входных данных
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> hash_sequence(const std::vector<std::vector<unsigned char>>& inputs,
                                                  size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Вычисление хеша для комбинации данных
     * 
     * @param inputs Последовательность входных данных
     * @param output_size Размер выхода
     * @return Хеш-значение
     */
    static std::vector<unsigned char> hash_combination(const std::vector<std::vector<unsigned char>>& inputs,
                                                     size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Проверка, что хеш является криптографически безопасным
     * 
     * @param hash Хеш для проверки
     * @return true, если хеш является криптографически безопасным
     */
    static bool is_crypto_secure(const std::vector<unsigned char>& hash);
    
    /**
     * @brief Проверка, что HMAC является криптографически безопасным
     * 
     * @param hmac HMAC для проверки
     * @return true, если HMAC является криптографически безопасным
     */
    static bool is_hmac_crypto_secure(const std::vector<unsigned char>& hmac);
    
private:
    /**
     * @brief Вычисление HMAC с использованием указанной хеш-функции
     * 
     * @param hash_func Функция хеширования
     * @param key Ключ HMAC
     * @param message Сообщение
     * @return HMAC значение
     */
    static std::vector<unsigned char> compute_hmac(
        std::function<std::vector<unsigned char>(const std::vector<unsigned char>&, size_t)> hash_func,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& message);
    
    /**
     * @brief Проверка HMAC с постоянным временем
     * 
     * @param expected Ожидаемое HMAC значение
     * @param actual Фактическое HMAC значение
     * @return true, если HMAC совпадает
     */
    static bool constant_time_compare(const std::vector<unsigned char>& expected,
                                    const std::vector<unsigned char>& actual);
};

} // namespace toruscsidh

#endif // TORUSCSIDH_POSTQUANTUM_HASH_H
