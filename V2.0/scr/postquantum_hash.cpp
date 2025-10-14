#include "postquantum_hash.h"
#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <sodium.h>
#include <chrono>
#include <algorithm>
#include "secure_audit_logger.h"
#include "secure_random.h"

namespace toruscsidh {

std::vector<unsigned char> PostQuantumHash::blake3(const std::vector<unsigned char>& input, 
                                                 size_t output_size) {
    // Проверка входных данных
    if (output_size == 0) {
        throw std::invalid_argument("Output size must be greater than 0");
    }
    
    // Инициализация BLAKE3
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    
    // Обновление хеш-состояния
    blake3_hasher_update(&hasher, input.data(), input.size());
    
    // Получение хеш-результата
    std::vector<unsigned char> output(output_size);
    blake3_hasher_finalize(&hasher, output.data(), output_size);
    
    return output;
}

std::vector<unsigned char> PostQuantumHash::blake3_string(const std::string& input, 
                                                        size_t output_size) {
    return blake3(std::vector<unsigned char>(input.begin(), input.end()), output_size);
}

std::vector<unsigned char> PostQuantumHash::blake3_gmp(const GmpRaii& input, 
                                                    size_t output_size) {
    // Преобразование GMP числа в байтовый массив
    size_t size = (mpz_sizeinbase(input.get_mpz_t(), 2) + 7) / 8;
    std::vector<unsigned char> bytes(size);
    mpz_export(bytes.data(), nullptr, 1, 1, 0, 0, input.get_mpz_t());
    
    return blake3(bytes, output_size);
}

std::vector<unsigned char> PostQuantumHash::shake256(const std::vector<unsigned char>& input, 
                                                   size_t output_size) {
    // Проверка входных данных
    if (output_size == 0) {
        throw std::invalid_argument("Output size must be greater than 0");
    }
    
    // Инициализация SHAKE256
    crypto_shake256_state state;
    crypto_shake256_init(&state);
    
    // Обновление состояния
    crypto_shake256_update(&state, input.data(), input.size());
    
    // Получение результата
    std::vector<unsigned char> output(output_size);
    crypto_shake256_final(&state, output.data(), output_size);
    
    return output;
}

std::vector<unsigned char> PostQuantumHash::shake256_string(const std::string& input, 
                                                         size_t output_size) {
    return shake256(std::vector<unsigned char>(input.begin(), input.end()), output_size);
}

std::vector<unsigned char> PostQuantumHash::shake256_gmp(const GmpRaii& input, 
                                                      size_t output_size) {
    // Преобразование GMP числа в байтовый массив
    size_t size = (mpz_sizeinbase(input.get_mpz_t(), 2) + 7) / 8;
    std::vector<unsigned char> bytes(size);
    mpz_export(bytes.data(), nullptr, 1, 1, 0, 0, input.get_mpz_t());
    
    return shake256(bytes, output_size);
}

std::vector<unsigned char> PostQuantumHash::hmac_blake3(const std::vector<unsigned char>& key,
                                                     const std::vector<unsigned char>& message) {
    // Проверка входных данных
    if (key.empty()) {
        throw std::invalid_argument("HMAC key cannot be empty");
    }
    
    // Используем BLAKE3 для HMAC
    return crypto_auth_hmacsha512_state::hmac_blake3(key, message);
}

std::vector<unsigned char> PostQuantumHash::hmac_shake256(const std::vector<unsigned char>& key,
                                                       const std::vector<unsigned char>& message) {
    // Проверка входных данных
    if (key.empty()) {
        throw std::invalid_argument("HMAC key cannot be empty");
    }
    
    // Используем SHAKE256 для HMAC
    return crypto_auth_hmacsha512_state::hmac_shake256(key, message);
}

bool PostQuantumHash::verify_hmac_constant_time(const std::vector<unsigned char>& expected,
                                             const std::vector<unsigned char>& actual,
                                             const std::chrono::microseconds& max_time) {
    // Проверка, что размеры совпадают
    if (expected.size() != actual.size()) {
        return false;
    }
    
    // Выполнение сравнения за постоянное время
    unsigned char result = 0;
    size_t length = expected.size();
    
    // Начало измерения времени
    auto start = std::chrono::high_resolution_clock::now();
    
    // Сравнение байт
    for (size_t i = 0; i < length; i++) {
        result |= expected[i] ^ actual[i];
    }
    
    // Проверка времени выполнения
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    if (elapsed < max_time) {
        // Добавляем задержку для обеспечения постоянного времени
        std::this_thread::sleep_for(max_time - elapsed);
    }
    
    return result == 0;
}

std::vector<unsigned char> PostQuantumHash::hkdf(const std::vector<unsigned char>& ikm,
                                              const std::vector<unsigned char>& salt,
                                              const std::string& info,
                                              size_t output_size) {
    // Проверка входных данных
    if (ikm.empty()) {
        throw std::invalid_argument("IKM cannot be empty");
    }
    
    if (output_size == 0) {
        throw std::invalid_argument("Output size must be greater than 0");
    }
    
    // Используем BLAKE3 для HKDF
    return hkdf_blake3(ikm, salt, info, output_size);
}

std::vector<unsigned char> PostQuantumHash::hkdf_shake256(const std::vector<unsigned char>& ikm,
                                                       const std::vector<unsigned char>& salt,
                                                       const std::string& info,
                                                       size_t output_size) {
    // Проверка входных данных
    if (ikm.empty()) {
        throw std::invalid_argument("IKM cannot be empty");
    }
    
    if (output_size == 0) {
        throw std::invalid_argument("Output size must be greater than 0");
    }
    
    // Шаг 1: Извлечение
    std::vector<unsigned char> prk = hmac_shake256(salt.empty() ? 
                                                  std::vector<unsigned char>(crypto_auth_hmacsha512_KEYBYTES, 0) : salt, 
                                                  ikm);
    
    // Шаг 2: Расширение
    std::vector<unsigned char> output;
    unsigned char counter = 1;
    
    while (output.size() < output_size) {
        std::vector<unsigned char> input;
        
        // Добавляем предыдущий результат (если есть)
        if (!output.empty()) {
            input.insert(input.end(), output.end() - crypto_auth_hmacsha512_BYTES, output.end());
        }
        
        // Добавляем информацию
        input.insert(input.end(), info.begin(), info.end());
        
        // Добавляем счетчик
        input.push_back(counter);
        
        // Вычисляем HMAC
        std::vector<unsigned char> step = hmac_shake256(prk, input);
        output.insert(output.end(), step.begin(), step.end());
        
        counter++;
    }
    
    // Обрезаем до нужного размера
    output.resize(output_size);
    
    return output;
}

std::vector<unsigned char> PostQuantumHash::hkdf_blake3(const std::vector<unsigned char>& ikm,
                                                     const std::vector<unsigned char>& salt,
                                                     const std::string& info,
                                                     size_t output_size) {
    // Проверка входных данных
    if (ikm.empty()) {
        throw std::invalid_argument("IKM cannot be empty");
    }
    
    if (output_size == 0) {
        throw std::invalid_argument("Output size must be greater than 0");
    }
    
    // Шаг 1: Извлечение
    std::vector<unsigned char> prk = hmac_blake3(salt.empty() ? 
                                               std::vector<unsigned char>(crypto_auth_hmacsha512_KEYBYTES, 0) : salt, 
                                               ikm);
    
    // Шаг 2: Расширение
    std::vector<unsigned char> output;
    unsigned char counter = 1;
    
    while (output.size() < output_size) {
        std::vector<unsigned char> input;
        
        // Добавляем предыдущий результат (если есть)
        if (!output.empty()) {
            input.insert(input.end(), output.end() - crypto_auth_hmacsha512_BYTES, output.end());
        }
        
        // Добавляем информацию
        input.insert(input.end(), info.begin(), info.end());
        
        // Добавляем счетчик
        input.push_back(counter);
        
        // Вычисляем HMAC
        std::vector<unsigned char> step = hmac_blake3(prk, input);
        output.insert(output.end(), step.begin(), step.end());
        
        counter++;
    }
    
    // Обрезаем до нужного размера
    output.resize(output_size);
    
    return output;
}

bool PostQuantumHash::is_postquantum_hash(const std::vector<unsigned char>& hash) {
    // Проверка, что хеш имеет достаточную длину для постквантовой безопасности
    return hash.size() >= SecurityConstants::MIN_POSTQUANTUM_HASH_SIZE;
}

bool PostQuantumHash::is_postquantum_hmac(const std::vector<unsigned char>& hmac) {
    // Проверка, что HMAC имеет достаточную длину для постквантовой безопасности
    return hmac.size() >= SecurityConstants::MIN_POSTQUANTUM_HMAC_SIZE;
}

std::vector<unsigned char> PostQuantumHash::hash_string(const std::string& input, 
                                                     size_t output_size) {
    // Используем BLAKE3 для хеширования строк
    return blake3_string(input, output_size);
}

std::vector<unsigned char> PostQuantumHash::hash(const std::vector<unsigned char>& input, 
                                              size_t output_size) {
    // Используем BLAKE3 для хеширования данных
    return blake3(input, output_size);
}

std::vector<unsigned char> PostQuantumHash::hash_gmp(const GmpRaii& input, 
                                                  size_t output_size) {
    // Используем BLAKE3 для хеширования GMP чисел
    return blake3_gmp(input, output_size);
}

bool PostQuantumHash::has_sufficient_length(const std::vector<unsigned char>& hash,
                                         SecurityConstants::SecurityLevel security_level) {
    // Проверка достаточной длины хеша для заданного уровня безопасности
    size_t required_length = 0;
    
    switch (security_level) {
        case SecurityConstants::LEVEL_128:
            required_length = 32; // 256 бит для 128-битной безопасности против квантовых атак
            break;
        case SecurityConstants::LEVEL_192:
            required_length = 48; // 384 бит для 192-битной безопасности против квантовых атак
            break;
        case SecurityConstants::LEVEL_256:
            required_length = 64; // 512 бит для 256-битной безопасности против квантовых атак
            break;
        default:
            required_length = 32; // По умолчанию 128-битная безопасность
    }
    
    return hash.size() >= required_length;
}

std::vector<unsigned char> PostQuantumHash::hash_sequence(const std::vector<std::vector<unsigned char>>& inputs,
                                                       size_t output_size) {
    // Хеширование последовательности данных
    std::vector<unsigned char> concatenated;
    
    for (const auto& input : inputs) {
        concatenated.insert(concatenated.end(), input.begin(), input.end());
    }
    
    return hash(concatenated, output_size);
}

std::vector<unsigned char> PostQuantumHash::hash_combination(const std::vector<std::vector<unsigned char>>& inputs,
                                                          size_t output_size) {
    // Хеширование комбинации данных с использованием дерева Меркла
    if (inputs.empty()) {
        return std::vector<unsigned char>();
    }
    
    if (inputs.size() == 1) {
        return hash(inputs[0], output_size);
    }
    
    // Строим дерево Меркла
    std::vector<std::vector<unsigned char>> current_level = inputs;
    
    while (current_level.size() > 1) {
        std::vector<std::vector<unsigned char>> next_level;
        
        for (size_t i = 0; i < current_level.size(); i += 2) {
            if (i + 1 < current_level.size()) {
                // Хешируем пару
                std::vector<unsigned char> combined;
                combined.insert(combined.end(), current_level[i].begin(), current_level[i].end());
                combined.insert(combined.end(), current_level[i + 1].begin(), current_level[i + 1].end());
                next_level.push_back(hash(combined, output_size));
            } else {
                // Если остался один элемент, просто добавляем его
                next_level.push_back(current_level[i]);
            }
        }
        
        current_level = next_level;
    }
    
    return current_level[0];
}

bool PostQuantumHash::is_crypto_secure(const std::vector<unsigned char>& hash) {
    // Проверка криптографической безопасности хеша
    // Проверяем, что хеш не содержит слабых последовательностей
    
    // Проверка на постоянные байты
    bool all_same = true;
    for (size_t i = 1; i < hash.size(); i++) {
        if (hash[i] != hash[0]) {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        return false;
    }
    
    // Проверка на регулярные паттерны
    for (size_t i = 0; i < hash.size() - 1; i++) {
        if (hash[i] == hash[i + 1] && hash[i] == hash[i + 2] && hash[i] == hash[i + 3]) {
            return false; // Слишком много повторяющихся байтов
        }
    }
    
    return true;
}

bool PostQuantumHash::is_hmac_crypto_secure(const std::vector<unsigned char>& hmac) {
    return is_crypto_secure(hmac);
}

std::vector<unsigned char> PostQuantumHash::compute_hmac(
    std::function<std::vector<unsigned char>(const std::vector<unsigned char>&, size_t)> hash_func,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& message) {
    
    // Проверка входных данных
    if (key.empty()) {
        throw std::invalid_argument("HMAC key cannot be empty");
    }
    
    // Размер блока
    const size_t block_size = 64;
    
    // Подготовка ключа
    std::vector<unsigned char> key_padded(block_size, 0);
    
    if (key.size() > block_size) {
        std::vector<unsigned char> key_hashed = hash_func(key, block_size);
        std::copy(key_hashed.begin(), key_hashed.end(), key_padded.begin());
    } else {
        std::copy(key.begin(), key.end(), key_padded.begin());
    }
    
    // Создание ipad и opad
    std::vector<unsigned char> ipad(block_size, 0x36);
    std::vector<unsigned char> opad(block_size, 0x5c);
    
    for (size_t i = 0; i < block_size; i++) {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }
    
    // Вычисление HMAC
    std::vector<unsigned char> inner_input;
    inner_input.insert(inner_input.end(), ipad.begin(), ipad.end());
    inner_input.insert(inner_input.end(), message.begin(), message.end());
    std::vector<unsigned char> inner_hash = hash_func(inner_input, block_size);
    
    std::vector<unsigned char> outer_input;
    outer_input.insert(outer_input.end(), opad.begin(), opad.end());
    outer_input.insert(outer_input.end(), inner_hash.begin(), inner_hash.end());
    
    return hash_func(outer_input, block_size);
}

bool PostQuantumHash::constant_time_compare(const std::vector<unsigned char>& expected,
                                         const std::vector<unsigned char>& actual) {
    // Проверка, что размеры совпадают
    if (expected.size() != actual.size()) {
        return false;
    }
    
    // Выполнение сравнения за постоянное время
    unsigned char result = 0;
    size_t length = expected.size();
    
    for (size_t i = 0; i < length; i++) {
        result |= expected[i] ^ actual[i];
    }
    
    return result == 0;
}

namespace crypto_auth_hmacsha512_state {
    
    std::vector<unsigned char> hmac_blake3(const std::vector<unsigned char>& key,
                                         const std::vector<unsigned char>& message) {
        // Реализация HMAC-BLAKE3
        // BLAKE3 не имеет встроенного HMAC, поэтому используем стандартную конструкцию HMAC
        
        // Размер блока для BLAKE3
        const size_t block_size = 64;
        
        // Подготовка ключа
        std::vector<unsigned char> key_padded(block_size, 0);
        
        if (key.size() > block_size) {
            std::vector<unsigned char> key_hashed = PostQuantumHash::blake3(key, block_size);
            std::copy(key_hashed.begin(), key_hashed.end(), key_padded.begin());
        } else {
            std::copy(key.begin(), key.end(), key_padded.begin());
        }
        
        // Создание ipad и opad
        std::vector<unsigned char> ipad(block_size, 0x36);
        std::vector<unsigned char> opad(block_size, 0x5c);
        
        for (size_t i = 0; i < block_size; i++) {
            ipad[i] ^= key_padded[i];
            opad[i] ^= key_padded[i];
        }
        
        // Вычисление HMAC
        std::vector<unsigned char> inner_input;
        inner_input.insert(inner_input.end(), ipad.begin(), ipad.end());
        inner_input.insert(inner_input.end(), message.begin(), message.end());
        std::vector<unsigned char> inner_hash = PostQuantumHash::blake3(inner_input, block_size);
        
        std::vector<unsigned char> outer_input;
        outer_input.insert(outer_input.end(), opad.begin(), opad.end());
        outer_input.insert(outer_input.end(), inner_hash.begin(), inner_hash.end());
        
        return PostQuantumHash::blake3(outer_input, crypto_auth_hmacsha512_BYTES);
    }
    
    std::vector<unsigned char> hmac_shake256(const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& message) {
        // Реализация HMAC-SHAKE256
        
        // Размер блока для SHAKE256
        const size_t block_size = 136;
        
        // Подготовка ключа
        std::vector<unsigned char> key_padded(block_size, 0);
        
        if (key.size() > block_size) {
            std::vector<unsigned char> key_hashed = PostQuantumHash::shake256(key, block_size);
            std::copy(key_hashed.begin(), key_hashed.end(), key_padded.begin());
        } else {
            std::copy(key.begin(), key.end(), key_padded.begin());
        }
        
        // Создание ipad и opad
        std::vector<unsigned char> ipad(block_size, 0x36);
        std::vector<unsigned char> opad(block_size, 0x5c);
        
        for (size_t i = 0; i < block_size; i++) {
            ipad[i] ^= key_padded[i];
            opad[i] ^= key_padded[i];
        }
        
        // Вычисление HMAC
        std::vector<unsigned char> inner_input;
        inner_input.insert(inner_input.end(), ipad.begin(), ipad.end());
        inner_input.insert(inner_input.end(), message.begin(), message.end());
        std::vector<unsigned char> inner_hash = PostQuantumHash::shake256(inner_input, block_size);
        
        std::vector<unsigned char> outer_input;
        outer_input.insert(outer_input.end(), opad.begin(), opad.end());
        outer_input.insert(outer_input.end(), inner_hash.begin(), inner_hash.end());
        
        return PostQuantumHash::shake256(outer_input, crypto_auth_hmacsha512_BYTES);
    }
    
} // namespace crypto_auth_hmacsha512_state

} // namespace toruscsidh
