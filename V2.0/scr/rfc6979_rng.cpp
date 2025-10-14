#include "rfc6979_rng.h"
#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <sodium.h>
#include "postquantum_hash.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

Rfc6979Rng::Rfc6979Rng(const GmpRaii& p, 
                       const std::vector<short>& private_key,
                       int max_key_magnitude)
    : p_(p),
      private_key_(private_key),
      max_key_magnitude_(max_key_magnitude),
      initialized_(false) {
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Rfc6979Rng initialized", false);
}

Rfc6979Rng::~Rfc6979Rng() {
    // Очистка памяти
    SecureRandom::secure_clean_memory(v_.data(), v_.size());
    SecureRandom::secure_clean_memory(k_.data(), k_.size());
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Rfc6979Rng destroyed", false);
}

GmpRaii Rfc6979Rng::generate_k(const std::vector<unsigned char>& message_hash) {
    std::lock_guard<std::mutex> lock(rng_mutex_);
    
    // Проверка, что хеш сообщения не пустой
    if (message_hash.empty()) {
        throw std::invalid_argument("Message hash cannot be empty");
    }
    
    // Получаем байтовое представление приватного ключа
    std::vector<unsigned char> private_key_bytes;
    for (const short& val : private_key_) {
        unsigned char bytes[2];
        bytes[0] = (val >> 8) & 0xFF;
        bytes[1] = val & 0xFF;
        private_key_bytes.push_back(bytes[0]);
        private_key_bytes.push_back(bytes[1]);
    }
    
    // Инициализация HMAC_DRBG
    initialize_hmac_drbg(private_key_bytes);
    
    // Создаем данные для генерации k
    std::vector<unsigned char> t;
    t.push_back(0x00);
    t.insert(t.end(), private_key_bytes.begin(), private_key_bytes.end());
    t.push_back(0x01);
    t.insert(t.end(), message_hash.begin(), message_hash.end());
    
    // Генерируем k
    GmpRaii k;
    bool found_valid_k = false;
    int retry_count = 0;
    
    while (!found_valid_k && retry_count < SecurityConstants::MAX_RFC6979_RETRIES) {
        // Генерируем случайное число
        std::vector<unsigned char> k_bytes = generate_bytes((mpz_sizeinbase(p_.get_mpz_t(), 2) + 7) / 8);
        
        // Преобразуем в GmpRaii
        mpz_import(k.get_mpz_t(), k_bytes.size(), 1, 1, 0, 0, k_bytes.data());
        
        // Проверяем, что k в допустимом диапазоне
        if (is_valid_k(k, p_)) {
            found_valid_k = true;
        } else {
            // Обновляем состояние генератора
            update_hmac_drbg(k_bytes);
            retry_count++;
        }
    }
    
    if (!found_valid_k) {
        // Если не удалось найти подходящее k, генерируем случайное значение
        SecureAuditLogger::get_instance().log_event("security",
            "RFC 6979 failed to find valid k, using fallback random value", true);
        
        std::vector<unsigned char> random_bytes = SecureRandom::generate_random_bytes(
            (mpz_sizeinbase(p_.get_mpz_t(), 2) + 7) / 8);
        mpz_import(k.get_mpz_t(), random_bytes.size(), 1, 1, 0, 0, random_bytes.data());
        k %= p_;
    }
    
    return k;
}

std::vector<short> Rfc6979Rng::generate_ephemeral_key(const std::string& message) {
    std::lock_guard<std::mutex> lock(rng_mutex_);
    
    // Хешируем сообщение
    std::vector<unsigned char> message_hash = PostQuantumHash::blake3(
        std::vector<unsigned char>(message.begin(), message.end()),
        SecurityConstants::MESSAGE_HASH_SIZE);
    
    // Генерируем k
    GmpRaii k = generate_k(message_hash);
    
    // Создаем эфемерный ключ
    std::vector<short> ephemeral_key = private_key_;
    
    // Модифицируем эфемерный ключ на основе k
    for (size_t i = 0; i < ephemeral_key.size(); i++) {
        // Используем k для модификации ключа
        int mod = mpz_fdiv_ui(k.get_mpz_t(), max_key_magnitude_ * 2 + 1);
        ephemeral_key[i] += mod - max_key_magnitude_;
        
        // Ограничиваем значение в допустимом диапазоне
        ephemeral_key[i] = std::max(-max_key_magnitude_, 
                                  std::min(max_key_magnitude_, ephemeral_key[i]));
    }
    
    return ephemeral_key;
}

int Rfc6979Rng::random_int(int min, int max) {
    std::lock_guard<std::mutex> lock(rng_mutex_);
    
    if (min >= max) {
        throw std::invalid_argument("Invalid range for random_int");
    }
    
    // Генерируем случайное число
    size_t range = max - min;
    size_t bytes_needed = (mpz_sizeinbase(GmpRaii(range).get_mpz_t(), 2) + 7) / 8;
    std::vector<unsigned char> random_bytes = generate_bytes(bytes_needed);
    
    // Преобразуем в число
    GmpRaii rand_value;
    mpz_import(rand_value.get_mpz_t(), random_bytes.size(), 1, 1, 0, 0, random_bytes.data());
    
    // Приводим к диапазону
    int result = min + (mpz_fdiv_ui(rand_value.get_mpz_t(), range));
    
    return result;
}

bool Rfc6979Rng::is_valid_k(const GmpRaii& k, const GmpRaii& p) const {
    return k > GmpRaii(0) && k < p;
}

std::vector<short> Rfc6979Rng::get_private_key() const {
    std::lock_guard<std::mutex> lock(rng_mutex_);
    return private_key_;
}

void Rfc6979Rng::initialize_hmac_drbg(const std::vector<unsigned char>& seed_seed) {
    // Размер ключа HMAC
    size_t key_size = crypto_auth_hmacsha512_KEYBYTES;
    
    // Инициализация состояния V
    v_.resize(crypto_auth_hmacsha512_BYTES);
    std::fill(v_.begin(), v_.end(), 0x01);
    
    // Инициализация состояния K
    k_.resize(key_size);
    std::fill(k_.begin(), k_.end(), 0x00);
    
    // Создаем данные для инициализации
    std::vector<unsigned char> seed;
    seed.push_back(0x00);
    seed.insert(seed.end(), seed_seed.begin(), seed_seed.end());
    
    // Обновляем состояние
    update_hmac_drbg(seed);
    
    initialized_ = true;
}

unsigned char Rfc6979Rng::generate_byte() {
    if (!initialized_) {
        throw std::runtime_error("HMAC_DRBG not initialized");
    }
    
    // Обновляем состояние
    std::vector<unsigned char> data = {0x00};
    update_hmac_drbg(data);
    
    // Генерируем байт
    std::vector<unsigned char> output;
    output.push_back(0x00);
    output.insert(output.end(), v_.begin(), v_.end());
    
    std::vector<unsigned char> hmac = PostQuantumHash::hmac_blake3(k_, output);
    
    return hmac[0];
}

std::vector<unsigned char> Rfc6979Rng::generate_bytes(size_t size) {
    std::vector<unsigned char> result;
    result.reserve(size);
    
    for (size_t i = 0; i < size; i++) {
        result.push_back(generate_byte());
    }
    
    return result;
}

void Rfc6979Rng::update_hmac_drbg(const std::vector<unsigned char>& additional_data) {
    if (!initialized_) {
        throw std::runtime_error("HMAC_DRBG not initialized");
    }
    
    // Создаем данные для обновления
    std::vector<unsigned char> data;
    data.push_back(0x00);
    data.insert(data.end(), v_.begin(), v_.end());
    
    if (!additional_data.empty()) {
        data.push_back(0x00);
        data.insert(data.end(), additional_data.begin(), additional_data.end());
    }
    
    // Вычисляем HMAC
    std::vector<unsigned char> hmac = PostQuantumHash::hmac_blake3(k_, data);
    
    // Обновляем состояние K
    k_ = PostQuantumHash::hmac_blake3(k_, hmac);
    
    // Обновляем состояние V
    for (size_t i = 0; i < v_.size(); i++) {
        v_[i] ^= hmac[i];
    }
}

} // namespace toruscsidh
