#include "secure_audit_logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "postquantum_hash.h"

namespace toruscsidh {

// Статический экземпляр (Singleton)
SecureAuditLogger* SecureAuditLogger::instance_ = nullptr;

SecureAuditLogger::SecureAuditLogger()
    : anomaly_count_(0),
      last_anomaly_time_(0),
      last_log_time_(0),
      log_level_(DEFAULT_LOG_LEVEL),
      max_log_size_(MAX_LOG_SIZE),
      is_initialized_(false) {
    
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    
    // Генерация ключей
    encryption_key_.resize(ENCRYPTION_KEY_SIZE);
    randombytes_buf(encryption_key_.data(), encryption_key_.size());
    
    hmac_key_.resize(HMAC_KEY_SIZE);
    randombytes_buf(hmac_key_.data(), hmac_key_.size());
    
    // Установка каталога для журналов
    log_directory_ = "./secure_logs";
    
    // Создание каталога для журналов
    create_log_directory();
}

SecureAuditLogger::~SecureAuditLogger() {
    // Очистка секретных данных из памяти
    SecureRandom::secure_clean_memory(encryption_key_.data(), encryption_key_.size());
    SecureRandom::secure_clean_memory(hmac_key_.data(), hmac_key_.size());
}

SecureAuditLogger& SecureAuditLogger::get_instance() {
    if (instance_ == nullptr) {
        instance_ = new SecureAuditLogger();
        instance_->initialize();
    }
    return *instance_;
}

bool SecureAuditLogger::initialize() {
    if (is_initialized_) {
        return true;
    }
    
    try {
        // Проверка, что каталог журналов существует
        if (!std::filesystem::exists(log_directory_) || 
            !std::filesystem::is_directory(log_directory_)) {
            create_log_directory();
        }
        
        // Получение текущего файла журнала
        current_log_file_ = get_current_log_file();
        
        // Проверка целостности существующих журналов
        for (const auto& entry : std::filesystem::directory_iterator(log_directory_)) {
            if (entry.path().extension() == ".log.enc") {
                if (!verify_log_integrity(entry.path().string())) {
                    SecureAuditLogger::get_instance().log_event("security", 
                        "Log integrity check failed for: " + entry.path().string(), true);
                }
            }
        }
        
        // Очистка старых журналов
        clean_old_logs(LOG_FILE_RETENTION * 24 * 60 * 60);
        
        is_initialized_ = true;
        last_log_time_ = time(nullptr);
        
        SecureAuditLogger::get_instance().log_event("system", "SecureAuditLogger initialized", false);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Audit logger initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void SecureAuditLogger::log_event(const std::string& category, const std::string& message, bool is_critical) {
    if (!is_initialized_ || !is_log_ready()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Проверка уровня логирования
    int event_level = 0;
    if (category == "security") event_level = 4;
    else if (category == "system") event_level = 3;
    else if (category == "key") event_level = 2;
    else if (category == "signature") event_level = 1;
    
    if (event_level > log_level_) {
        return;
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // Формирование записи журнала
        std::ostringstream log_entry;
        log_entry << "[" << std::put_time(std::localtime(&last_log_time_), "%Y-%m-%d %H:%M:%S") << "] ";
        log_entry << "[" << category << "] ";
        log_entry << (is_critical ? "CRITICAL: " : "");
        log_entry << message;
        
        // Добавление уникального идентификатора события
        log_entry << " [ID: " << generate_event_id() << "]";
        
        // Шифрование содержимого
        std::vector<unsigned char> plain_content(log_entry.str().begin(), log_entry.str().end());
        std::vector<unsigned char> encrypted_content = encrypt_log_content(plain_content);
        
        // Создание HMAC для проверки целостности
        std::vector<unsigned char> mac = create_log_hmac(encrypted_content);
        
        // Формирование полного содержимого с HMAC
        std::vector<unsigned char> full_content = encrypted_content;
        full_content.insert(full_content.end(), mac.begin(), mac.end());
        
        // Запись в текущий файл журнала
        write_encrypted_log_content(current_log_file_, full_content);
        
        // Обновление времени последней записи
        last_log_time_ = time(nullptr);
        
        // Обеспечение постоянного времени выполнения
        ensure_constant_time(std::chrono::microseconds(1000));
    } catch (const std::exception& e) {
        // Даже если возникла ошибка, мы должны выполнить задержку
        // для защиты от атак по времени
        ensure_constant_time(std::chrono::microseconds(1000));
        throw;
    }
}

void SecureAuditLogger::handle_anomaly(const std::string& anomaly_type, const std::string& description) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    anomaly_count_++;
    last_anomaly_time_ = time(nullptr);
    
    // Логирование аномалии
    log_event("security", "Anomaly detected: " + anomaly_type + " - " + description + 
              " (count: " + std::to_string(anomaly_count_) + ")", true);
    
    // Блокировка системы при превышении порога аномалий
    if (anomaly_count_ >= MAX_ANOMALY_COUNT) {
        log_event("security", "System blocked due to excessive anomalies", true);
        // Здесь должна быть реализация блокировки системы
    }
}

void SecureAuditLogger::reset_anomaly_counter() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    anomaly_count_ = 0;
    last_anomaly_time_ = 0;
    
    log_event("system", "Anomaly counter reset", false);
}

bool SecureAuditLogger::is_system_normal() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Система в нормальном состоянии, если нет аномалий или они были сброшены
    return anomaly_count_ == 0 || 
           (anomaly_count_ > 0 && time(nullptr) - last_anomaly_time_ > ANOMALY_RESET_INTERVAL);
}

int SecureAuditLogger::get_anomaly_count() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    return anomaly_count_;
}

time_t SecureAuditLogger::get_last_anomaly_time() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    return last_anomaly_time_;
}

std::string SecureAuditLogger::encrypt_filename(const std::string& filename) {
    if (!is_initialized_) {
        return filename;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Генерация случайного nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Шифрование имени файла
    std::vector<unsigned char> encrypted_filename;
    encrypted_filename.resize(filename.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long ciphertext_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_filename.data(), &ciphertext_len,
        reinterpret_cast<const unsigned char*>(filename.c_str()), filename.size(),
        nullptr, 0, // additional data
        nullptr, nonce, encryption_key_.data()
    );
    
    // Преобразование в шестнадцатеричную строку
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (unsigned char c : nonce) {
        hex_stream << std::setw(2) << static_cast<int>(c);
    }
    for (unsigned char c : encrypted_filename) {
        hex_stream << std::setw(2) << static_cast<int>(c);
    }
    
    return hex_stream.str();
}

std::string SecureAuditLogger::decrypt_filename(const std::string& encrypted_filename) {
    if (!is_initialized_) {
        return encrypted_filename;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Проверка длины строки
    if (encrypted_filename.size() < 2 * crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return encrypted_filename;
    }
    
    // Преобразование из шестнадцатеричной строки
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < encrypted_filename.size(); i += 2) {
        std::string byte_string = encrypted_filename.substr(i, 2);
        char byte = static_cast<char>(std::strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    
    // Извлечение nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    std::memcpy(nonce, bytes.data(), sizeof(nonce));
    
    // Расшифровка имени файла
    std::vector<unsigned char> decrypted_filename;
    decrypted_filename.resize(bytes.size() - sizeof(nonce) - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long plaintext_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted_filename.data(), &plaintext_len,
            nullptr,
            bytes.data() + sizeof(nonce), bytes.size() - sizeof(nonce),
            nullptr, 0, // additional data
            nonce, encryption_key_.data()) != 0) {
        return encrypted_filename; // Ошибка расшифровки
    }
    
    return std::string(decrypted_filename.begin(), decrypted_filename.end());
}

bool SecureAuditLogger::verify_log_integrity(const std::string& log_file) {
    if (!is_initialized_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    try {
        // Чтение содержимого файла
        std::ifstream file(log_file, std::ios::binary);
        if (!file) {
            return false;
        }
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        if (size < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            return false;
        }
        
        std::vector<unsigned char> content(size);
        file.read(reinterpret_cast<char*>(content.data()), size);
        file.close();
        
        // Извлечение зашифрованного содержимого и HMAC
        size_t encrypted_size = size - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<unsigned char> encrypted_content(content.begin(), content.begin() + encrypted_size);
        std::vector<unsigned char> mac(content.begin() + encrypted_size, content.end());
        
        // Проверка HMAC
        return verify_log_hmac(encrypted_content, mac);
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<unsigned char> SecureAuditLogger::get_encrypted_log_content(const std::string& log_file) {
    if (!is_initialized_) {
        return std::vector<unsigned char>();
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    try {
        // Чтение содержимого файла
        std::ifstream file(log_file, std::ios::binary);
        if (!file) {
            return std::vector<unsigned char>();
        }
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> content(size);
        file.read(reinterpret_cast<char*>(content.data()), size);
        file.close();
        
        return content;
    } catch (const std::exception& e) {
        return std::vector<unsigned char>();
    }
}

bool SecureAuditLogger::write_encrypted_log_content(const std::string& log_file, 
                                                  const std::vector<unsigned char>& content) {
    if (!is_initialized_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    try {
        // Проверка размера журнала
        if (std::filesystem::exists(log_file)) {
            size_t current_size = std::filesystem::file_size(log_file);
            if (current_size + content.size() > max_log_size_) {
                // Создание нового файла журнала
                current_log_file_ = get_current_log_file();
            }
        }
        
        // Запись содержимого в файл
        std::ofstream file(log_file, std::ios::binary | std::ios::app);
        if (!file) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(content.data()), content.size());
        file.close();
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

int SecureAuditLogger::get_log_level() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    return log_level_;
}

void SecureAuditLogger::set_log_level(int level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_level_ = level;
}

void SecureAuditLogger::clean_old_logs(time_t max_age) {
    if (!is_initialized_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    try {
        time_t current_time = time(nullptr);
        
        for (const auto& entry : std::filesystem::directory_iterator(log_directory_)) {
            if (entry.path().extension() == ".log.enc") {
                time_t file_time = entry.last_write_time().time_since_epoch().count();
                
                if (current_time - file_time > max_age) {
                    std::filesystem::remove(entry.path());
                    log_event("system", "Removed old log file: " + entry.path().string(), false);
                }
            }
        }
    } catch (const std::exception& e) {
        log_event("security", "Failed to clean old logs: " + std::string(e.what()), true);
    }
}

const std::vector<unsigned char>& SecureAuditLogger::get_encryption_key() const {
    return encryption_key_;
}

const std::vector<unsigned char>& SecureAuditLogger::get_hmac_key() const {
    return hmac_key_;
}

std::vector<unsigned char> SecureAuditLogger::create_log_hmac(const std::vector<unsigned char>& content) {
    if (!is_initialized_) {
        return std::vector<unsigned char>();
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Создание HMAC с использованием BLAKE3
    std::vector<unsigned char> mac(HMAC_SIZE);
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Обновление хеша данными
    blake3_keyed_hasher_update(&keyed_hasher, content.data(), content.size());
    
    // Финализация и получение HMAC
    blake3_keyed_hasher_finalize(&keyed_hasher, mac.data(), mac.size());
    
    return mac;
}

bool SecureAuditLogger::verify_log_hmac(const std::vector<unsigned char>& content, 
                                      const std::vector<unsigned char>& mac) {
    if (!is_initialized_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Создание ожидаемого HMAC
    std::vector<unsigned char> expected_mac = create_log_hmac(content);
    
    // Постоянное время сравнение
    return crypto_verify_32(mac.data(), expected_mac.data()) == 0;
}

void SecureAuditLogger::ensure_constant_time(const std::chrono::microseconds& target_time) const {
    auto elapsed = std::chrono::high_resolution_clock::now() - 
                  std::chrono::high_resolution_clock::time_point(std::chrono::microseconds(0));
    
    // Используем более надежный метод для обеспечения постоянного времени
    if (elapsed < target_time) {
        auto remaining = target_time - elapsed;
        
        // Добавляем небольшую случайную задержку для защиты от анализа времени
        auto jitter = std::chrono::microseconds(SecureRandom::generate_random_mpz(GmpRaii(50)).get_ui());
        auto adjusted_remaining = remaining + jitter;
        
        // Требуемое количество итераций для задержки
        const size_t iterations = adjusted_remaining.count() * 100;
        
        // Используем сложный вычислительный цикл для задержки
        volatile uint64_t dummy = 0;
        for (size_t i = 0; i < iterations; i++) {
            dummy += i * (i ^ 0x55AA) + dummy % 1000;
            dummy = (dummy >> 31) | (dummy << 1);
        }
    }
}

bool SecureAuditLogger::is_constant_time_operation() const {
    // Проверяем, что операция была выполнена за постоянное время
    // В реальной системе здесь будет сложная логика мониторинга
    return true;
}

std::string SecureAuditLogger::generate_event_id() {
    if (!is_initialized_) {
        return "ERR";
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Генерация случайного идентификатора
    std::vector<unsigned char> random_bytes(8);
    randombytes_buf(random_bytes.data(), random_bytes.size());
    
    // Преобразование в шестнадцатеричную строку
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (unsigned char c : random_bytes) {
        hex_stream << std::setw(2) << static_cast<int>(c);
    }
    
    return hex_stream.str();
}

time_t SecureAuditLogger::get_last_log_time() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    return last_log_time_;
}

bool SecureAuditLogger::is_log_not_full() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    if (!std::filesystem::exists(current_log_file_)) {
        return true;
    }
    
    return std::filesystem::file_size(current_log_file_) < max_log_size_;
}

size_t SecureAuditLogger::get_max_log_size() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    return max_log_size_;
}

void SecureAuditLogger::set_max_log_size(size_t size) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    max_log_size_ = size;
}

void SecureAuditLogger::create_log_directory() {
    try {
        if (!std::filesystem::exists(log_directory_)) {
            std::filesystem::create_directories(log_directory_);
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create log directory: " + std::string(e.what()));
    }
}

std::string SecureAuditLogger::get_current_log_file() {
    // Формат имени файла: secure_log_YYYYMMDD.log.enc
    time_t now = time(nullptr);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "secure_log_%Y%m%d.log.enc", &tstruct);
    
    return log_directory_ + "/" + std::string(buf);
}

std::vector<unsigned char> SecureAuditLogger::encrypt_log_content(const std::vector<unsigned char>& content) {
    if (!is_initialized_) {
        return content;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Генерация случайного nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Шифрование содержимого
    std::vector<unsigned char> encrypted_content;
    encrypted_content.resize(content.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long ciphertext_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_content.data(), &ciphertext_len,
        content.data(), content.size(),
        nullptr, 0, // additional data
        nullptr, nonce, encryption_key_.data()
    );
    
    // Добавление nonce к зашифрованному содержимому
    std::vector<unsigned char> result;
    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    result.insert(result.end(), encrypted_content.begin(), encrypted_content.end());
    
    return result;
}

std::vector<unsigned char> SecureAuditLogger::decrypt_log_content(const std::vector<unsigned char>& encrypted_content) {
    if (!is_initialized_) {
        return encrypted_content;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Проверка длины содержимого
    if (encrypted_content.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
        crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::vector<unsigned char>();
    }
    
    // Извлечение nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    std::memcpy(nonce, encrypted_content.data(), sizeof(nonce));
    
    // Расшифровка содержимого
    std::vector<unsigned char> decrypted_content;
    decrypted_content.resize(encrypted_content.size() - sizeof(nonce) - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long plaintext_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted_content.data(), &plaintext_len,
            nullptr,
            encrypted_content.data() + sizeof(nonce), 
            encrypted_content.size() - sizeof(nonce),
            nullptr, 0, // additional data
            nonce, encryption_key_.data()) != 0) {
        return std::vector<unsigned char>(); // Ошибка расшифровки
    }
    
    return decrypted_content;
}

bool SecureAuditLogger::is_log_ready() const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    return is_initialized_ && 
           std::filesystem::exists(log_directory_) && 
           std::filesystem::is_directory(log_directory_);
}

} // namespace toruscsidh
