#ifndef CODE_INTEGRITY_H
#define CODE_INTEGRITY_H

#include <vector>
#include <string>
#include <mutex>
#include <ctime>
#include <map>
#include <filesystem>
#include <sodium.h>
#include "security_constants.h"
#include "postquantum_hash.h"

/**
 * @brief Класс для проверки и восстановления целостности системы
 */
class CodeIntegrityProtection {
public:
    /**
     * @brief Конструктор
     */
    CodeIntegrityProtection();
    
    /**
     * @brief Деструктор
     */
    ~CodeIntegrityProtection();
    
    /**
     * @brief Проверка целостности системы
     * @return true, если система цела
     */
    bool system_integrity_check();
    
    /**
     * @brief Самовосстановление системы из резервной копии
     * @return true, если восстановление прошло успешно
     */
    bool self_recovery();
    
    /**
     * @brief Сохранение состояния для восстановления
     */
    void save_recovery_state();
    
    /**
     * @brief Обновление критериев безопасности с отложенной активацией
     * @param major_version Основная версия
     * @param minor_version Дополнительная версия
     * @param activation_time Время активации
     * @return true, если обновление запланировано успешно
     */
    bool update_criteria_version(int major_version, int minor_version, time_t activation_time);
    
    /**
     * @brief Проверка, заблокирована ли система из-за аномалий
     * @return true, если система заблокирована
     */
    bool is_blocked_due_to_anomalies() const;
    
    /**
     * @brief Обработка аномалии
     * @param anomaly_type Тип аномалии
     * @param description Описание аномалии
     */
    void handle_anomaly(const std::string& anomaly_type, const std::string& description);
    
    /**
     * @brief Сброс счетчика аномалий
     */
    void reset_anomaly_counter();
    
    /**
     * @brief Проверка, готова ли система к работе
     * @return true, если система готова
     */
    bool is_system_ready() const;
    
    /**
     * @brief Получение ключа для резервного копирования
     * @return Ключ для резервного копирования
     */
    std::vector<unsigned char> get_backup_key() const;
    
    /**
     * @brief Получение безопасного ключа из защищенного хранилища
     * @return Ключ из защищенного хранилища
     */
    std::vector<unsigned char> get_secure_backup_key_from_storage() const;
    
    /**
     * @brief Получение мастер-пароля от пользователя
     * @return Мастер-пароль
     */
    std::string get_master_password_from_user() const;
    
    /**
     * @brief Обновление критических компонентов
     */
    void update_critical_components();
    
    /**
     * @brief Проверка целостности системы
     * @return true, если система цела
     */
    bool verify_system_integrity();

private:
    std::mutex integrity_mutex;          ///< Мьютекс для защиты целостности
    bool is_blocked;                     ///< Флаг блокировки системы
    size_t anomaly_count;                ///< Счетчик аномалий
    time_t last_anomaly_time;            ///< Время последней аномалии
    time_t last_backup_time;             ///< Время последней резервной копии
    time_t last_recovery_time;           ///< Время последнего восстановления
    std::vector<unsigned char> hmac_key; ///< Ключ HMAC для проверки целостности
    std::vector<unsigned char> backup_key; ///< Ключ для резервного копирования
    std::vector<unsigned char> system_public_key; ///< Публичный ключ системы
    std::vector<std::string> critical_modules; ///< Критические модули системы
    
    /**
     * @brief Инициализация ключа HMAC
     */
    void initialize_hmac_key();
    
    /**
     * @brief Подпись критических модулей
     */
    void sign_critical_modules();
    
    /**
     * @brief Проверка модуля
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     * @return true, если подпись верна
     */
    bool verify_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Подпись модуля
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     */
    void sign_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Загрузка модуля
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @return true, если загрузка успешна
     */
    bool load_module(const std::string& module_name, std::vector<unsigned char>& data);
    
    /**
     * @brief Восстановление из резервной копии
     * @return true, если восстановление успешно
     */
    bool recover_from_backup();
};

CodeIntegrityProtection::CodeIntegrityProtection()
    : is_blocked(false), 
      anomaly_count(0), 
      last_anomaly_time(0),
      last_backup_time(0),
      last_recovery_time(0) {
    
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    
    // Генерация случайного ключа HMAC
    hmac_key.resize(SecurityConstants::HMAC_KEY_SIZE);
    randombytes_buf(hmac_key.data(), hmac_key.size());
    
    // Генерация ключа для резервного копирования
    backup_key.resize(32);
    randombytes_buf(backup_key.data(), backup_key.size());
    
    // Генерация ключа для подписи
    crypto_sign_keypair(system_public_key.data(), nullptr);
    
    // Определение критических модулей
    critical_modules = {
        "toruscsidh_core",
        "secure_random",
        "postquantum_hash",
        "rfc6979_rng",
        "elliptic_curve",
        "geometric_validator",
        "code_integrity",
        "secure_audit_logger"
    };
    
    // Инициализация HMAC ключа
    initialize_hmac_key();
    
    // Подпись критических модулей
    sign_critical_modules();
    
    // Сохранение состояния для восстановления
    save_recovery_state();
}

CodeIntegrityProtection::~CodeIntegrityProtection() {
    // Очистка памяти
    SecureRandom::secure_clean_memory(hmac_key.data(), hmac_key.size());
    SecureRandom::secure_clean_memory(backup_key.data(), backup_key.size());
}

bool CodeIntegrityProtection::system_integrity_check() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    // Проверка счетчика аномалий
    if (is_blocked) {
        return false;
    }
    
    // Проверка времени с последней аномалии
    if (anomaly_count > 0 && time(nullptr) - last_anomaly_time > SecurityConstants::ANOMALY_RESET_INTERVAL) {
        reset_anomaly_counter();
    }
    
    // Проверка целостности критических модулей
    for (const auto& module : critical_modules) {
        std::vector<unsigned char> module_data;
        if (!load_module(module, module_data)) {
            handle_anomaly("module_load", "Failed to load module: " + module);
            return false;
        }
        
        if (!verify_module(module, module_data.data(), module_data.size())) {
            handle_anomaly("module_integrity", "Module integrity check failed: " + module);
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::self_recovery() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        // Попытка восстановления из резервной копии
        if (recover_from_backup()) {
            // После успешного восстановления, проверяем целостность системы
            return system_integrity_check();
        }
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}

void CodeIntegrityProtection::save_recovery_state() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Создание директории для резервных копий
        std::filesystem::create_directories("secure_storage/backups");
        
        // Сбор данных для резервной копии
        std::vector<unsigned char> backup_data;
        
        for (const auto& module : critical_modules) {
            // Загрузка модуля
            std::vector<unsigned char> module_data;
            if (!load_module(module, module_data)) {
                throw std::runtime_error("Failed to load module: " + module);
            }
            
            // Добавление размера модуля
            size_t module_size = module_data.size();
            backup_data.insert(backup_data.end(), 
                              reinterpret_cast<unsigned char*>(&module_size), 
                              reinterpret_cast<unsigned char*>(&module_size) + sizeof(size_t));
            
            // Добавление данных модуля
            backup_data.insert(backup_data.end(), module_data.begin(), module_data.end());
        }
        
        // Шифрование данных
        std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
        randombytes_buf(nonce.data(), nonce.size());
        
        std::vector<unsigned char> ciphertext(backup_data.size() + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(ciphertext.data(), 
                             backup_data.data(), 
                             backup_data.size(), 
                             nonce.data(), 
                             backup_key.data());
        
        // Создание HMAC для проверки целостности
        std::vector<unsigned char> mac(crypto_auth_BYTES);
        crypto_auth(mac.data(), 
                   ciphertext.data(), 
                   ciphertext.size(), 
                   hmac_key.data());
        
        // Формирование полных данных резервной копии
        std::vector<unsigned char> full_backup;
        full_backup.insert(full_backup.end(), nonce.begin(), nonce.end());
        full_backup.insert(full_backup.end(), ciphertext.begin(), ciphertext.end());
        full_backup.insert(full_backup.end(), mac.begin(), mac.end());
        
        // Сохранение в защищенный файл
        std::string backup_filename = "secure_storage/backups/backup_" + 
                                     std::to_string(time(nullptr)) + ".enc";
        
        std::ofstream backup_file(backup_filename, std::ios::binary);
        if (!backup_file) {
            throw std::runtime_error("Failed to open backup file");
        }
        
        backup_file.write(reinterpret_cast<const char*>(full_backup.data()), full_backup.size());
        backup_file.close();
        
        // Обновление времени последней резервной копии
        last_backup_time = time(nullptr);
        
    } catch (const std::exception& e) {
        handle_anomaly("backup_failure", std::string("Failed to save recovery state: ") + e.what());
    }
}

bool CodeIntegrityProtection::update_criteria_version(int major_version, int minor_version, time_t activation_time) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        // Проверка, что время активации в будущем
        if (activation_time <= time(nullptr)) {
            return false;
        }
        
        // Создание резервной копии текущих критериев
        save_recovery_state();
        
        // В реальной системе здесь будет безопасное обновление через мультиподпись
        // Для примера просто обновляем данные
        // ...
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CodeIntegrityProtection::is_blocked_due_to_anomalies() const {
    return is_blocked;
}

void CodeIntegrityProtection::handle_anomaly(const std::string& anomaly_type, const std::string& description) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    // Логирование аномалии
    // В реальной системе здесь будет запись в защищенный журнал
    
    // Обновление счетчика аномалий
    anomaly_count++;
    last_anomaly_time = time(nullptr);
    
    // Проверка, нужно ли блокировать систему
    if (anomaly_count >= SecurityConstants::MAX_ANOMALY_COUNT) {
        is_blocked = true;
    }
}

void CodeIntegrityProtection::reset_anomaly_counter() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    anomaly_count = 0;
}

bool CodeIntegrityProtection::is_system_ready() const {
    return !is_blocked;
}

std::vector<unsigned char> CodeIntegrityProtection::get_backup_key() const {
    return backup_key;
}

std::vector<unsigned char> CodeIntegrityProtection::get_secure_backup_key_from_storage() const {
    std::vector<unsigned char> key(32);
    
    // Попытка загрузить ключ из защищенного файла
    if (std::filesystem::exists("secure_storage/backup_key.enc")) {
        // Чтение зашифрованного ключа
        std::ifstream key_file("secure_storage/backup_key.enc", std::ios::binary);
        if (key_file) {
            key_file.seekg(0, std::ios::end);
            size_t size = key_file.tellg();
            key_file.seekg(0, std::ios::beg);
            std::vector<unsigned char> encrypted_key(size);
            
            key_file.read(reinterpret_cast<char*>(encrypted_key.data()), size);
            key_file.close();
            
            // Расшифровка ключа
            std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
            std::copy(encrypted_key.begin(), encrypted_key.begin() + crypto_secretbox_NONCEBYTES, nonce.begin());
            
            std::vector<unsigned char> ciphertext(encrypted_key.begin() + crypto_secretbox_NONCEBYTES, encrypted_key.end());
            if (ciphertext.size() < crypto_secretbox_MACBYTES) {
                throw std::runtime_error("Invalid encrypted key format");
            }
            
            std::vector<unsigned char> decrypted_key(ciphertext.size() - crypto_secretbox_MACBYTES);
            if (crypto_secretbox_open_easy(decrypted_key.data(), 
                                         ciphertext.data(), 
                                         ciphertext.size(), 
                                         nonce.data(), 
                                         backup_key.data()) != 0) {
                throw std::runtime_error("Failed to decrypt backup key");
            }
            
            // Проверка целостности ключа
            std::vector<unsigned char> mac(crypto_auth_BYTES);
            std::copy(encrypted_key.end() - crypto_auth_BYTES, encrypted_key.end(), mac.begin());
            
            if (!PostQuantumHash::verify_hmac_blake3(hmac_key, ciphertext, mac)) {
                throw std::runtime_error("Backup key integrity check failed");
            }
            
            std::copy(decrypted_key.begin(), decrypted_key.end(), key.begin());
        }
    }
    
    return key;
}

std::string CodeIntegrityProtection::get_master_password_from_user() const {
    std::string password;
    
    // В реальном приложении следует использовать secure_getpass() или аналоги
    // Это пример, в продакшене нужна более безопасная реализация
    std::cout << "Введите мастер-пароль для защиты системы (пароль не будет отображаться): ";
    
    // Используем терминальный ввод без эха
#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') { // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    
    return password;
}

void CodeIntegrityProtection::update_critical_components() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Сохранение состояния перед обновлением
        save_recovery_state();
        
        // В реальной системе обновление из защищенного источника
        // ...
        
        // Переподпись критических модулей
        sign_critical_modules();
        
        // Сброс счетчика аномалий
        anomaly_count = 0;
        is_blocked = false;
    } catch (const std::exception& e) {
        // Логирование ошибки
        handle_anomaly("update_failure", std::string("Failed to update: ") + e.what());
        throw;
    }
}

bool CodeIntegrityProtection::verify_system_integrity() {
    return system_integrity_check();
}

void CodeIntegrityProtection::initialize_hmac_key() {
    randombytes_buf(hmac_key.data(), hmac_key.size());
}

void CodeIntegrityProtection::sign_critical_modules() {
    for (const auto& module : critical_modules) {
        std::vector<unsigned char> module_data;
        if (load_module(module, module_data)) {
            sign_module(module, module_data.data(), module_data.size());
        }
    }
}

bool CodeIntegrityProtection::verify_module(const std::string& module_name, const void* data, size_t size) {
    // В реальной системе здесь будет проверка подписи
    // Для демонстрации всегда возвращаем true
    return true;
}

void CodeIntegrityProtection::sign_module(const std::string& module_name, const void* data, size_t size) {
    // В реальной системе здесь будет создание подписи
    // Для демонстрации ничего не делаем
}

bool CodeIntegrityProtection::load_module(const std::string& module_name, std::vector<unsigned char>& data) {
    // В реальной системе здесь будет загрузка модуля
    // Для демонстрации возвращаем пустые данные
    data.clear();
    return true;
}

bool CodeIntegrityProtection::recover_from_backup() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Поиск последней резервной копии
        std::string latest_backup;
        time_t latest_time = 0;
        
        for (const auto& entry : std::filesystem::directory_iterator("secure_storage/backups")) {
            if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                time_t file_time = std::filesystem::last_write_time(entry.path());
                if (file_time > latest_time) {
                    latest_time = file_time;
                    latest_backup = entry.path().string();
                }
            }
        }
        
        if (latest_backup.empty()) {
            return false;
        }
        
        // Загрузка резервной копии
        std::ifstream backup_file(latest_backup, std::ios::binary);
        if (!backup_file) {
            return false;
        }
        
        backup_file.seekg(0, std::ios::end);
        size_t size = backup_file.tellg();
        backup_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> full_backup(size);
        backup_file.read(reinterpret_cast<char*>(full_backup.data()), size);
        backup_file.close();
        
        // Проверка целостности резервной копии
        if (full_backup.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            return false;
        }
        
        std::vector<unsigned char> nonce(full_backup.begin(), 
                                       full_backup.begin() + crypto_secretbox_NONCEBYTES);
        std::vector<unsigned char> ciphertext(full_backup.begin() + crypto_secretbox_NONCEBYTES, 
                                           full_backup.end() - crypto_auth_BYTES);
        std::vector<unsigned char> mac(full_backup.end() - crypto_auth_BYTES, full_backup.end());
        
        if (!PostQuantumHash::verify_hmac_blake3(hmac_key, ciphertext, mac)) {
            return false;
        }
        
        // Расшифровка резервной копии
        std::vector<unsigned char> backup_data(ciphertext.size() - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(backup_data.data(), 
                                     ciphertext.data(), 
                                     ciphertext.size(), 
                                     nonce.data(), 
                                     backup_key.data()) != 0) {
            return false;
        }
        
        // Восстановление модулей
        size_t offset = 0;
        for (const auto& module : critical_modules) {
            if (offset + sizeof(size_t) > backup_data.size()) {
                return false;
            }
            
            size_t module_size;
            std::copy(backup_data.begin() + offset, 
                     backup_data.begin() + offset + sizeof(size_t), 
                     reinterpret_cast<unsigned char*>(&module_size));
            offset += sizeof(size_t);
            
            if (offset + module_size > backup_data.size()) {
                return false;
            }
            
            // Восстановление модуля
            // В реальной системе здесь будет запись данных модуля
            // ...
            
            offset += module_size;
        }
        
        // Обновление времени последнего восстановления
        last_recovery_time = time(nullptr);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

#endif // CODE_INTEGRITY_H
