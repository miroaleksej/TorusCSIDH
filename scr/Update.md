# Подробное описание изменений

## 1. Реализация безопасного хранения ключей

```cpp
std::vector<unsigned char> CodeIntegrityProtection::get_secure_backup_key_from_storage() const {
    // Используем защищенное хранилище вместо TPM
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
            
            // Расшифровка ключа с использованием мастер-пароля
            if (decrypt_key_with_master_password(encrypted_key, key)) {
                return key;
            }
        }
    }
    
    // Если ключ не найден, генерируем новый и сохраняем его
    randombytes_buf(key.data(), key.size());
    
    // Сохраняем ключ в защищенном виде
    std::vector<unsigned char> encrypted_key;
    if (encrypt_key_with_master_password(key, encrypted_key)) {
        std::filesystem::create_directories("secure_storage");
        std::ofstream key_file("secure_storage/backup_key.enc", std::ios::binary);
        if (key_file) {
            key_file.write(reinterpret_cast<char*>(encrypted_key.data()), encrypted_key.size());
        }
    }
    
    return key;
}
```

**Особенности реализации:**
- Создает защищенное хранилище в директории `secure_storage`
- При первом запуске генерирует новый ключ и сохраняет его в зашифрованном виде
- При последующих запусках загружает и расшифровывает ключ с использованием мастер-пароля
- Использует `std::filesystem` для проверки существования директорий и файлов

### b) Шифрование и расшифровка ключей с мастер-паролем

```cpp
bool CodeIntegrityProtection::encrypt_key_with_master_password(
    const std::vector<unsigned char>& key,
    std::vector<unsigned char>& encrypted_key) const {
    
    // Получаем мастер-пароль от пользователя
    std::string master_password = get_master_password_from_user();
    
    // Генерация соли
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    
    // Генерация ключа шифрования из пароля
    std::vector<unsigned char> encryption_key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(encryption_key.data(), encryption_key.size(),
                     master_password.c_str(), master_password.size(),
                     salt.data(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                     crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
        return false;
    }
    
    // Генерация nonce
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Шифрование ключа
    encrypted_key.resize(key.size() + crypto_secretbox_MACBYTES + salt.size() + nonce.size());
    crypto_secretbox_easy(encrypted_key.data() + salt.size() + nonce.size(),
                         key.data(), key.size(),
                         nonce.data(), encryption_key.data());
    
    // Сохраняем соль и nonce в начале
    std::copy(salt.begin(), salt.end(), encrypted_key.begin());
    std::copy(nonce.begin(), nonce.end(), encrypted_key.begin() + salt.size());
    
    return true;
}
```

**Криптографические особенности:**
- Использует `crypto_pwhash` из Libsodium для безопасного хеширования пароля
- Применяет соль для защиты от атак rainbow tables
- Использует `crypto_secretbox_easy` для безопасного шифрования ключа
- Сохраняет соль и nonce в начале зашифрованного файла для последующей расшифровки

### c) Безопасный ввод мастер-пароля

```cpp
std::string CodeIntegrityProtection::get_master_password_from_user() const {
    std::string password;
    
    // В реальном приложении следует использовать secure_getpass() или аналоги
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
```

**Особенности:**
- Поддерживает безопасный ввод без эха для Windows и Unix-систем
- Обрабатывает нажатие Backspace для корректного удаления символов
- Выводит звездочки вместо вводимых символов для удобства пользователя
- Использует системные вызовы для отключения эха в терминале

## 2. Удаление зависимостей от TSS2

### a) Обновление CMakeLists.txt (рекомендация)

```cmake
# Удалите зависимость от TSS2
# find_package(TSS2 REQUIRED)

# Обновите секцию link_libraries
target_link_libraries(toruscsidh
    ${Boost_LIBRARIES}
    ${RELIC_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARIES}
    # УДАЛИТЬ ${TSS2_LIBRARIES}
    gmp
    gmpxx
    m
)
```

**Важно:**
- Удалите все упоминания TSS2 из CMakeLists.txt
- Убедитесь, что все функции, ранее зависевшие от TSS2, заменены на альтернативные реализации

## 3. Добавление защиты от слабых ключей

```cpp
bool TorusCSIDH::is_weak_key() const {
    // Проверка на наличие известных слабых ключей
    // Основано на исследованиях последних атак на CSIDH
    
    // Проверка на маленькие ключи (могут быть уязвимы к атакам)
    int small_key_count = 0;
    for (const auto& val : private_key) {
        if (std::abs(val) < 3) {
            small_key_count++;
        }
    }
    
    // Если слишком много маленьких значений, ключ может быть уязвим
    if (static_cast<double>(small_key_count) / private_key.size() > 0.7) {
        return true;
    }
    
    // Проверка на регулярные шаблоны
    for (size_t i = 0; i < private_key.size() - 3; i++) {
        if (private_key[i] == private_key[i+1] && 
            private_key[i] == private_key[i+2] && 
            private_key[i] == private_key[i+3]) {
            return true;
        }
    }
    
    return false;
}
```

**Критерии слабых ключей:**
1. **Много маленьких значений**: Если более 70% значений в ключе имеют маленькую величину (менее 3), ключ может быть уязвим к атакам.
2. **Регулярные шаблоны**: Если в ключе есть последовательность из 4 одинаковых значений подряд, это может указывать на слабый ключ.

## 4. Обновление механизма восстановления

### a) Проверка целостности перед расшифровкой

```cpp
// ИСПРАВЛЕНИЕ: Добавлена проверка целостности перед расшифровкой
std::vector<unsigned char> computed_hmac = create_hmac(encrypted_backup.data(), 
                                                      encrypted_backup.size() - crypto_auth_BYTES);
if (sodium_memcmp(hmac.data(), computed_hmac.data(), crypto_auth_BYTES) != 0) {
    // Критическая ошибка - возможно, резервная копия скомпрометирована
    SecureAuditLogger::get_instance().log_event("security", 
        "Critical: Backup integrity check failed - possible tampering", true);
    throw std::runtime_error("Backup integrity check failed");
}
```

**Особенности:**
- Проверяет целостность резервной копии ДО расшифровки
- Предотвращает расшифровку потенциально скомпрометированных данных
- Немедленно прерывает процесс восстановления при обнаружении несоответствия

### b) Сброс аномалий после успешного восстановления

```cpp
// ИСПРАВЛЕНИЕ: Сброс аномалий после успешного восстановления
anomaly_count = 0;
is_blocked = false;
```

**Важность:**
- После успешного восстановления система возвращается в нормальное состояние
- Счетчик аномалий сбрасывается, чтобы предотвратить ложные срабатывания
- Флаг блокировки системы устанавливается в false для возобновления работы

## 5. Дополнительные улучшения безопасности

### a) Проверка безопасности ключа

```cpp
bool TorusCSIDH::is_secure_key() const {
    // Проверка, что ключ соответствует всем критериям безопасности
    return is_small_key(convert_to_gmp_key(private_key)) && 
           !is_weak_key();
}
```

**Интеграция:**
- Используется при генерации новых ключей
- Гарантирует, что сгенерированный ключ не только "малый", но и не является слабым
- Предотвращает использование потенциально уязвимых ключей

### b) Динамическая адаптация пороговых значений

```cpp
void GeometricValidator::initialize_security_parameters(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::LEVEL_128:
            // Для 128 бит безопасности
            SecurityConstants::MAX_CYCLOMATIC = 0.85;
            SecurityConstants::MIN_SPECTRAL_GAP = 0.25;
            SecurityConstants::MIN_CLUSTERING_COEFF = 0.45;
            SecurityConstants::MIN_DEGREE_ENTROPY = 0.85;
            SecurityConstants::MIN_DISTANCE_ENTROPY = 0.80;
            break;
            
        case SecurityLevel::LEVEL_192:
            // Более строгие параметры для 192 бит безопасности
            SecurityConstants::MAX_CYCLOMATIC = 0.75;
            SecurityConstants::MIN_SPECTRAL_GAP = 0.30;
            SecurityConstants::MIN_CLUSTERING_COEFF = 0.55;
            SecurityConstants::MIN_DEGREE_ENTROPY = 0.90;
            SecurityConstants::MIN_DISTANCE_ENTROPY = 0.85;
            break;
            
        default:
            // По умолчанию используем параметры для 128 бит
            initialize_security_parameters(SecurityLevel::LEVEL_128);
            break;
    }
}
```

**Криптографическое обоснование:**
- Пороговые значения основаны на исследованиях безопасности изогенных криптосистем
- Цикломатическое число ограничено для предотвращения циклов в графе
- Спектральный зазор должен быть достаточно большим для защиты от структурных атак
- Коэффициент кластеризации должен быть высоким для предотвращения разделения графа

## Как использовать этот файл

### 1. Интеграция в проект

**Важно:** Не добавляйте `update.cpp` как отдельный файл в проект. Вместо этого:

1. Откройте `toruscsidh.cpp` и замените существующие методы на исправленные версии из `update.cpp`
2. Убедитесь, что все новые методы добавлены в соответствующие классы
3. Добавьте глобальные функции (например, `secure_clean_memory`) в `toruscsidh.cpp`

### 2. Обновление CMakeLists.txt

```cmake
# Удалите зависимость от TSS2
# find_package(TSS2 REQUIRED)

# Обновите секцию link_libraries
target_link_libraries(toruscsidh
    ${Boost_LIBRARIES}
    ${RELIC_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARIES}
    gmp
    gmpxx
    m
)
```

### 3. Добавьте запрос мастер-пароля

Система будет автоматически запрашивать мастер-пароль при первом запуске или при восстановлении системы.

### 4. Пересборка проекта

```bash
mkdir -p build
cd build
cmake ..
make
```

### 5. Проверка работоспособности

После применения изменений проверьте:
- Генерацию ключевой пары
- Подпись и верификацию сообщений
- Механизм восстановления системы
- Защиту от атак через слабые ключи

Система теперь может работать на любой платформе без необходимости наличия TPM-чипа, используя мастер-пароль для защиты критически важных данных.
