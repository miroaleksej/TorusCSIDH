1. **Интегрируйте исправления** в существующие файлы

2. **Добавьте запрос мастер-пароля** при первом запуске системы:
   ```cpp
   std::string CodeIntegrityProtection::get_master_password_from_user() const {
       std::string password;
       std::cout << "Введите мастер-пароль для защиты системы: ";
       // В реальном приложении используйте безопасный ввод без эха
       std::getline(std::cin, password);
       return password;
   }
   ```
## Правильный способ применения исправлений

### 1. Замена методов в toruscsidh.cpp

Откройте файл `toruscsidh.cpp` и внесите следующие изменения:

#### Замените метод `TorusCSIDH::verify()`
Найдите в коде:
```cpp
bool TorusCSIDH::verify(const std::vector<unsigned char>& message,
                        const std::vector<unsigned char>& signature,
                        const MontgomeryCurve& public_curve) {
```

Замените его на исправленную версию из `update.cpp`, которая включает:
- Проверку коммутативности: `[d_eph][d_A]E_0 = [d_A][d_eph]E_0`
- Проверку "малости" ключа
- Улучшенную защиту от атак по времени

#### Добавьте метод `TorusCSIDH::is_small_key()`
Добавьте этот метод в класс `TorusCSIDH`:
```cpp
bool TorusCSIDH::is_small_key(const GmpRaii& key) const {
    // Реализация из update.cpp
}
```

#### Замените метод `TorusCSIDH::generate_key_pair()`
Найдите и замените существующую реализацию на исправленную версию, которая гарантирует "малость" ключа.

#### Добавьте метод `TorusCSIDH::convert_to_gmp_key()`
```cpp
GmpRaii TorusCSIDH::convert_to_gmp_key(const std::vector<short>& key) const {
    // Реализация из update.cpp
}
```

### 2. Обновление класса CodeIntegrityProtection

#### Замените метод `recover_from_backup()`
Найдите в `toruscsidh.cpp`:
```cpp
bool CodeIntegrityProtection::recover_from_backup() {
```

Замените его на исправленную версию из `update.cpp`, которая теперь работает **без TPM**:
- Использует `get_secure_backup_key_from_storage()` вместо TPM
- Добавлена проверка целостности перед расшифровкой
- Реализована безопасная очистка ключей

#### Добавьте новые методы
Добавьте в класс `CodeIntegrityProtection`:
```cpp
std::vector<unsigned char> CodeIntegrityProtection::get_secure_backup_key_from_storage() const {
    // Реализация из update.cpp
}

bool CodeIntegrityProtection::encrypt_key_with_master_password(
    const std::vector<unsigned char>& key,
    std::vector<unsigned char>& encrypted_key) const {
    // Реализация из update.cpp
}

bool CodeIntegrityProtection::decrypt_key_with_master_password(
    const std::vector<unsigned char>& encrypted_key,
    std::vector<unsigned char>& key) const {
    // Реализация из update.cpp
}
```

### 3. Обновление класса GeometricValidator

#### Замените метод `validate_curve()`
Найдите и замените существующую реализацию на исправленную версию из `update.cpp`, которая:
- Добавляет криптографическое обоснование пороговых значений
- Проверяет все геометрические свойства кривой

#### Добавьте метод `initialize_security_parameters()`
```cpp
void GeometricValidator::initialize_security_parameters(SecurityLevel level) {
    // Реализация из update.cpp
}
```

### 4. Добавьте глобальные функции

Добавьте в `toruscsidh.cpp` (вне классов) следующие функции:
```cpp
void secure_clean_memory(void* ptr, size_t size) {
    // Реализация из update.cpp
}

GmpRaii secure_gmp_random(const GmpRaii& max) {
    // Реализация из update.cpp
}
```

## Важные изменения в CMakeLists.txt

Удалите зависимость от TSS2, так как мы больше не используем TPM:
```cmake
# УДАЛИТЬ ЭТУ СТРОКУ
find_package(TSS2 REQUIRED)
```

И обновите секцию link_libraries:
```cmake
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

## Шаги для применения исправлений

1. **Создайте резервную копию проекта**:
   ```bash
   cp toruscsidh.cpp toruscsidh.cpp.bak
   ```

2. **Откройте toruscsidh.cpp** в текстовом редакторе

3. **Найдите и замените методы** согласно инструкциям выше

4. **Обновите CMakeLists.txt**, удалив зависимости от TSS2

5. **Добавьте запрос мастер-пароля** в main.cpp:
   ```cpp
   // Добавьте этот код в начало main()
   std::string get_master_password() {
       std::string password;
       std::cout << "Введите мастер-пароль для защиты системы: ";
       // В реальном приложении используйте secure_getpass() или аналоги
       std::getline(std::cin, password);
       return password;
   }
   
   // И добавьте вызов этой функции где-то перед использованием системы
   std::string master_password = get_master_password();
   ```

6. **Пересоберите проект**:
   ```bash
   mkdir -p build
   cd build
   cmake ..
   make
   ```

## Проверка работоспособности

После применения изменений запустите проект и проверьте:

1. **Генерацию ключевой пары**:
   ```cpp
   csidh.generate_key_pair();
   ```

2. **Подпись и верификацию**:
   ```cpp
   auto signature = csidh.sign(message);
   bool valid = csidh.verify(message, signature, csidh.get_public_curve());
   ```

3. **Геометрическую проверку**:
   Убедитесь, что система корректно проверяет геометрические свойства кривых

4. **Механизм восстановления**:
   Попробуйте вызвать `csidh.code_integrity.self_recovery()` для проверки механизма восстановления

## Важные замечания

1. **Мастер-пароль**: Система теперь будет запрашивать мастер-пароль при первом запуске для защиты ключей.

2. **Безопасная очистка памяти**: Убедитесь, что функция `secure_clean_memory()` вызывается для всех секретных данных после использования.

3. **Проверка коммутативности**: Это критически важное исправление для безопасности CSIDH - убедитесь, что оно работает правильно.

4. **Тестирование**: Добавьте тесты для новых функций, особенно для проверки коммутативности и механизма восстановления.

Эти изменения сделают ваш проект безопаснее и устраним критические уязвимости
