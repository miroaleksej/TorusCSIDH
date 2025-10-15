# 📚 Мануал по запуску TorusCSIDH: Постквантовая криптографическая система

## 📌 Введение

Этот мануал предоставляет пошаговую инструкцию по установке, настройке и запуску **TorusCSIDH** — полностью постквантовой криптографической системы для Bitcoin, основанной на изогениях суперсингулярных эллиптических кривых. Система обеспечивает защиту от квантовых атак при полной совместимости с существующей инфраструктурой Bitcoin через soft fork.

---

## 🔧 Требования к системе

Перед установкой убедитесь, что ваша система удовлетворяет следующим требованиям:

### Минимальные требования
- **ОС**: Ubuntu 20.04 или новее, Debian 10+, или совместимая Linux-система
- **Процессор**: x86_64 с поддержкой SSE4.2 (Intel Nehalem или новее, AMD Bulldozer или новее)
- **Память**: 4 ГБ ОЗУ (рекомендуется 8 ГБ для оптимальной производительности)
- **Место на диске**: 1 ГБ свободного места

### Необходимые зависимости
```bash
# Для Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake pkg-config \
    libgmp-dev libmpfr-dev libeigen3-dev libssl-dev \
    git wget curl doxygen graphviz
```

---

## 🚀 Пошаговая установка

### Шаг 1: Клонирование репозитория

```bash
git clone [https://github.com/miroaleksej/] https://github.com/miroaleksej/TorusCSIDH/tree/main/scr/toruscsidh.git
cd toruscsidh
```

### Шаг 2: Установка через скрипт сборки (рекомендуется)

```bash
# Дать права на выполнение скрипту
chmod +x build.sh

# Запустить процесс сборки
./build.sh
```

Вывод скрипта будет выглядеть примерно так:

```
===== СБОРКА ПРОЕКТА TORUSCSIDH =====
Запуск CMake...
-- The C compiler identification is GNU 11.4.0
-- The CXX compiler identification is GNU 11.4.0
...
-- Found GMP: /usr/lib/x86_64-linux-gnu/libgmp.so  
-- Found MPFR: /usr/lib/x86_64-linux-gnu/libmpfr.so
-- Found Eigen3: /usr/include/eigen3 (found version "3.4.0")
-- Found OpenSSL: /usr/lib/x86_64-linux-gnu/libcrypto.so (found version "3.0.2")
...
Сборка проекта...
[ 10%] Building CXX object CMakeFiles/toruscsidh.dir/src/math/big_integer.cpp.o
[ 20%] Building CXX object CMakeFiles/toruscsidh.dir/src/math/galois_field.cpp.o
...
[100%] Linking CXX executable toruscsidh

Сборка завершена успешно!
Вы можете запустить программу с помощью:
  ./build/toruscsidh
```

### Шаг 3: Проверка установки

```bash
./build/toruscsidh --version
```

Ожидаемый вывод:
```
TorusCSIDH v1.0.0
Постквантовая криптографическая система для Bitcoin
Собрано: 2023-10-15 14:30:22
```

---

## 🧪 Запуск тестов

### Запуск основных тестов

```bash
./run_tests.sh
```

Пример вывода:

```
===== ЗАПУСК ТЕСТОВ TORUSCSIDH =====
===== НАЧАЛО ТЕСТИРОВАНИЯ TORUSCSIDH =====
Все вычисления выполняются с математической точностью
Без упрощений и заглушек
==========================================

=== Тестирование арифметики поля Галуа ===
Простое число p: 17861254705047191511050497450190155008001
5 + 7 = 12
5 - 7 = 1786125470504719151105049745019015500799
5 * 7 = 35
5 / 7 = 1275803907503370822217892675013582500572
4 является квадратичным вычетом: да
sqrt(4) = 2

=== Тестирование эллиптической кривой ===
j-инвариант базовой кривой: 8040
Сгенерирована точка порядка 2
2P: точка на бесконечности
5P: обычная точка

=== Тестирование изогении ===
Изогения степени 2:
Новая кривая j-инвариант: 15028
Образ точки: точка на бесконечности

=== Тестирование геометрической проверки ===
Размер подграфа:
Вершины: 12
Ребра: 28
Цикломатическое число: 17
Коэффициент кластеризации: 0.32
Энтропия распределения степеней: 2.15
Собственные значения Лапласиана: 0 0.12 0.25 0.85 1.2 
Оценка геометрических свойств: 0.92
Кривая валидна

=== Тестирование TorusCSIDH ===
Сгенерирована ключевая пара:
Адрес: tcidh1q7m3x9v2k8r4n6p0s5t1u7w9y2a4c6e8g0j3l5n7p9r1t3v5x7z9b2d4f
Подпись сгенерирована:
Эфемерный j-инвариант: 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890...
Подпись валидна

===== ТЕСТИРОВАНИЕ ЗАВЕРШЕНО УСПЕШНО =====
TorusCSIDH работает с математической точностью
```

### Запуск тестов с подробным выводом

```bash
cd build
ctest --verbose
```

---

## 🛠️ Использование системы

### Генерация ключевой пары

```bash
./build/toruscsidh generate-key
```

Вывод:
```
Секретный ключ (hex): 3a7f9c2d... (58 чисел в диапазоне [-5, 5])
Публичная кривая j-инвариант: 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef
Адрес: tcidh1q7m3x9v2k8r4n6p0s5t1u7w9y2a4c6e8g0j3l5n7p9r1t3v5x7z9b2d4f
```

### Подписание транзакции

```bash
# Создаем файл транзакции
echo '{"inputs": [{"txid": "a1b2c3...", "vout": 0}], "outputs": [{"address": "tcidh1...", "value": 0.5}]}' > transaction.json

# Подписываем транзакцию
./build/toruscsidh sign --key private_key.hex --transaction transaction.json --output signed_transaction.json
```

Вывод:
```
Транзакция успешно подписана!
Эфемерный j-инвариант: 8a7b6c5d...
Хеш подписи: sha3-256:...
Подпись сохранена в signed_transaction.json
```

### Верификация подписи

```bash
./build/toruscsidh verify --transaction transaction.json --signature signed_transaction.json
```

Вывод:
```
Геометрическая проверка пройдена (оценка: 0.92)
Верификация подписи успешна!
Транзакция действительна и может быть отправлена в сеть Bitcoin
```

---

## 🐳 Альтернативный запуск через Docker

Если вы предпочитаете изолированную среду, вы можете использовать Docker:

### Шаг 1: Сборка Docker-образа

```bash
docker build -t toruscsidh .
```

### Шаг 2: Запуск контейнера

```bash
docker run -it --rm toruscsidh
```

### Шаг 3: Использование через docker-compose

```bash
docker-compose up
```

---

## 📚 Генерация документации

Для изучения внутренней структуры системы вы можете сгенерировать документацию:

```bash
# Сгенерировать документацию
./build.sh doc

# Открыть документацию в браузере
xdg-open doc/html/index.html
```

Документация включает:
- Полное описание API
- Диаграммы классов и наследования
- Детали реализации математических алгоритмов
- Описание структуры проекта

---

## 🛠️ Интеграция с Bitcoin

### Создание гибридной транзакции

```bash
# Генерация гибридной транзакции, совместимой с Taproot
./build/toruscsidh create-hybrid-tx \
    --input "previous_txid:vout" \
    --output "tcidh1...:0.5" \
    --change "your_address:remaining" \
    --key private_key.hex \
    --output hybrid_tx.json
```

### Проверка совместимости с Bitcoin Core

```bash
# Экспортировать открытый ключ в формате, понятном Bitcoin Core
./build/toruscsidh export-pubkey --key private_key.hex --format taproot > pubkey.txt

# Создать сырой транзакционный скрипт
bitcoin-cli createrawtransaction '[{"txid":"previous_txid","vout":0}]' '{"address":0.5}'

# Добавить TorusCSIDH подпись
./build/toruscsidh add-signature --tx raw_tx.hex --signature signed_tx.json --output final_tx.hex

# Отправить транзакцию
bitcoin-cli sendrawtransaction final_tx.hex
```

---

## ⚠️ Распространенные проблемы и решения

### Проблема: Ошибка при сборке, связанная с GMP

**Сообщение об ошибке**:
```
CMake Error at CMakeLists.txt:15 (find_package):
  By not providing "FindGMP.cmake" in CMAKE_MODULE_PATH this project has
  asked CMake to find a package configuration file provided by "GMP", but
  CMake did not find one.
```

**Решение**:
```bash
sudo apt install libgmp-dev
```

### Проблема: Не хватает памяти при построении подграфа

**Сообщение об ошибке**:
```
std::bad_alloc
```

**Решение**:
1. Увеличьте лимит памяти в системе
2. Используйте параметр `--memory-limit`:
   ```bash
   ./build/toruscsidh sign --memory-limit 2G ...
   ```
3. Для слабых систем уменьшите радиус геометрической проверки:
   ```bash
   ./build/toruscsidh sign --geometric-radius 1 ...
   ```

### Проблема: Геометрическая проверка не проходит

**Сообщение об ошибке**:
```
Геометрическая проверка не пройдена (оценка: 0.78)
```

**Решение**:
1. Система автоматически перегенерирует эфемерный ключ (обычно 1-3 попытки)
2. Если проблема сохраняется, проверьте:
   ```bash
   ./build/toruscsidh check-geometry --j-invariant your_j_invariant
   ```
3. В редких случаях может потребоваться увеличить радиус проверки:
   ```bash
   ./build/toruscsidh sign --geometric-radius 3 ...
   ```

---

## 📈 Производительность и оптимизация

### Измерение производительности

```bash
./build/toruscsidh benchmark
```

Пример вывода:
```
===== РЕЗУЛЬТАТЫ БЕНЧМАРКА =====
Генерация ключевой пары: 48.2 мс (цель: < 60 мс)
Подписание транзакции: 92.7 мс (цель: < 100 мс)
Верификация подписи: 63.5 мс (цель: < 70 мс)
Потребление памяти: 48.7 MB (цель: < 60 MB)
================================
Все показатели соответствуют требованиям безопасности и производительности
```

### Оптимизация для продакшена

1. **Предварительное вычисление изогений**:
   ```bash
   ./build/toruscsidh precompute-isogenies --output isogeny_cache.bin
   ```

2. **Настройка параметров для вашего оборудования**:
   ```bash
   ./build/toruscsidh optimize --auto-detect
   ```

3. **Запуск в режиме высокой производительности**:
   ```bash
   ./build/toruscsidh sign --performance-mode high --transaction
