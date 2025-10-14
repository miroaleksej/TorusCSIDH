# TorusCSIDH: Постквантовая криптографическая система на основе CSIDH с геометрической проверкой безопасности (работы поинаписанию кода не завершены. На данном этапе - это концепт!)

![Build Status](https://github.com/toruscsidh/toruscsidh/workflows/Build/badge.svg)
![Security Scan](https://github.com/toruscsidh/toruscsidh/workflows/Security%20Scan/badge.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**TorusCSIDH** — это высокобезопасная постквантовая криптографическая библиотека, реализующая протокол CSIDH (Commutative Supersingular Isogeny Diffie-Hellman) с инновационной геометрической проверкой безопасности. Система предназначена для защиты от квантовых атак и обеспечивает долгосрочную безопасность криптографических приложений, включая интеграцию с Bitcoin.

## Особенности

- **Постквантовая безопасность**: Устойчивость к атакам на основе квантовых компьютеров
- **Геометрическая проверка безопасности** с 7 критериями:
  - Цикломатическое число
  - Спектральный анализ (спектральный зазор)
  - Коэффициент кластеризации
  - Энтропия распределения степеней
  - Энтропия распределения кратчайших путей
  - Расстояние до базовой кривой
  - Гибридная оценка на основе всех критериев
- **Защита от атак по побочным каналам**: Все криптографические операции выполняются за постоянное время
- **Система проверки целостности кода**: Автоматическое обнаружение и восстановление после атак
- **Безопасная реализация RFC6979**: Детерминированная генерация подписей
- **Формат адреса Bech32m** (BIP-350): Совместимость с постквантовыми адресами
- **Интеграция с Bitcoin**: Поддержка без хардфорка

## Архитектура безопасности

TorusCSIDH использует двухуровневую систему безопасности:

1. **Алгебраический уровень**: Традиционная безопасность на основе сложности задачи вычисления изогений
2. **Геометрический уровень**: Дополнительная защита через анализ топологических свойств графа изогений

> **Важно**: Геометрическая проверка **не заменяет** алгебраическую безопасность, а **дополняет** её. Эта защита не доказана в теоретико-криптографическом смысле, но практически обоснована: если злоумышленник не может создать кривую, проходящую геометрическую проверку, не зная секрета, — атака становится невозможной.

## Установка

### Требования

- CMake 3.10 или новее
- Компилятор с поддержкой C++17
- Boost 1.65 или новее
- OpenSSL
- Libsodium
- GMP
- BLAKE3

### Сборка

```bash
git clone https://github.com/toruscsidh/toruscsidh.git
cd toruscsidh
mkdir build
cd build
cmake ..
make
```

### Установка

```bash
sudo make install
```

## Использование

### Быстрый старт

```cpp
#include <toruscsidh/toruscsidh.h>
#include <iostream>

int main() {
    try {
        // Создание системы с уровнем безопасности 128 бит
        TorusCSIDH csidh(SecurityConstants::SecurityLevel::LEVEL_128);
        
        // Инициализация системы
        csidh.initialize();
        
        // Генерация ключевой пары
        csidh.generate_key_pair();
        
        // Генерация адреса
        std::string address = csidh.generate_address();
        std::cout << "Сгенерированный адрес: " << address << std::endl;
        
        // Подпись сообщения
        std::string message = "Hello, post-quantum world!";
        std::vector<unsigned char> signature = csidh.sign(
            std::vector<unsigned char>(message.begin(), message.end())
        );
        
        // Проверка подписи
        bool is_valid = csidh.verify(
            std::vector<unsigned char>(message.begin(), message.end()),
            signature
        );
        std::cout << "Подпись " << (is_valid ? "валидна" : "невалидна") << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
```

### Формат адреса

TorusCSIDH использует новый формат адреса, совместимый с Bech32m (BIP-350):

```
tcidh1<encoded_payload>
```

Пример:
```
tcidh1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9x7q9
```

### Подпись транзакции

Подпись в TorusCSIDH работает аналогично ECDSA, но с улучшенной безопасностью:

**Подписывание:**
1. Генерация эфемерного ключа $d_{\text{eph}}$
2. Вычисление $E_{\text{eph}} = [d_{\text{eph}}]E_0$
3. Вычисление общего секрета $S = j([d_A]E_{\text{eph}})$
4. Формирование подписи: $\sigma = \big( j(E_{\text{eph}}),\ H(M \parallel S) \big)$

**Проверка:**
1. Восстановление $E_{\text{eph}}$
2. Вычисление $S' = j([d_{\text{eph}}]E_A)$ (без знания $d_A$!)
3. Проверка: $h \stackrel{?}{=} H(M \parallel S')$

**Преимущество:** повторное использование $d_{\text{eph}}$ **не компрометирует** $d_A$ — в отличие от ECDSA.

## Интеграция в Bitcoin

TorusCSIDH может быть интегрирован в Bitcoin без хардфорка:

- **ScriptPubKey**: `OP_1 <32-byte SHA256(j)>` — аналогично Taproot
- **Witness**: `[signature, j_pub]`
- **Размеры**:
  - Открытый ключ: 64 байта
  - Подпись: 96 байт

## Документация

Полная документация доступна в каталоге [docs](docs/).

- [Архитектурные решения](docs/architecture.md)
- [Анализ безопасности](docs/security_analysis.md)
- [Геометрические критерии безопасности](docs/geometric_validation.md)
- [Руководство по использованию](docs/usage/getting_started.md)
- [Примеры кода](docs/usage/examples.md)

## Тестирование

Для запуска тестов:

```bash
cd build
make test
```

## Лицензия

Этот проект лицензирован в соответствии с MIT License - подробности см. в файле [LICENSE](LICENSE).

## Безопасность

Если вы обнаружили уязвимость, пожалуйста, ознакомьтесь с нашими [инструкциями по безопасности](SECURITY.md).

## Участие в проекте

Мы приветствуем вклад в проект! Пожалуйста, ознакомьтесь с нашим [руководством по внесению изменений](CONTRIBUTING.md) перед отправкой PR.

## Ссылки

- [Оригинальная статья о CSIDH](https://eprint.iacr.org/2018/383)
- [BIP-350: Bech32m для постквантовых адресов](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
- [BLAKE3: современная постквантовая хеш-функция](https://github.com/BLAKE3-team/BLAKE3)

## Контакты

- Email: miro-aleksej@yandex.ru


---

**TorusCSIDH** © 2025. Создано с заботой о будущем криптографии.
