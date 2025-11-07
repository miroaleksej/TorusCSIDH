/**
 * @file fp.h
 * @brief Арифметика в конечном поле Fp для системы TorusCSIDH
 * 
 * Этот модуль предоставляет constant-time реализацию арифметических операций
 * в конечном поле Fp для параметра безопасности 128 бит (CSIDH-512).
 * Все операции защищены от атак по побочным каналам.
 */

#ifndef TORUS_CSIDH_MATH_FP_H
#define TORUS_CSIDH_MATH_FP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Параметры конечного поля
 * 
 * Для уровня безопасности 128 бит:
 * - p = 2^512 - 0xFFFFFFFFFFFFFDC7
 * - Размер лимба: 64 бита
 * - Количество лимбов: 8 (512 бит / 64 бита)
 */
#define NLIMBS 8
#define FP_BITS 512
#define BITS_PER_LIMB 64

/**
 * @brief Представление элемента конечного поля
 * 
 * Элемент поля представляется как массив из NLIMBS 64-битных слов
 * в виде целого числа в системе счисления с основанием 2^64.
 */
typedef struct {
    uint64_t d[NLIMBS];  ///< Коэффициенты в представлении по основанию 2^64
} fp;

/**
 * @brief Контекст модульной арифметики
 * 
 * Содержит предвычисленные значения для эффективных операций
 * в поле Fp с модулем p.
 */
typedef struct {
    fp modulus;        ///< Модуль p
    fp r;              ///< R mod p (где R = 2^512 для Montgomery)
    fp r2;             ///< R^2 mod p
    uint64_t inv;      ///< -p^{-1} mod 2^64 для Montgomery reduction
} fp_ctx;

/**
 * @brief Глобальный контекст для CSIDH-512
 * 
 * Предварительно инициализированный контекст для модуля:
 * p = 2^512 - 0xFFFFFFFFFFFFFDC7
 */
extern const fp_ctx fp_ctx_512;

/**
 * @brief Инициализация контекста модульной арифметики
 * 
 * @param[in,out] ctx Контекст для инициализации
 * @param[in] modulus Модуль в виде массива 64-битных слов
 * 
 * @note Constant-time операция
 */
void fp_init_ctx(fp_ctx* ctx, const uint64_t* modulus);

/**
 * @brief Копирование элемента поля
 * 
 * @param[out] r Результат: r = a
 * @param[in] a Исходный элемент
 * 
 * @note Constant-time операция
 */
void fp_copy(fp* r, const fp* a);

/**
 * @brief Установка элемента в ноль
 * 
 * @param[out] a Элемент для установки в ноль
 * 
 * @note Constant-time операция
 */
void fp_set_zero(fp* a);

/**
 * @brief Установка элемента в единицу
 * 
 * @param[out] a Элемент для установки в единицу
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_set_one(fp* a, const fp_ctx* ctx);

/**
 * @brief Проверка, является ли элемент нулевым
 * 
 * @param[in] a Проверяемый элемент
 * @return 1 если a = 0, иначе 0
 * 
 * @note Constant-time операция
 */
int fp_is_zero(const fp* a);

/**
 * @brief Проверка, является ли элемент единицей
 * 
 * @param[in] a Проверяемый элемент
 * @param[in] ctx Контекст арифметики
 * @return 1 если a = 1, иначе 0
 * 
 * @note Constant-time операция
 */
int fp_is_one(const fp* a, const fp_ctx* ctx);

/**
 * @brief Сравнение двух элементов на равенство
 * 
 * @param[in] a Первый элемент
 * @param[in] b Второй элемент
 * @return 1 если a = b, иначе 0
 * 
 * @note Constant-time операция
 */
int fp_equal(const fp* a, const fp* b);

/**
 * @brief Сложение двух элементов
 * 
 * @param[out] r Результат: r = a + b mod p
 * @param[in] a Первое слагаемое
 * @param[in] b Второе слагаемое
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_add(fp* r, const fp* a, const fp* b, const fp_ctx* ctx);

/**
 * @brief Вычитание двух элементов
 * 
 * @param[out] r Результат: r = a - b mod p
 * @param[in] a Уменьшаемое
 * @param[in] b Вычитаемое
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_sub(fp* r, const fp* a, const fp* b, const fp_ctx* ctx);

/**
 * @brief Отрицание элемента
 * 
 * @param[out] r Результат: r = -a mod p
 * @param[in] a Исходный элемент
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_neg(fp* r, const fp* a, const fp_ctx* ctx);

/**
 * @brief Умножение двух элементов (Montgomery)
 * 
 * @param[out] r Результат: r = a * b mod p
 * @param[in] a Первый множитель
 * @param[in] b Второй множитель
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_mul(fp* r, const fp* a, const fp* b, const fp_ctx* ctx);

/**
 * @brief Возведение в квадрат
 * 
 * @param[out] r Результат: r = a^2 mod p
 * @param[in] a Исходный элемент
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_sqr(fp* r, const fp* a, const fp_ctx* ctx);

/**
 * @brief Инверсия элемента
 * 
 * @param[out] r Результат: r = a^-1 mod p
 * @param[in] a Исходный элемент (не может быть нулевым)
 * @param[in] ctx Контекст арифметики
 * 
 * @return 1 при успехе, 0 при ошибке (например, если a = 0)
 * 
 * @note Constant-time операция
 */
int fp_inv(fp* r, const fp* a, const fp_ctx* ctx);

/**
 * @brief Деление двух элементов
 * 
 * @param[out] r Результат: r = a * b^-1 mod p
 * @param[in] a Делимое
 * @param[in] b Делитель (не может быть нулевым)
 * @param[in] ctx Контекст арифметики
 * 
 * @return 1 при успехе, 0 при ошибке
 * 
 * @note Constant-time операция
 */
int fp_div(fp* r, const fp* a, const fp* b, const fp_ctx* ctx);

/**
 * @brief Генерация криптографически безопасного случайного элемента
 * 
 * @param[out] r Случайный элемент в [0, p-1]
 * 
 * @note Constant-time операция
 */
void fp_rand(fp* r);

/**
 * @brief Преобразование байтового массива в элемент поля
 * 
 * @param[out] r Результат: элемент поля
 * @param[in] bytes Исходные байты
 * @param[in] len Длина байтового массива
 * 
 * @note Если len < sizeof(fp), оставшиеся байты заполняются нулями
 * @note Если len > sizeof(fp), лишние байты игнорируются
 * @note Результат всегда принадлежит [0, p-1] после редукции
 * 
 * @note Constant-time операция
 */
void fp_from_bytes(fp* r, const uint8_t* bytes, size_t len);

/**
 * @brief Преобразование элемента поля в байтовый массив
 * 
 * @param[out] bytes Результат: байты в big-endian формате
 * @param[in] a Исходный элемент
 * 
 * @note Constant-time операция
 */
void fp_to_bytes(uint8_t* bytes, const fp* a);

/**
 * @brief Символ Лежандра
 * 
 * @param[in] a Исследуемый элемент
 * @param[in] ctx Контекст арифметики
 * @return 
 *   -1 если a - не квадратичный вычет mod p
 *    0 если a = 0 mod p
 *    1 если a - квадратичный вычет mod p
 * 
 * @note Constant-time операция
 */
int fp_legendre(const fp* a, const fp_ctx* ctx);

/**
 * @brief Извлечение квадратного корня
 * 
 * @param[out] r Результат: r^2 = a mod p (один из корней)
 * @param[in] a Исследуемый элемент
 * @param[in] ctx Контекст арифметики
 * 
 * @return 1 если корень существует, 0 иначе
 * 
 * @note Для CSIDH-512 p ≡ 3 (mod 4), используется алгоритм: r = a^((p+1)/4) mod p
 * @note Constant-time операция
 */
int fp_sqrt(fp* r, const fp* a, const fp_ctx* ctx);

/**
 * @brief Преобразование в Montgomery представление
 * 
 * @param[out] r Результат: r = a * R mod p
 * @param[in] a Исходный элемент
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_to_montgomery(fp* r, const fp* a, const fp_ctx* ctx);

/**
 * @brief Преобразование из Montgomery представления
 * 
 * @param[out] r Результат: r = a * R^-1 mod p
 * @param[in] a Элемент в Montgomery представлении
 * @param[in] ctx Контекст арифметики
 * 
 * @note Constant-time операция
 */
void fp_from_montgomery(fp* r, const fp* a, const fp_ctx* ctx);

/**
 * @brief Безопасное обнуление элемента
 * 
 * @param[in,out] a Элемент для обнуления
 * 
 * @note Гарантированно не оптимизируется компилятором
 * @note Обнуляет всю память, занимаемую элементом
 */
void fp_secure_zeroize(fp* a);

/**
 * @brief Constant-time сравнение двух элементов
 * 
 * @param[in] a Первый элемент
 * @param[in] b Второй элемент
 * @return -1, 0, или 1 в зависимости от сравнения
 * 
 * @note Время выполнения не зависит от значений a и b
 */
int fp_constant_time_compare(const fp* a, const fp* b);

#ifdef __cplusplus
}
#endif

#endif // TORUS_CSIDH_MATH_FP_H
