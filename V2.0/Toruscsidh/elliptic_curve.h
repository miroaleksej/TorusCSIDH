#ifndef TORUSCSIDH_ELLIPTIC_CURVE_H
#define TORUSCSIDH_ELLIPTIC_CURVE_H

#include <vector>
#include <gmpxx.h>
#include <cmath>
#include <stdexcept>
#include <algorithm>
#include "security_constants.h"
#include "geometric_validator.h"

namespace toruscsidh {

/**
 * @brief Класс для представления точки на эллиптической кривой в проективных координатах
 * 
 * Использует представление (X:Z) для эффективных вычислений на кривой Монтгомери.
 */
class EllipticCurvePoint {
public:
    /**
     * @brief Конструктор точки
     * 
     * @param x Координата X
     * @param z Координата Z
     */
    EllipticCurvePoint(const GmpRaii& x = GmpRaii(0), const GmpRaii& z = GmpRaii(1));
    
    /**
     * @brief Проверка, является ли точка бесконечностью
     * 
     * @return true, если точка является бесконечностью
     */
    bool is_infinity() const;
    
    /**
     * @brief Проверка, лежит ли точка на кривой
     * 
     * @param curve Кривая
     * @return true, если точка лежит на кривой
     */
    bool is_on_curve(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Сложение точек (алгоритм Лопес-Дахаб)
     * 
     * @param other Другая точка
     * @param curve Кривая
     * @return Результат сложения
     */
    EllipticCurvePoint add(const EllipticCurvePoint& other, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Удвоение точки
     * 
     * @param curve Кривая
     * @return Удвоенная точка
     */
    EllipticCurvePoint double_point(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Умножение точки на скаляр
     * 
     * Использует алгоритм двоичного возведения в степень для эффективных вычислений.
     * 
     * @param scalar Скаляр
     * @param curve Кривая
     * @return Результат умножения
     */
    EllipticCurvePoint scalar_multiply(const GmpRaii& scalar, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка порядка точки
     * 
     * @param order Порядок
     * @param curve Кривая
     * @return true, если точка имеет указанный порядок
     */
    bool has_order(unsigned int order, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка имеет ненулевой порядок
     * 
     * @param curve Кривая
     * @return true, если точка имеет ненулевой порядок
     */
    bool has_nonzero_order(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Поиск точки заданного порядка
     * 
     * @param order Порядок
     * @param curve Кривая
     * @return Точка заданного порядка
     */
    static EllipticCurvePoint find_point_of_order(unsigned int order, const MontgomeryCurve& curve);
    
    /**
     * @brief Вычисление j-инварианта точки
     * 
     * @return j-инвариант
     */
    GmpRaii compute_j_invariant() const;
    
    /**
     * @brief Получение координаты X
     * 
     * @return Координата X
     */
    const GmpRaii& get_x() const;
    
    /**
     * @brief Получение координаты Z
     * 
     * @return Координата Z
     */
    const GmpRaii& get_z() const;
    
    /**
     * @brief Проверка, что точка является генератором
     * 
     * @param curve Кривая
     * @return true, если точка является генератором
     */
    bool is_generator(const MontgomeryCurve& curve) const;
    
private:
    GmpRaii x;  // Координата X
    GmpRaii z;  // Координата Z
};

/**
 * @brief Класс для представления эллиптической кривой в форме Монтгомери
 * 
 * Кривая задается уравнением: By^2 = x^3 + Ax^2 + x над полем F_p.
 */
class MontgomeryCurve {
public:
    /**
     * @brief Конструктор кривой
     * 
     * @param A Параметр A кривой
     * @param p Характеристика поля
     */
    MontgomeryCurve(const GmpRaii& A, const GmpRaii& p);
    
    /**
     * @brief Конструктор кривой с параметром B
     * 
     * @param A Параметр A кривой
     * @param B Параметр B кривой
     * @param p Характеристика поля
     */
    MontgomeryCurve(const GmpRaii& A, const GmpRaii& B, const GmpRaii& p);
    
    /**
     * @brief Проверка, является ли кривая суперсингулярной
     * 
     * @return true, если кривая суперсингулярна
     */
    bool is_supersingular() const;
    
    /**
     * @brief Вычисление j-инварианта кривой
     * 
     * j-инвариант определяется как: j = 1728 * (4A^3) / (4A^3 + 27B^2)
     * Для кривой Монтгомери B = 1, поэтому: j = 1728 * (4A^3) / (4A^3 + 27)
     * 
     * @return j-инвариант кривой
     */
    GmpRaii compute_j_invariant() const;
    
    /**
     * @brief Вычисление порядка кривой
     * 
     * @return Порядок кривой
     */
    GmpRaii compute_order() const;
    
    /**
     * @brief Вычисление изогении заданной степени
     * 
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny(const EllipticCurvePoint& kernel_point, unsigned int degree) const;
    
    /**
     * @brief Вычисление изогении степени 3
     * 
     * @param kernel_point Точка ядра
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny_degree_3(const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Вычисление изогении степени 5
     * 
     * @param kernel_point Точка ядра
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny_degree_5(const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Вычисление изогении степени 7
     * 
     * @param kernel_point Точка ядра
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny_degree_7(const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Поиск точки заданного порядка
     * 
     * @param order Порядок точки
     * @return Точка заданного порядка
     */
    EllipticCurvePoint find_point_of_order(unsigned int order) const;
    
    /**
     * @brief Проверка безопасности кривой для CSIDH
     * 
     * @return true, если кривая безопасна для использования в CSIDH
     */
    bool is_secure_for_csidh() const;
    
    /**
     * @brief Проверка, эквивалентны ли две кривые
     * 
     * @param other Другая кривая
     * @return true, если кривые эквивалентны
     */
    bool is_equivalent_to(const MontgomeryCurve& other) const;
    
    /**
     * @brief Получение параметра A
     * 
     * @return Параметр A
     */
    const GmpRaii& get_A() const;
    
    /**
     * @brief Получение параметра B
     * 
     * @return Параметр B
     */
    const GmpRaii& get_B() const;
    
    /**
     * @brief Получение характеристики поля
     * 
     * @return Характеристика поля
     */
    const GmpRaii& get_p() const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру для TorusCSIDH
     * 
     * @return true, если кривая соответствует требованиям
     */
    bool has_valid_torus_structure() const;
    
    /**
     * @brief Вычисление квадратичного вычета
     * 
     * @param a Число для проверки
     * @return true, если a является квадратичным вычетом
     */
    bool is_quadratic_residue(const GmpRaii& a) const;
    
private:
    GmpRaii A;  // Параметр A кривой
    GmpRaii B;  // Параметр B кривой (обычно 1 для кривых Монтгомери)
    GmpRaii p;  // Характеристика поля
    
    /**
     * @brief Вычисление квадратного корня в поле F_p
     * 
     * @param a Число, из которого извлекается корень
     * @return Квадратный корень
     */
    GmpRaii sqrtm(const GmpRaii& a) const;
};

/**
 * @brief Вспомогательный класс для работы с квадратичными вычетами
 */
class QuadraticResidue {
public:
    /**
     * @brief Проверка, является ли число квадратичным вычетом
     * 
     * @param a Число для проверки
     * @param p Характеристика поля
     * @return true, если a является квадратичным вычетом
     */
    static bool is_quadratic_residue(const GmpRaii& a, const GmpRaii& p);
    
    /**
     * @brief Вычисление квадратного корня в поле F_p
     * 
     * Использует алгоритм Тонелли-Шенкса.
     * 
     * @param a Число, из которого извлекается корень
     * @param p Характеристика поля
     * @return Квадратный корень
     */
    static GmpRaii sqrtm(const GmpRaii& a, const GmpRaii& p);
    
    /**
     * @brief Вычисление символа Лежандра
     * 
     * @param a Число
     * @param p Характеристика поля
     * @return Символ Лежандра
     */
    static int legendre_symbol(const GmpRaii& a, const GmpRaii& p);
};

} // namespace toruscsidh

#endif // TORUSCSIDH_ELLIPTIC_CURVE_H
