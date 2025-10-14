#ifndef TORUSCSIDH_ELLIPTIC_CURVE_H
#define TORUSCSIDH_ELLIPTIC_CURVE_H

#include <vector>
#include <gmpxx.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>
#include "security_constants.h"
#include "secure_random.h"

namespace toruscsidh {

/**
 * @brief Класс для представления точки на эллиптической кривой
 */
class EllipticCurvePoint {
public:
    /**
     * @brief Конструктор
     * 
     * @param x x-координата
     * @param z z-координата
     */
    EllipticCurvePoint(const GmpRaii& x, const GmpRaii& z);
    
    /**
     * @brief Деструктор
     */
    ~EllipticCurvePoint();
    
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
     * @brief Получение x-координаты
     * 
     * @return x-координата
     */
    GmpRaii get_x() const;
    
    /**
     * @brief Получение z-координаты
     * 
     * @return z-координата
     */
    GmpRaii get_z() const;
    
    /**
     * @brief Вычисление скалярного умножения точки
     * 
     * @param k Скаляр
     * @param curve Кривая
     * @return Результат скалярного умножения
     */
    EllipticCurvePoint scalar_multiply(const GmpRaii& k, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка порядка точки
     * 
     * @param order Ожидаемый порядок
     * @param curve Кривая
     * @return true, если точка имеет указанный порядок
     */
    bool has_order(const GmpRaii& order, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление двойной точки
     * 
     * @param curve Кривая
     * @return Двойная точка
     */
    EllipticCurvePoint double_point(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Сложение точек
     * 
     * @param other Другая точка
     * @param curve Кривая
     * @return Сумма точек
     */
    EllipticCurvePoint add_point(const EllipticCurvePoint& other, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычитание точек
     * 
     * @param other Другая точка
     * @param curve Кривая
     * @return Разность точек
     */
    EllipticCurvePoint subtract_point(const EllipticCurvePoint& other, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка равенства точек
     * 
     * @param other Другая точка
     * @return true, если точки равны
     */
    bool operator==(const EllipticCurvePoint& other) const;
    
    /**
     * @brief Проверка неравенства точек
     * 
     * @param other Другая точка
     * @return true, если точки не равны
     */
    bool operator!=(const EllipticCurvePoint& other) const;
    
private:
    GmpRaii x_; ///< x-координата
    GmpRaii z_; ///< z-координата
};

/**
 * @brief Класс для представления кривой Монтгомери
 */
class MontgomeryCurve {
public:
    /**
     * @brief Конструктор
     * 
     * @param A Параметр A кривой
     * @param B Параметр B кривой (обычно 1)
     * @param p Характеристика поля
     */
    MontgomeryCurve(const GmpRaii& A, const GmpRaii& B, const GmpRaii& p);
    
    /**
     * @brief Деструктор
     */
    ~MontgomeryCurve();
    
    /**
     * @brief Получение параметра A
     * 
     * @return Параметр A
     */
    GmpRaii get_A() const;
    
    /**
     * @brief Получение параметра B
     * 
     * @return Параметр B
     */
    GmpRaii get_B() const;
    
    /**
     * @brief Получение характеристики поля
     * 
     * @return Характеристика поля
     */
    GmpRaii get_p() const;
    
    /**
     * @brief Вычисление j-инварианта кривой
     * 
     * j = 256 * (A^2 - 3)^3 / (A^2 - 4)
     * 
     * @return j-инвариант
     */
    GmpRaii compute_j_invariant() const;
    
    /**
     * @brief Проверка суперсингулярности кривой
     * 
     * @return true, если кривая суперсингулярна
     */
    bool is_supersingular() const;
    
    /**
     * @brief Проверка, имеет ли кривая правильную структуру для TorusCSIDH
     * 
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_torus_structure() const;
    
    /**
     * @brief Вычисление порядка кривой
     * 
     * @return Порядок кривой
     */
    GmpRaii compute_order() const;
    
    /**
     * @brief Поиск точки заданного порядка
     * 
     * @param order Порядок точки
     * @return Точка заданного порядка
     */
    EllipticCurvePoint find_point_of_order(unsigned int order) const;
    
    /**
     * @brief Вычисление изогении степени 3
     * 
     * @param kernel_point Точка ядра
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny_degree_3(const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Вычисление изогении степени 5
     * 
     * @param kernel_point Точка ядра
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny_degree_5(const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Вычисление изогении степени 7
     * 
     * @param kernel_point Точка ядра
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny_degree_7(const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Вычисление изогении общей степени
     * 
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny_general(const EllipticCurvePoint& kernel_point, unsigned int degree) const;
    
    /**
     * @brief Вычисление изогении
     * 
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny(const EllipticCurvePoint& kernel_point, unsigned int degree) const;
    
    /**
     * @brief Проверка эквивалентности кривых
     * 
     * @param other Другая кривая
     * @return true, если кривые эквивалентны
     */
    bool is_equivalent_to(const MontgomeryCurve& other) const;
    
    /**
     * @brief Вычисление квадратного корня по модулю p
     * 
     * @param a Число
     * @param p Модуль
     * @return Квадратный корень
     */
    static GmpRaii sqrt_mod_p(const GmpRaii& a, const GmpRaii& p);
    
    /**
     * @brief Вычисление символа Лежандра
     * 
     * @param a Число
     * @param p Модуль
     * @return Символ Лежандра
     */
    static int legendre_symbol(const GmpRaii& a, const GmpRaii& p);
    
    /**
     * @brief Вычисление обратного элемента по модулю p
     * 
     * @param a Число
     * @param p Модуль
     * @return Обратный элемент
     */
    static GmpRaii modular_inverse(const GmpRaii& a, const GmpRaii& p);
    
    /**
     * @brief Проверка, является ли число квадратичным вычетом по модулю p
     * 
     * @param a Число
     * @param p Модуль
     * @return true, если число является квадратичным вычетом
     */
    static bool is_quadratic_residue(const GmpRaii& a, const GmpRaii& p);
    
private:
    GmpRaii A_; ///< Параметр A кривой
    GmpRaii B_; ///< Параметр B кривой
    GmpRaii p_; ///< Характеристика поля
};

} // namespace toruscsidh

#endif // TORUSCSIDH_ELLIPTIC_CURVE_H
