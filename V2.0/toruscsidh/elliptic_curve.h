#ifndef TORUSCSIDH_ELLIPTIC_CURVE_H
#define TORUSCSIDH_ELLIPTIC_CURVE_H

#include <vector>
#include <gmpxx.h>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>
#include "security_constants.h"

namespace toruscsidh {

/**
 * @brief Класс для представления точки на эллиптической кривой
 * 
 * Реализует операции над точками эллиптической кривой в проективных координатах
 * для защиты от атак по времени и энергопотреблению.
 */
class EllipticCurvePoint {
public:
    /**
     * @brief Конструктор точки
     * 
     * @param x Координата x в проективных координатах
     * @param z Координата z в проективных координатах
     * @param p Характеристика поля
     */
    EllipticCurvePoint(const GmpRaii& x, const GmpRaii& z, const GmpRaii& p);
    
    /**
     * @brief Конструктор точки в аффинных координатах
     * 
     * @param x Координата x в аффинных координатах
     * @param y Координата y в аффинных координатах
     * @param p Характеристика поля
     */
    EllipticCurvePoint(const GmpRaii& x, const GmpRaii& y, const GmpRaii& p);
    
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
     * @param curve Кривая для проверки
     * @return true, если точка лежит на кривой
     */
    bool is_on_curve(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Получение аффинной координаты x
     * 
     * @return Аффинная координата x
     */
    GmpRaii get_x() const;
    
    /**
     * @brief Получение аффинной координаты y
     * 
     * @return Аффинная координата y
     */
    GmpRaii get_y() const;
    
    /**
     * @brief Получение проективной координаты x
     * 
     * @return Проективная координата x
     */
    const GmpRaii& get_x_projective() const;
    
    /**
     * @brief Получение проективной координаты z
     * 
     * @return Проективная координата z
     */
    const GmpRaii& get_z_projective() const;
    
    /**
     * @brief Получение характеристики поля
     * 
     * @return Характеристика поля
     */
    const GmpRaii& get_p() const;
    
    /**
     * @brief Проверка, имеет ли точка заданный порядок
     * 
     * @param order Порядок для проверки
     * @param curve Кривая, на которой находится точка
     * @return true, если точка имеет заданный порядок
     */
    bool has_order(const GmpRaii& order, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Добавление точки
     * 
     * Выполняет операцию сложения двух точек на эллиптической кривой.
     * 
     * @param other Другая точка
     * @param curve Кривая, на которой выполняется операция
     * @return Результат сложения
     */
    EllipticCurvePoint add(const EllipticCurvePoint& other, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Удвоение точки
     * 
     * Выполняет операцию удвоения точки на эллиптической кривой.
     * 
     * @param curve Кривая, на которой выполняется операция
     * @return Результат удвоения
     */
    EllipticCurvePoint double_point(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Умножение точки на скаляр
     * 
     * Выполняет операцию умножения точки на скаляр с использованием
     * алгоритма Монтгомери для защиты от атак по времени.
     * 
     * @param scalar Скаляр
     * @param curve Кривая, на которой выполняется операция
     * @return Результат умножения
     */
    EllipticCurvePoint multiply(const GmpRaii& scalar, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка равенства точек
     * 
     * @param other Другая точка
     * @return true, если точки равны
     */
    bool is_equal_to(const EllipticCurvePoint& other) const;
    
    /**
     * @brief Проверка, что точка имеет малый порядок
     * 
     * @param order Порядок
     * @param curve Кривая
     * @return true, если точка имеет малый порядок
     */
    bool has_small_order(unsigned int order, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка является ядром изогении
     * 
     * @param degree Степень изогении
     * @param curve Кривая
     * @return true, если точка является ядром изогении
     */
    bool is_kernel_point(unsigned int degree, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка является базисом для изогении
     * 
     * @param degree Степень изогении
     * @param curve Кривая
     * @return true, если точка является базисом для изогении
     */
    bool is_basis_point(unsigned int degree, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Получение точки в аффинных координатах
     * 
     * @return Точка в аффинных координатах
     */
    std::pair<GmpRaii, GmpRaii> to_affine() const;
    
    /**
     * @brief Получение точки в проективных координатах
     * 
     * @return Точка в проективных координатах
     */
    std::pair<GmpRaii, GmpRaii> to_projective() const;
    
    /**
     * @brief Проверка, что точка является кручением
     * 
     * @param curve Кривая
     * @return true, если точка является кручением
     */
    bool is_torsion_point(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление порядка точки
     * 
     * @param curve Кривая
     * @return Порядок точки
     */
    GmpRaii compute_order(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка является генератором подгруппы
     * 
     * @param order Порядок подгруппы
     * @param curve Кривая
     * @return true, если точка является генератором подгруппы
     */
    bool is_generator_of_subgroup(const GmpRaii& order, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка имеет порядок, делящийся на заданное число
     * 
     * @param divisor Делитель
     * @param curve Кривая
     * @return true, если порядок точки делится на заданное число
     */
    bool order_divides(const GmpRaii& divisor, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка имеет порядок, кратный заданному числу
     * 
     * @param multiple Кратное
     * @param curve Кривая
     * @return true, если порядок точки кратен заданному числу
     */
    bool order_is_multiple_of(const GmpRaii& multiple, const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что точка имеет максимальный порядок
     * 
     * @param curve Кривая
     * @return true, если точка имеет максимальный порядок
     */
    bool has_maximal_order(const class MontgomeryCurve& curve) const;
    
private:
    GmpRaii x_; ///< Проективная координата x
    GmpRaii z_; ///< Проективная координата z
    GmpRaii p_; ///< Характеристика поля
};

/**
 * @brief Класс для представления эллиптической кривой в форме Монтгомери
 * 
 * Реализует операции с эллиптическими кривыми в форме Монтгомери:
 * By² = x³ + Ax² + x
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
     * @brief Деструктор
     */
    ~MontgomeryCurve();
    
    /**
     * @brief Получение параметра A кривой
     * 
     * @return Параметр A
     */
    const GmpRaii& get_A() const;
    
    /**
     * @brief Получение характеристики поля
     * 
     * @return Характеристика поля
     */
    const GmpRaii& get_p() const;
    
    /**
     * @brief Вычисление j-инварианта кривой
     * 
     * j-инвариант для кривой в форме Монтгомери:
     * j = 256 * (A² - 3)³ / (A² - 4)
     * 
     * @return j-инвариант
     */
    GmpRaii compute_j_invariant() const;
    
    /**
     * @brief Проверка, является ли кривая суперсингулярной
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
     * @brief Проверка, что кривая безопасна для CSIDH
     * 
     * @return true, если кривая безопасна для CSIDH
     */
    bool is_secure_for_csidh() const;
    
    /**
     * @brief Проверка, что кривая является легитимной для TorusCSIDH
     * 
     * @return true, если кривая легитимна
     */
    bool is_legitimate_for_toruscsidh() const;
    
    /**
     * @brief Вычисление порядка кривой
     * 
     * @return Порядок кривой
     */
    GmpRaii compute_order() const;
    
    /**
     * @brief Проверка эквивалентности кривых
     * 
     * @param other Другая кривая
     * @return true, если кривые эквивалентны
     */
    bool is_equivalent_to(const MontgomeryCurve& other) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную характеристику
     * 
     * @return true, если кривая имеет правильную характеристику
     */
    bool has_valid_characteristic() const;
    
    /**
     * @brief Проверка, что кривая имеет правильный параметр A
     * 
     * @return true, если кривая имеет правильный параметр A
     */
    bool has_valid_parameter_A() const;
    
    /**
     * @brief Проверка, что кривая является суперсингулярной для CSIDH
     * 
     * @return true, если кривая является суперсингулярной для CSIDH
     */
    bool is_supersingular_for_csidh() const;
    
    /**
     * @brief Проверка, что кривая имеет правильный порядок
     * 
     * @return true, если кривая имеет правильный порядок
     */
    bool has_valid_order() const;
    
    /**
     * @brief Проверка, что кривая имеет правильные изогении
     * 
     * @return true, если кривая имеет правильные изогении
     */
    bool has_valid_isogenies() const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру графа изогений
     * 
     * @return true, если кривая имеет правильную структуру графа изогений
     */
    bool has_valid_isogeny_graph_structure() const;
    
    /**
     * @brief Вычисление изогении с использованием формул Велю
     * 
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny_velu(const EllipticCurvePoint& kernel_point, unsigned int degree) const;
    
    /**
     * @brief Проверка, что кривая является базовой для TorusCSIDH
     * 
     * @return true, если кривая является базовой
     */
    bool is_base_curve() const;
    
    /**
     * @brief Проверка, что кривая является публичной
     * 
     * @return true, если кривая является публичной
     */
    bool is_public_curve() const;
    
    /**
     * @brief Проверка, что кривая является приватной
     * 
     * @return true, если кривая является приватной
     */
    bool is_private_curve() const;
    
    /**
     * @brief Проверка, что кривая является эфемерной
     * 
     * @return true, если кривая является эфемерной
     */
    bool is_ephemeral_curve() const;
    
private:
    GmpRaii A_; ///< Параметр A кривой
    GmpRaii p_; ///< Характеристика поля
    
    /**
     * @brief Вычисление многочлена деления
     * 
     * @param n Степень многочлена
     * @return Многочлен деления
     */
    GmpRaii compute_division_polynomial(unsigned int n) const;
    
    /**
     * @brief Вычисление многочлена деления с использованием рекуррентных соотношений
     * 
     * @param n Степень многочлена
     * @return Многочлен деления
     */
    GmpRaii compute_division_polynomial_recursive(unsigned int n) const;
    
    /**
     * @brief Вычисление многочлена деления с использованием формулы Велю
     * 
     * @param n Степень многочлена
     * @return Многочлен деления
     */
    GmpRaii compute_division_polynomial_velu(unsigned int n) const;
    
    /**
     * @brief Вычисление многочлена деления для четных n
     * 
     * @param n Степень многочлена
     * @return Многочлен деления
     */
    GmpRaii compute_division_polynomial_even(unsigned int n) const;
    
    /**
     * @brief Вычисление многочлена деления для нечетных n
     * 
     * @param n Степень многочлена
     * @return Многочлен деления
     */
    GmpRaii compute_division_polynomial_odd(unsigned int n) const;
    
    /**
     * @brief Проверка, что точка является точкой ядра
     * 
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return true, если точка является точкой ядра
     */
    bool is_valid_kernel_point(const EllipticCurvePoint& kernel_point, unsigned int degree) const;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_ELLIPTIC_CURVE_H
