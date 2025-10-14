#ifndef TORUSCSIDH_GEOMETRIC_VALIDATOR_H
#define TORUSCSIDH_GEOMETRIC_VALIDATOR_H

#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/laplacian_matrix.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/clustering_coefficient.hpp>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>
#include <boost/numeric/ublas/lu.hpp>
#include <boost/numeric/ublas/eigen.hpp>
#include "elliptic_curve.h"
#include "security_constants.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

// Определение пользовательского свойства для хранения кривой в вершине графа
struct vertex_curve_t {
    typedef boost::vertex_property_tag kind;
};

// Тип графа изогений с информацией о кривых в вершинах
typedef boost::property<vertex_curve_t, MontgomeryCurve> VertexProperty;
typedef boost::adjacency_list<
    boost::vecS, 
    boost::vecS, 
    boost::undirectedS,
    VertexProperty,
    boost::property<boost::edge_index_t, int>
> IsogenyGraph;

/**
 * @brief Класс для геометрической проверки кривых
 * 
 * Реализует математически точную проверку кривых на основе анализа
 * их локальной позиции в графе изогений. Проверка основана на точных
 * вычислениях цикломатического числа и спектрального зазора.
 */
class GeometricValidator {
public:
    /**
     * @brief Конструктор
     * 
     * @param security_level Уровень безопасности
     */
    explicit GeometricValidator(SecurityConstants::SecurityLevel security_level);
    
    /**
     * @brief Проверка кривой на безопасность
     * 
     * Выполняет точную геометрическую проверку кривой.
     * 
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая для проверки
     * @param cyclomatic_score Результат проверки цикломатического числа
     * @param spectral_score Результат проверки спектрального зазора
     * @return true, если кривая легитимна
     */
    bool validate_curve(const MontgomeryCurve& base_curve,
                       const MontgomeryCurve& public_curve,
                       double& cyclomatic_score,
                       double& spectral_score);
    
    /**
     * @brief Построение локального подграфа изогений
     * 
     * Строит небольшой подграф изогений вокруг базовой кривой.
     * 
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая
     * @return Подграф изогений
     */
    IsogenyGraph build_local_subgraph(const MontgomeryCurve& base_curve,
                                    const MontgomeryCurve& public_curve);
    
    /**
     * @brief Вычисление цикломатического числа
     * 
     * Цикломатическое число = E - V + C, где
     * E - количество ребер
     * V - количество вершин
     * C - количество компонент связности
     * 
     * @param graph Граф изогений
     * @return Нормализованное цикломатическое число [0,1]
     */
    double compute_cyclomatic_number(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление спектрального зазора
     * 
     * Спектральный зазор = (λ₄ - λ₃) / λ₃
     * где λ₃, λ₄ - собственные значения нормализованной матрицы Лапласа
     * 
     * @param graph Граф изогений
     * @return Нормализованный спектральный зазор [0,1]
     */
    double compute_spectral_gap(const IsogenyGraph& graph) const;
    
    /**
     * @brief Проверка целостности геометрической проверки
     * 
     * @return true, если геометрическая проверка цела
     */
    bool verify_integrity() const;
    
private:
    /**
     * @brief Получение кривой из вершины графа
     * 
     * @param graph Граф изогений
     * @param v Вершина графа
     * @return Кривая, соответствующая вершине
     */
    const MontgomeryCurve& get_curve_from_vertex(const IsogenyGraph& graph, 
                                              IsogenyGraph::vertex_descriptor v) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление матрицы Лапласа
     * 
     * @param graph Граф изогений
     * @return Матрица Лапласа
     */
    boost::numeric::ublas::matrix<double> compute_laplacian_matrix(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление собственных значений матрицы
     * 
     * @param matrix Матрица
     * @return Собственные значения
     */
    std::vector<double> compute_eigenvalues(const boost::numeric::ublas::matrix<double>& matrix) const;
    
    SecurityConstants::SecurityLevel security_level_; // Уровень безопасности
    int subgraph_radius_; // Радиус подграфа для анализа
    std::mutex validator_mutex_; // Мьютекс для синхронизации
};

} // namespace toruscsidh

#endif // TORUSCSIDH_GEOMETRIC_VALIDATOR_H
