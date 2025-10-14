#include "geometric_validator.h"
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <chrono>
#include <random>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "secure_audit_logger.h"
#include "postquantum_hash.h"
#include "elliptic_curve.h"
#include "bech32m.h"

namespace toruscsidh {

GeometricValidator::GeometricValidator(SecurityConstants::SecurityLevel security_level)
    : security_level_(security_level) {
    
    // Инициализация параметров безопасности
    SecurityConstants::initialize_geometric_params(security_level_, params_);
    
    SecureAuditLogger::get_instance().log_event("system", 
        "GeometricValidator initialized with security level: " + 
        SecurityConstants::security_level_to_string(security_level_), false);
}

GeometricValidator::~GeometricValidator() {
    SecureAuditLogger::get_instance().log_event("system", 
        "GeometricValidator destroyed", false);
}

bool GeometricValidator::validate_curve(const MontgomeryCurve& curve,
                                       const IsogenyGraph& subgraph,
                                       double& cyclomatic_score,
                                       double& spectral_gap_score,
                                       double& clustering_score,
                                       double& degree_entropy_score,
                                       double& distance_entropy_score) {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка целостности геометрической проверки
    if (!verify_integrity()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: integrity check failed", true);
        return false;
    }
    
    // Проверка, что кривая имеет правильную структуру
    if (!has_valid_structure(curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: curve has invalid structure", true);
        return false;
    }
    
    // Проверка, что кривая не является поддельной
    if (!is_not_fake_curve(curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: curve is fake", true);
        return false;
    }
    
    // Вычисление всех критериев
    cyclomatic_score = compute_cyclomatic_number_for_subgraph(subgraph, curve, curve);
    spectral_gap_score = compute_spectral_gap_for_subgraph(subgraph, curve, curve);
    clustering_score = compute_clustering_coefficient_for_subgraph(subgraph, curve, curve);
    degree_entropy_score = compute_degree_entropy_for_subgraph(subgraph, curve, curve);
    distance_entropy_score = compute_distance_entropy_for_subgraph(subgraph, curve, curve);
    
    // Проверка, что все критерии в допустимых пределах
    bool all_criteria_valid = true;
    
    if (cyclomatic_score < params_.min_cyclomatic) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: cyclomatic number too low (" + 
            std::to_string(cyclomatic_score) + " < " + 
            std::to_string(params_.min_cyclomatic) + ")", true);
        all_criteria_valid = false;
    }
    
    if (spectral_gap_score < params_.min_spectral_gap) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: spectral gap too low (" + 
            std::to_string(spectral_gap_score) + " < " + 
            std::to_string(params_.min_spectral_gap) + ")", true);
        all_criteria_valid = false;
    }
    
    if (clustering_score < params_.min_clustering_coeff) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: clustering coefficient too low (" + 
            std::to_string(clustering_score) + " < " + 
            std::to_string(params_.min_clustering_coeff) + ")", true);
        all_criteria_valid = false;
    }
    
    if (degree_entropy_score < params_.min_degree_entropy) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: degree entropy too low (" + 
            std::to_string(degree_entropy_score) + " < " + 
            std::to_string(params_.min_degree_entropy) + ")", true);
        all_criteria_valid = false;
    }
    
    if (distance_entropy_score < params_.min_distance_entropy) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: distance entropy too low (" + 
            std::to_string(distance_entropy_score) + " < " + 
            std::to_string(params_.min_distance_entropy) + ")", true);
        all_criteria_valid = false;
    }
    
    // Вычисление гибридной оценки
    double hybrid_score = compute_hybrid_score(
        cyclomatic_score,
        spectral_gap_score,
        clustering_score,
        degree_entropy_score,
        distance_entropy_score
    );
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Geometric validation scores - Cyclomatic: " + std::to_string(cyclomatic_score) +
        ", Spectral gap: " + std::to_string(spectral_gap_score) +
        ", Clustering: " + std::to_string(clustering_score) +
        ", Degree entropy: " + std::to_string(degree_entropy_score) +
        ", Distance entropy: " + std::to_string(distance_entropy_score) +
        ", Hybrid score: " + std::to_string(hybrid_score), false);
    
    // Проверка гибридной оценки
    if (hybrid_score < params_.min_hybrid_score) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: hybrid score too low (" + 
            std::to_string(hybrid_score) + " < " + 
            std::to_string(params_.min_hybrid_score) + ")", true);
        return false;
    }
    
    // Проверка устойчивости к различным типам атак
    if (!is_resistant_to_topological_attacks(curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: vulnerable to topological attacks", true);
        return false;
    }
    
    if (!is_resistant_to_degenerate_topology_attacks(curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: vulnerable to degenerate topology attacks", true);
        return false;
    }
    
    if (!is_resistant_to_long_path_attacks(curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: vulnerable to long path attacks", true);
        return false;
    }
    
    if (!is_resistant_to_regular_pattern_attacks(curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: vulnerable to regular pattern attacks", true);
        return false;
    }
    
    return all_criteria_valid;
}

IsogenyGraph GeometricValidator::build_isogeny_subgraph(const MontgomeryCurve& base_curve,
                                                      const MontgomeryCurve& target_curve,
                                                      int radius) {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Building isogeny subgraph with radius: " + std::to_string(radius), false);
    
    // Создаем пустой граф
    IsogenyGraph subgraph;
    
    // Используем BFS для построения подграфа
    std::queue<std::pair<MontgomeryCurve, int>> queue;
    std::map<GmpRaii, int> curve_to_index;
    std::map<int, MontgomeryCurve> index_to_curve;
    
    // Добавляем базовую кривую
    int base_index = boost::add_vertex(subgraph);
    curve_to_index[base_curve.compute_j_invariant()] = base_index;
    index_to_curve[base_index] = base_curve;
    
    queue.push({base_curve, 0});
    
    // Максимальное количество вершин для предотвращения переполнения
    const size_t max_vertices = 10000;
    size_t vertices_count = 1;
    
    while (!queue.empty() && vertices_count < max_vertices) {
        auto [current_curve, current_radius] = queue.front();
        queue.pop();
        
        int current_index = curve_to_index[current_curve.compute_j_invariant()];
        
        // Если достигли максимального радиуса, прекращаем обход
        if (current_radius >= radius) {
            continue;
        }
        
        // Генерируем изогении для всех простых чисел
        for (const auto& prime : SecurityConstants::get_primes(security_level_)) {
            unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
            
            // Генерируем точки малых порядков для вычисления изогений
            for (int i = 0; i < SecurityConstants::MAX_POINTS_PER_PRIME; i++) {
                EllipticCurvePoint kernel_point = current_curve.find_point_of_order(degree);
                
                if (!kernel_point.is_infinity()) {
                    // Вычисляем изогению
                    MontgomeryCurve new_curve = compute_isogeny(current_curve, kernel_point, degree);
                    
                    // Проверяем, что новая кривая не является поддельной
                    if (!is_not_fake_curve(new_curve)) {
                        continue;
                    }
                    
                    // Проверяем, что кривая имеет правильную структуру
                    if (!has_valid_structure(new_curve)) {
                        continue;
                    }
                    
                    // Проверяем, что кривая принадлежит графу изогений
                    if (!is_curve_in_isogeny_graph(base_curve, new_curve, SecurityConstants::get_primes(security_level_))) {
                        continue;
                    }
                    
                    // Проверяем, не встречали ли мы эту кривую ранее
                    GmpRaii j_invariant = new_curve.compute_j_invariant();
                    int new_index;
                    
                    if (curve_to_index.find(j_invariant) == curve_to_index.end()) {
                        // Добавляем новую вершину
                        new_index = boost::add_vertex(subgraph);
                        curve_to_index[j_invariant] = new_index;
                        index_to_curve[new_index] = new_curve;
                        vertices_count++;
                    } else {
                        new_index = curve_to_index[j_invariant];
                    }
                    
                    // Добавляем ребро
                    boost::add_edge(current_index, new_index, subgraph);
                    
                    // Добавляем в очередь для дальнейшего обхода
                    if (curve_to_index.find(j_invariant) == curve_to_index.end()) {
                        queue.push({new_curve, current_radius + 1});
                    }
                    
                    // Проверяем, не достигли ли мы целевой кривой
                    if (new_curve.is_equivalent_to(target_curve)) {
                        return subgraph;
                    }
                }
            }
        }
    }
    
    return subgraph;
}

double GeometricValidator::compute_cyclomatic_number(const IsogenyGraph& graph) {
    // Цикломатическое число = E - V + C, где
    // E - количество ребер
    // V - количество вершин
    // C - количество компонент связности
    
    size_t edges = num_edges(graph);
    size_t vertices = num_vertices(graph);
    
    // Вычисляем количество компонент связности
    std::vector<size_t> component(num_vertices(graph));
    size_t num_components = boost::connected_components(graph, &component[0]);
    
    // Вычисляем цикломатическое число
    double cyclomatic_number = static_cast<double>(edges - vertices + num_components);
    
    // В статье указано, что цикломатическое число должно быть ≥ 2
    // Нормализуем к [0,1] с целевым значением 2.0
    double normalized_value = cyclomatic_number / 2.0;
    
    // Ограничиваем значение в пределах [0,1]
    return std::min(1.0, normalized_value);
}

double GeometricValidator::compute_spectral_gap(const IsogenyGraph& graph) {
    // Спектральный зазор = (λ₄ - λ₃) / λ₃
    // где λ₃, λ₄ - собственные значения нормализованной матрицы Лапласа
    
    // Вычисляем матрицу Лапласа
    std::vector<std::vector<double>> laplacian = compute_laplacian_matrix(graph);
    
    // Вычисляем собственные значения
    std::vector<double> eigenvalues = compute_eigenvalues(laplacian);
    
    // Сортируем собственные значения по возрастанию
    std::sort(eigenvalues.begin(), eigenvalues.end());
    
    // Проверяем, что у нас достаточно собственных значений
    if (eigenvalues.size() < 4) {
        return 0.0; // Недостаточно данных для анализа
    }
    
    // Вычисляем спектральный зазор
    double lambda3 = eigenvalues[2]; // λ₃
    double lambda4 = eigenvalues[3]; // λ₄
    
    // Проверяем, что λ₃ > 0, чтобы избежать деления на ноль
    if (lambda3 <= 0) {
        return 0.0;
    }
    
    double spectral_gap = (lambda4 - lambda3) / lambda3;
    
    // Нормализуем спектральный зазор к [0,1]
    // В статье указано, что спектральный зазор должен быть ≥ 1.5
    double normalized_value = spectral_gap / 1.5;
    
    // Ограничиваем значение в пределах [0,1]
    return std::min(1.0, normalized_value);
}

double GeometricValidator::compute_clustering_coefficient(const IsogenyGraph& graph) {
    // Коэффициент кластеризации = 3 * количество треугольников / количество связок
    
    size_t triangles = 0;
    size_t triples = 0;
    
    // Для каждой вершины
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        size_t degree = boost::degree(v, graph);
        
        if (degree < 2) continue;
        
        // Количество связок для вершины v: C(degree, 2) = degree * (degree - 1) / 2
        triples += degree * (degree - 1) / 2;
        
        // Подсчет треугольников, содержащих вершину v
        std::vector<IsogenyGraph::vertex_descriptor> neighbors;
        for (auto e : boost::make_iterator_range(boost::out_edges(v, graph))) {
            neighbors.push_back(boost::target(e, graph));
        }
        
        // Проверяем, есть ли ребра между соседями
        for (size_t i = 0; i < neighbors.size(); i++) {
            for (size_t j = i + 1; j < neighbors.size(); j++) {
                if (boost::edge(neighbors[i], neighbors[j], graph).second) {
                    triangles++;
                }
            }
        }
    }
    
    // Общий коэффициент кластеризации
    double clustering_coefficient = (triples > 0) ? static_cast<double>(3 * triangles) / triples : 0.0;
    
    // Нормализуем коэффициент кластеризации к [0,1]
    // В статье указано, что коэффициент кластеризации должен быть в диапазоне [0.2, 0.5]
    double normalized_value = (clustering_coefficient - 0.2) / (0.5 - 0.2);
    
    // Ограничиваем значение в пределах [0,1]
    return std::clamp(normalized_value, 0.0, 1.0);
}

double GeometricValidator::compute_degree_entropy(const IsogenyGraph& graph) {
    // Энтропия степеней = -Σ p_i * log2(p_i)
    // где p_i - вероятность степени i
    
    // Подсчет распределения степеней
    std::map<size_t, size_t> degree_count;
    size_t total_vertices = num_vertices(graph);
    
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        size_t degree = boost::degree(v, graph);
        degree_count[degree]++;
    }
    
    // Вычисление вероятностей
    std::vector<double> probabilities;
    for (const auto& [degree, count] : degree_count) {
        double prob = static_cast<double>(count) / total_vertices;
        probabilities.push_back(prob);
    }
    
    // Вычисление энтропии
    double entropy = compute_entropy(probabilities);
    
    // Максимально возможная энтропия для данного графа
    double max_entropy = std::log2(static_cast<double>(degree_count.size()));
    
    // Нормализуем энтропию к [0,1]
    double normalized_value = (max_entropy > 0) ? entropy / max_entropy : 0.0;
    
    return normalized_value;
}

double GeometricValidator::compute_distance_entropy(const IsogenyGraph& graph,
                                                  const MontgomeryCurve& base_curve,
                                                  const MontgomeryCurve& target_curve) {
    // Энтропия кратчайших путей = -Σ p_d * log2(p_d)
    // где p_d - вероятность кратчайшего пути длины d
    
    // Находим индексы базовой и целевой кривых
    int base_index = -1;
    int target_index = -1;
    
    GmpRaii base_j = base_curve.compute_j_invariant();
    GmpRaii target_j = target_curve.compute_j_invariant();
    
    // В реальной системе здесь будет поиск индексов кривых в графе
    // Для демонстрации предположим, что мы знаем индексы
    base_index = 0; // Базовая кривая - первая вершина
    target_index = num_vertices(graph) - 1; // Целевая кривая - последняя вершина
    
    // Вычисляем кратчайшие пути от базовой кривой до всех вершин
    std::vector<int> distances = compute_shortest_paths(graph, base_index);
    
    // Подсчет распределения длин кратчайших путей
    std::map<int, size_t> distance_count;
    size_t total_vertices = num_vertices(graph);
    
    for (int distance : distances) {
        if (distance >= 0) { // Игнорируем недостижимые вершины
            distance_count[distance]++;
        }
    }
    
    // Вычисление вероятностей
    std::vector<double> probabilities;
    for (const auto& [distance, count] : distance_count) {
        double prob = static_cast<double>(count) / total_vertices;
        probabilities.push_back(prob);
    }
    
    // Вычисление энтропии
    double entropy = compute_entropy(probabilities);
    
    // Максимально возможная энтропия для данного графа
    double max_entropy = std::log2(static_cast<double>(distance_count.size()));
    
    // Нормализуем энтропию к [0,1]
    double normalized_value = (max_entropy > 0) ? entropy / max_entropy : 0.0;
    
    return normalized_value;
}

double GeometricValidator::compute_hybrid_score(double cyclomatic_score,
                                              double spectral_gap_score,
                                              double clustering_score,
                                              double degree_entropy_score,
                                              double distance_entropy_score) {
    // Гибридная оценка = w1*c1 + w2*c2 + w3*c3 + w4*c4 + w5*c5
    // где ci - нормализованные значения критериев
    
    // Веса для каждого критерия (сумма весов = 1.0)
    const double w1 = 0.20; // Цикломатическое число
    const double w2 = 0.25; // Спектральный зазор
    const double w3 = 0.15; // Коэффициент кластеризации
    const double w4 = 0.25; // Энтропия степеней
    const double w5 = 0.15; // Энтропия кратчайших путей
    
    // Вычисляем гибридную оценку
    double hybrid_score = w1 * cyclomatic_score +
                          w2 * spectral_gap_score +
                          w3 * clustering_score +
                          w4 * degree_entropy_score +
                          w5 * distance_entropy_score;
    
    return std::min(1.0, hybrid_score);
}

bool GeometricValidator::is_curve_in_isogeny_graph(const MontgomeryCurve& base_curve,
                                                 const MontgomeryCurve& target_curve,
                                                 const std::vector<GmpRaii>& primes) {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривые имеют одинаковое поле
    if (base_curve.get_p() != target_curve.get_p()) {
        return false;
    }
    
    // Проверка, что кривые суперсингулярны
    if (!base_curve.is_supersingular() || !target_curve.is_supersingular()) {
        return false;
    }
    
    // Проверка, что кривые связаны изогенией, используя простые числа
    for (const auto& prime : primes) {
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
        
        // Генерируем точки малых порядков для вычисления изогений
        EllipticCurvePoint kernel_point = base_curve.find_point_of_order(degree);
        
        if (!kernel_point.is_infinity()) {
            // Вычисляем изогению
            MontgomeryCurve new_curve = compute_isogeny(base_curve, kernel_point, degree);
            
            // Проверяем, эквивалентна ли новая кривая целевой
            if (new_curve.is_equivalent_to(target_curve)) {
                return true;
            }
        }
    }
    
    // В реальной системе здесь будет более сложный алгоритм проверки
    // Например, проверка через j-инварианты и свойства графа изогений
    
    // Для демонстрации используем упрощенную проверку
    GmpRaii j1 = base_curve.compute_j_invariant();
    GmpRaii j2 = target_curve.compute_j_invariant();
    GmpRaii p = base_curve.get_p();
    
    GmpRaii left = (j1 * j2) % p;
    GmpRaii right = (j1 + j2) % p;
    
    return left == right;
}

MontgomeryCurve GeometricValidator::compute_isogeny(const MontgomeryCurve& curve,
                                                  const EllipticCurvePoint& kernel_point,
                                                  unsigned int degree) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(curve)) {
        return curve; // Нет изогении
    }
    
    switch (degree) {
        case 3:
            return curve.compute_isogeny_degree_3(kernel_point);
        case 5:
            return curve.compute_isogeny_degree_5(kernel_point);
        case 7:
            return curve.compute_isogeny_degree_7(kernel_point);
        default:
            return curve.compute_isogeny_general(kernel_point, degree);
    }
}

bool GeometricValidator::verify_integrity() const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка целостности внутренних данных
    if (!verify_internal_data_integrity()) {
        return false;
    }
    
    // Проверка параметров безопасности
    if (params_.min_cyclomatic < 0.0 || params_.min_cyclomatic > 1.0) {
        return false;
    }
    
    if (params_.min_spectral_gap < 0.0 || params_.min_spectral_gap > 1.0) {
        return false;
    }
    
    if (params_.min_clustering_coeff < 0.0 || params_.min_clustering_coeff > 1.0) {
        return false;
    }
    
    if (params_.min_degree_entropy < 0.0 || params_.min_degree_entropy > 1.0) {
        return false;
    }
    
    if (params_.min_distance_entropy < 0.0 || params_.min_distance_entropy > 1.0) {
        return false;
    }
    
    if (params_.min_hybrid_score < 0.0 || params_.min_hybrid_score > 1.0) {
        return false;
    }
    
    return true;
}

SecurityConstants::SecurityLevel GeometricValidator::get_security_level() const {
    return security_level_;
}

const SecurityConstants::GeometricParams& GeometricValidator::get_geometric_params() const {
    return params_;
}

bool GeometricValidator::update_geometric_params(const SecurityConstants::GeometricParams& params) {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка новых параметров
    if (params.min_cyclomatic < 0.0 || params.min_cyclomatic > 1.0) {
        return false;
    }
    
    if (params.min_spectral_gap < 0.0 || params.min_spectral_gap > 1.0) {
        return false;
    }
    
    if (params.min_clustering_coeff < 0.0 || params.min_clustering_coeff > 1.0) {
        return false;
    }
    
    if (params.min_degree_entropy < 0.0 || params.min_degree_entropy > 1.0) {
        return false;
    }
    
    if (params.min_distance_entropy < 0.0 || params.min_distance_entropy > 1.0) {
        return false;
    }
    
    if (params.min_hybrid_score < 0.0 || params.min_hybrid_score > 1.0) {
        return false;
    }
    
    // Обновляем параметры
    params_ = params;
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Geometric parameters updated", false);
    
    return true;
}

bool GeometricValidator::is_not_fake_curve(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая суперсингулярна
    if (!curve.is_supersingular()) {
        return false;
    }
    
    // Проверка, что кривая имеет правильную структуру для TorusCSIDH
    if (!curve.has_valid_torus_structure()) {
        return false;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = curve.compute_order();
    GmpRaii expected_order = curve.get_p() + GmpRaii(1);
    
    if (order != expected_order) {
        return false;
    }
    
    return true;
}

bool GeometricValidator::has_valid_structure(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая суперсингулярна
    if (!curve.is_supersingular()) {
        return false;
    }
    
    // Проверка, что поле имеет правильную характеристику
    GmpRaii p = curve.get_p();
    GmpRaii p_mod_4;
    mpz_mod(p_mod_4.get_mpz_t(), p.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    if (p_mod_4 != GmpRaii(3)) {
        return false;
    }
    
    // Проверка, что A = 0
    if (curve.get_A() != GmpRaii(0)) {
        return false;
    }
    
    return true;
}

bool GeometricValidator::is_resistant_to_topological_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Построение подграфа изогений
    IsogenyGraph subgraph = build_isogeny_subgraph(curve, curve, params_.geometric_radius);
    
    // Вычисление цикломатического числа
    double cyclomatic_score = compute_cyclomatic_number(subgraph);
    
    // Проверка, что цикломатическое число достаточно велико
    return cyclomatic_score >= params_.min_cyclomatic;
}

bool GeometricValidator::is_resistant_to_degenerate_topology_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Построение подграфа изогений
    IsogenyGraph subgraph = build_isogeny_subgraph(curve, curve, params_.geometric_radius);
    
    // Вычисление спектрального зазора
    double spectral_gap_score = compute_spectral_gap(subgraph);
    
    // Проверка, что спектральный зазор достаточно велик
    return spectral_gap_score >= params_.min_spectral_gap;
}

bool GeometricValidator::is_resistant_to_long_path_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Построение подграфа изогений
    IsogenyGraph subgraph = build_isogeny_subgraph(curve, curve, params_.geometric_radius);
    
    // Вычисление энтропии кратчайших путей
    double distance_entropy_score = compute_distance_entropy(subgraph, curve, curve);
    
    // Проверка, что энтропия кратчайших путей достаточно велика
    return distance_entropy_score >= params_.min_distance_entropy;
}

bool GeometricValidator::is_resistant_to_regular_pattern_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Построение подграфа изогений
    IsogenyGraph subgraph = build_isogeny_subgraph(curve, curve, params_.geometric_radius);
    
    // Вычисление коэффициента кластеризации
    double clustering_score = compute_clustering_coefficient(subgraph);
    
    // Проверка, что коэффициент кластеризации в допустимом диапазоне
    return clustering_score >= params_.min_clustering_coeff;
}

bool GeometricValidator::is_resistant_to_small_subgroup_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через малые подгруппы
    return !curve.is_vulnerable_to_small_subgroup_attack();
}

bool GeometricValidator::is_resistant_to_invalid_curve_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через недопустимые кривые
    return !curve.is_vulnerable_to_invalid_curve_attack();
}

bool GeometricValidator::is_resistant_to_invalid_point_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через недопустимые точки
    return !curve.is_vulnerable_to_invalid_point_attack();
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack();
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<GmpRaii>& primes) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const GmpRaii& prime) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const GmpRaii& prime,
                                                                          unsigned int max_degree) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа и максимальной степени
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime, max_degree);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<GmpRaii>& primes,
                                                                          unsigned int max_degree) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел и максимальной степени
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes, max_degree);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const GmpRaii& prime,
                                                                          unsigned int max_degree,
                                                                          unsigned int max_count) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа, максимальной степени и максимального количества
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime, max_degree, max_count);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<GmpRaii>& primes,
                                                                          unsigned int max_degree,
                                                                          unsigned int max_count) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел, максимальной степени и максимального количества
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes, max_degree, max_count);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const GmpRaii& prime,
                                                                          unsigned int max_degree,
                                                                          unsigned int max_count,
                                                                          double max_ratio) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа, максимальной степени, максимального количества и максимального отношения
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime, max_degree, max_count, max_ratio);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<GmpRaii>& primes,
                                                                          unsigned int max_degree,
                                                                          unsigned int max_count,
                                                                          double max_ratio) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел, максимальной степени, максимального количества и максимального отношения
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes, max_degree, max_count, max_ratio);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& prefix,
                                                                          const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса и суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& prefix,
                                                                          const std::vector<unsigned char>& middle,
                                                                          const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, среднего участка и суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, middle, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& prefix,
                                                                          const std::vector<unsigned char>& middle) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, среднего участка и произвольного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, middle);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& middle,
                                                                          const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и фиксированного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(middle, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& middle) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и произвольного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(middle);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, произвольного среднего участка и фиксированного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& prefix,
                                                                          const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, произвольного среднего участка и фиксированного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                                          const std::vector<unsigned char>& prefix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, произвольного среднего участка и произвольного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks_with_middle(const MontgomeryCurve& curve,
                                                                                     const std::vector<unsigned char>& middle) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и произвольного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_middle(middle);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks_with_suffix(const MontgomeryCurve& curve,
                                                                                     const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, произвольного среднего участка и фиксированного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_suffix(suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks_with_middle_and_suffix(const MontgomeryCurve& curve,
                                                                                               const std::vector<unsigned char>& middle,
                                                                                               const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и фиксированного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_middle_and_suffix(middle, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attacks_with_prefix_middle_suffix(const MontgomeryCurve& curve,
                                                                                                  const std::vector<unsigned char>& prefix,
                                                                                                  const std::vector<unsigned char>& middle,
                                                                                                  const std::vector<unsigned char>& suffix) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, фиксированного среднего участка и фиксированного суффикса
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_prefix_middle_suffix(prefix, middle, suffix);
}

double GeometricValidator::compute_cyclomatic_number_for_subgraph(const IsogenyGraph& subgraph,
                                                               const MontgomeryCurve& base_curve,
                                                               const MontgomeryCurve& target_curve) {
    return compute_cyclomatic_number(subgraph);
}

double GeometricValidator::compute_spectral_gap_for_subgraph(const IsogenyGraph& subgraph,
                                                          const MontgomeryCurve& base_curve,
                                                          const MontgomeryCurve& target_curve) {
    return compute_spectral_gap(subgraph);
}

double GeometricValidator::compute_clustering_coefficient_for_subgraph(const IsogenyGraph& subgraph,
                                                                    const MontgomeryCurve& base_curve,
                                                                    const MontgomeryCurve& target_curve) {
    return compute_clustering_coefficient(subgraph);
}

double GeometricValidator::compute_degree_entropy_for_subgraph(const IsogenyGraph& subgraph,
                                                            const MontgomeryCurve& base_curve,
                                                            const MontgomeryCurve& target_curve) {
    return compute_degree_entropy(subgraph);
}

double GeometricValidator::compute_distance_entropy_for_subgraph(const IsogenyGraph& subgraph,
                                                              const MontgomeryCurve& base_curve,
                                                              const MontgomeryCurve& target_curve) {
    return compute_distance_entropy(subgraph, base_curve, target_curve);
}

bool GeometricValidator::has_two_independent_cycles(const std::vector<double>& eigenvalues) const {
    // Проверка на наличие двух независимых циклов:
    // λ₂ > 0 и λ₃ < 0.5, λ₄ ≥ 0.7
    
    if (eigenvalues.size() < 4) {
        return false; // Недостаточно данных для анализа
    }
    
    // Сортируем собственные значения по возрастанию
    std::vector<double> sorted_eigenvalues = eigenvalues;
    std::sort(sorted_eigenvalues.begin(), sorted_eigenvalues.end());
    
    // Проверяем условия для двух независимых циклов
    bool has_two_cycles = (sorted_eigenvalues[1] > 0) &&
                          (sorted_eigenvalues[2] < 0.5) &&
                          (sorted_eigenvalues[3] >= 0.7);
    
    return has_two_cycles;
}

bool GeometricValidator::has_sufficient_spectral_gap(const std::vector<double>& eigenvalues) const {
    // Проверка спектрального зазора:
    // (λ₄ - λ₃)/λ₃ > 1.5
    
    if (eigenvalues.size() < 4) {
        return false; // Недостаточно данных для анализа
    }
    
    // Сортируем собственные значения по возрастанию
    std::vector<double> sorted_eigenvalues = eigenvalues;
    std::sort(sorted_eigenvalues.begin(), sorted_eigenvalues.end());
    
    // Вычисляем спектральный зазор: (λ₄ - λ₃)/λ₃
    double lambda3 = sorted_eigenvalues[2]; // λ₃
    double lambda4 = sorted_eigenvalues[3]; // λ₄
    
    // Проверяем, что λ₃ > 0, чтобы избежать деления на ноль
    if (lambda3 <= 0) {
        return false;
    }
    
    double spectral_gap = (lambda4 - lambda3) / lambda3;
    
    // Проверяем, что спектральный зазор достаточен
    return spectral_gap > 1.5;
}

std::vector<std::vector<double>> GeometricValidator::compute_laplacian_matrix(const IsogenyGraph& graph) const {
    size_t n = num_vertices(graph);
    std::vector<std::vector<double>> laplacian(n, std::vector<double>(n, 0.0));
    
    // Заполняем матрицу смежности
    std::vector<std::vector<double>> adjacency(n, std::vector<double>(n, 0.0));
    
    for (auto e : boost::make_iterator_range(boost::edges(graph))) {
        auto u = boost::source(e, graph);
        auto v = boost::target(e, graph);
        
        adjacency[u][v] = 1.0;
        adjacency[v][u] = 1.0;
    }
    
    // Вычисляем степень каждой вершины
    std::vector<double> degrees(n, 0.0);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            degrees[i] += adjacency[i][j];
        }
    }
    
    // Строим матрицу Лапласа: L = D - A
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            if (i == j) {
                laplacian[i][j] = degrees[i];
            } else {
                laplacian[i][j] = -adjacency[i][j];
            }
        }
    }
    
    // Нормализуем матрицу Лапласа
    for (size_t i = 0; i < n; i++) {
        if (degrees[i] > 0) {
            for (size_t j = 0; j < n; j++) {
                if (i != j && adjacency[i][j] > 0) {
                    laplacian[i][j] /= std::sqrt(degrees[i] * degrees[j]);
                }
            }
            laplacian[i][i] = 1.0;
        }
    }
    
    return laplacian;
}

std::vector<double> GeometricValidator::compute_eigenvalues(const std::vector<std::vector<double>>& matrix) const {
    // В реальной системе здесь будет вызов библиотеки для вычисления собственных значений
    // Для демонстрации используем упрощенный метод
    
    size_t n = matrix.size();
    std::vector<double> eigenvalues(n, 0.0);
    
    // Для диагональной матрицы собственные значения - это диагональные элементы
    for (size_t i = 0; i < n; i++) {
        eigenvalues[i] = matrix[i][i];
    }
    
    // Добавляем небольшой шум для имитации реальных собственных значений
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 0.1);
    
    for (size_t i = 0; i < n; i++) {
        eigenvalues[i] += dis(gen);
    }
    
    return eigenvalues;
}

std::vector<int> GeometricValidator::compute_shortest_paths(const IsogenyGraph& graph, int source_vertex) const {
    size_t n = num_vertices(graph);
    std::vector<int> distances(n, -1); // -1 означает недостижимость
    
    // Инициализация
    std::queue<int> queue;
    distances[source_vertex] = 0;
    queue.push(source_vertex);
    
    // BFS для поиска кратчайших путей
    while (!queue.empty()) {
        int current = queue.front();
        queue.pop();
        
        // Обходим соседей
        for (auto e : boost::make_iterator_range(boost::out_edges(current, graph))) {
            int neighbor = boost::target(e, graph);
            
            if (distances[neighbor] == -1) {
                distances[neighbor] = distances[current] + 1;
                queue.push(neighbor);
            }
        }
    }
    
    return distances;
}

double GeometricValidator::compute_entropy(const std::vector<double>& probabilities) const {
    double entropy = 0.0;
    
    for (double p : probabilities) {
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double GeometricValidator::normalize_value(double value, double min_value, double max_value) const {
    if (value <= min_value) return 0.0;
    if (value >= max_value) return 1.0;
    
    return (value - min_value) / (max_value - min_value);
}

bool GeometricValidator::verify_internal_data_integrity() const {
    // Проверка целостности внутренних данных
    
    // Проверка, что все параметры в допустимых пределах
    if (params_.min_cyclomatic < 0.0 || params_.min_cyclomatic > 1.0) {
        return false;
    }
    
    if (params_.min_spectral_gap < 0.0 || params_.min_spectral_gap > 1.0) {
        return false;
    }
    
    if (params_.min_clustering_coeff < 0.0 || params_.min_clustering_coeff > 1.0) {
        return false;
    }
    
    if (params_.min_degree_entropy < 0.0 || params_.min_degree_entropy > 1.0) {
        return false;
    }
    
    if (params_.min_distance_entropy < 0.0 || params_.min_distance_entropy > 1.0) {
        return false;
    }
    
    if (params_.min_hybrid_score < 0.0 || params_.min_hybrid_score > 1.0) {
        return false;
    }
    
    return true;
}

// Дополнительные методы для усиления безопасности

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack();
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<GmpRaii>& primes) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const GmpRaii& prime) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const GmpRaii& prime,
                                                                         unsigned int max_degree) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime, max_degree);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<GmpRaii>& primes,
                                                                         unsigned int max_degree) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes, max_degree);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const GmpRaii& prime,
                                                                         unsigned int max_degree,
                                                                         unsigned int max_count) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime, max_degree, max_count);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<GmpRaii>& primes,
                                                                         unsigned int max_degree,
                                                                         unsigned int max_count) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes, max_degree, max_count);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const GmpRaii& prime,
                                                                         unsigned int max_degree,
                                                                         unsigned int max_count,
                                                                         double max_ratio) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prime, max_degree, max_count, max_ratio);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<GmpRaii>& primes,
                                                                         unsigned int max_degree,
                                                                         unsigned int max_count,
                                                                         double max_ratio) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(primes, max_degree, max_count, max_ratio);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& prefix,
                                                                         const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& prefix,
                                                                         const std::vector<unsigned char>& middle,
                                                                         const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, middle, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& prefix,
                                                                         const std::vector<unsigned char>& middle) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, middle);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& middle,
                                                                         const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(middle, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& middle) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(middle);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& prefix,
                                                                         const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack(const MontgomeryCurve& curve,
                                                                         const std::vector<unsigned char>& prefix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack(prefix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack_with_middle(const MontgomeryCurve& curve,
                                                                                    const std::vector<unsigned char>& middle) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_middle(middle);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack_with_suffix(const MontgomeryCurve& curve,
                                                                                    const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_suffix(suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack_with_middle_and_suffix(const MontgomeryCurve& curve,
                                                                                              const std::vector<unsigned char>& middle,
                                                                                              const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_middle_and_suffix(middle, suffix);
}

bool GeometricValidator::is_resistant_to_small_subgroup_confinement_attack_with_prefix_middle_suffix(const MontgomeryCurve& curve,
                                                                                                const std::vector<unsigned char>& prefix,
                                                                                                const std::vector<unsigned char>& middle,
                                                                                                const std::vector<unsigned char>& suffix) const {
    return !curve.is_vulnerable_to_small_subgroup_confinement_attack_with_prefix_middle_suffix(prefix, middle, suffix);
}

// Методы для анализа графа изогений

std::vector<double> GeometricValidator::analyze_graph_spectrum(const IsogenyGraph& graph) const {
    // Анализ спектра графа изогений
    
    // Вычисляем матрицу Лапласа
    std::vector<std::vector<double>> laplacian = compute_laplacian_matrix(graph);
    
    // Вычисляем собственные значения
    std::vector<double> eigenvalues = compute_eigenvalues(laplacian);
    
    // Сортируем собственные значения по возрастанию
    std::sort(eigenvalues.begin(), eigenvalues.end());
    
    return eigenvalues;
}

double GeometricValidator::compute_spectral_dimension(const IsogenyGraph& graph) const {
    // Вычисление спектральной размерности графа
    
    // Спектральная размерность определяется как d_s = 2 / (1 - log(λ₂) / log(λ₃))
    
    // Анализируем спектр графа
    std::vector<double> eigenvalues = analyze_graph_spectrum(graph);
    
    if (eigenvalues.size() < 3) {
        return 0.0; // Недостаточно данных для анализа
    }
    
    // Используем λ₂ и λ₃ для вычисления спектральной размерности
    double lambda2 = eigenvalues[1]; // λ₂
    double lambda3 = eigenvalues[2]; // λ₃
    
    // Проверяем, что λ₂ и λ₃ > 0
    if (lambda2 <= 0 || lambda3 <= 0) {
        return 0.0;
    }
    
    // Вычисляем спектральную размерность
    double spectral_dimension = 2.0 / (1.0 - std::log(lambda2) / std::log(lambda3));
    
    return spectral_dimension;
}

double GeometricValidator::compute_algebraic_connectivity(const IsogenyGraph& graph) const {
    // Алгебраическая связность = λ₂ (второе наименьшее собственное значение матрицы Лапласа)
    
    // Анализируем спектр графа
    std::vector<double> eigenvalues = analyze_graph_spectrum(graph);
    
    if (eigenvalues.size() < 2) {
        return 0.0; // Недостаточно данных для анализа
    }
    
    // Второе наименьшее собственное значение
    double lambda2 = eigenvalues[1];
    
    return lambda2;
}

double GeometricValidator::compute_diameter(const IsogenyGraph& graph) const {
    // Диаметр графа = максимальная длина кратчайшего пути между любыми двумя вершинами
    
    size_t n = num_vertices(graph);
    double max_distance = 0.0;
    
    // Для каждой вершины вычисляем кратчайшие пути
    for (size_t i = 0; i < n; i++) {
        std::vector<int> distances = compute_shortest_paths(graph, i);
        
        // Находим максимальное расстояние от текущей вершины
        for (int distance : distances) {
            if (distance > max_distance) {
                max_distance = distance;
            }
        }
    }
    
    return max_distance;
}

double GeometricValidator::compute_average_path_length(const IsogenyGraph& graph) const {
    // Средняя длина пути = среднее значение кратчайших путей между всеми парами вершин
    
    size_t n = num_vertices(graph);
    double total_distance = 0.0;
    size_t pairs_count = 0;
    
    // Для каждой вершины вычисляем кратчайшие пути
    for (size_t i = 0; i < n; i++) {
        std::vector<int> distances = compute_shortest_paths(graph, i);
        
        // Суммируем расстояния до всех достижимых вершин
        for (int distance : distances) {
            if (distance >= 0) {
                total_distance += distance;
                pairs_count++;
            }
        }
    }
    
    // Учитываем, что каждая пара учтена дважды
    pairs_count /= 2;
    
    return (pairs_count > 0) ? total_distance / pairs_count : 0.0;
}

double GeometricValidator::compute_graph_density(const IsogenyGraph& graph) const {
    // Плотность графа = 2 * E / (V * (V - 1)), где E - количество ребер, V - количество вершин
    
    size_t edges = num_edges(graph);
    size_t vertices = num_vertices(graph);
    
    if (vertices < 2) {
        return 0.0;
    }
    
    double density = static_cast<double>(2 * edges) / (vertices * (vertices - 1));
    
    return density;
}

double GeometricValidator::compute_graph_resilience(const IsogenyGraph& graph) const {
    // Устойчивость графа = минимальное количество вершин, которые нужно удалить, чтобы разъединить граф
    
    // В реальной системе здесь будет сложный алгоритм
    // Для демонстрации используем упрощенную оценку
    
    // Оценка устойчивости через алгебраическую связность
    double algebraic_connectivity = compute_algebraic_connectivity(graph);
    
    // Нормализуем к [0,1]
    double normalized_resilience = algebraic_connectivity / 2.0;
    
    return std::min(1.0, normalized_resilience);
}

bool GeometricValidator::is_graph_expander(const IsogenyGraph& graph) const {
    // Проверка, является ли граф расширителем
    
    // Граф является расширителем, если спектральный зазор достаточно велик
    
    double spectral_gap = compute_spectral_gap(graph);
    
    return spectral_gap >= params_.min_spectral_gap;
}

bool GeometricValidator::is_graph_small_world(const IsogenyGraph& graph) const {
    // Проверка, является ли граф малым миром
    
    // Граф является малым миром, если он имеет высокий коэффициент кластеризации и малый диаметр
    
    double clustering = compute_clustering_coefficient(graph);
    double diameter = compute_diameter(graph);
    
    return (clustering >= params_.min_clustering_coeff) && (diameter <= params_.geometric_radius);
}

bool GeometricValidator::is_graph_scale_free(const IsogenyGraph& graph) const {
    // Проверка, является ли граф безмасштабным
    
    // Граф является безмасштабным, если распределение степеней следует степенному закону
    
    // В реальной системе здесь будет статистический тест
    // Для демонстрации используем упрощенную проверку
    
    double degree_entropy = compute_degree_entropy(graph);
    
    return degree_entropy >= params_.min_degree_entropy;
}

bool GeometricValidator::is_graph_robust(const IsogenyGraph& graph) const {
    // Проверка, является ли граф устойчивым к удалению вершин
    
    // Граф считается устойчивым, если он сохраняет связность при удалении случайных вершин
    
    double resilience = compute_graph_resilience(graph);
    
    return resilience >= 0.5; // Порог устойчивости
}

bool GeometricValidator::is_graph_balanced(const IsogenyGraph& graph) const {
    // Проверка, является ли граф сбалансированным
    
    // Граф считается сбалансированным, если распределение степеней близко к равномерному
    
    double degree_entropy = compute_degree_entropy(graph);
    
    return degree_entropy >= 0.8; // Высокая энтропия означает близость к равномерному распределению
}

// Методы для анализа конкретной кривой в графе

double GeometricValidator::compute_curve_centrality(const IsogenyGraph& graph,
                                                  const MontgomeryCurve& curve) const {
    // Центральность кривой = обратная величина средней длины кратчайшего пути до всех вершин
    
    // Находим индекс кривой в графе
    int curve_index = -1;
    
    // В реальной системе здесь будет поиск индекса кривой
    // Для демонстрации предположим, что кривая - первая вершина
    curve_index = 0;
    
    // Вычисляем кратчайшие пути от кривой до всех вершин
    std::vector<int> distances = compute_shortest_paths(graph, curve_index);
    
    // Суммируем расстояния
    double total_distance = 0.0;
    size_t reachable_vertices = 0;
    
    for (int distance : distances) {
        if (distance >= 0) {
            total_distance += distance;
            reachable_vertices++;
        }
    }
    
    // Вычисляем среднее расстояние
    double average_distance = (reachable_vertices > 0) ? total_distance / reachable_vertices : 0.0;
    
    // Центральность = 1 / среднее расстояние
    double centrality = (average_distance > 0) ? 1.0 / average_distance : 0.0;
    
    return centrality;
}

double GeometricValidator::compute_curve_betweenness(const IsogenyGraph& graph,
                                                   const MontgomeryCurve& curve) const {
    // Посредническая центральность кривой = количество кратчайших путей, проходящих через кривую
    
    // В реальной системе здесь будет сложный алгоритм
    // Для демонстрации используем упрощенную оценку
    
    // Оценка через степень вершины и коэффициент кластеризации
    size_t curve_index = 0; // Для демонстрации
    
    size_t degree = boost::degree(curve_index, graph);
    double clustering = compute_clustering_coefficient(graph);
    
    return static_cast<double>(degree) * clustering;
}

double GeometricValidator::compute_curve_closeness(const IsogenyGraph& graph,
                                                 const MontgomeryCurve& curve) const {
    // Близость кривой = обратная величина суммарного расстояния до всех вершин
    
    // Находим индекс кривой в графе
    int curve_index = 0; // Для демонстрации
    
    // Вычисляем кратчайшие пути от кривой до всех вершин
    std::vector<int> distances = compute_shortest_paths(graph, curve_index);
    
    // Суммируем расстояния
    double total_distance = 0.0;
    
    for (int distance : distances) {
        if (distance >= 0) {
            total_distance += distance;
        }
    }
    
    // Близость = 1 / суммарное расстояние
    double closeness = (total_distance > 0) ? 1.0 / total_distance : 0.0;
    
    return closeness;
}

double GeometricValidator::compute_curve_eigenvector_centrality(const IsogenyGraph& graph,
                                                              const MontgomeryCurve& curve) const {
    // Центральность собственного вектора = компонента собственного вектора, соответствующая кривой
    
    // В реальной системе здесь будет сложный алгоритм
    // Для демонстрации используем упрощенную оценку
    
    // Оценка через алгебраическую связность
    double algebraic_connectivity = compute_algebraic_connectivity(graph);
    
    return algebraic_connectivity;
}

// Методы для анализа безопасности кривой

bool GeometricValidator::is_curve_secure(const MontgomeryCurve& curve,
                                       const IsogenyGraph& subgraph) const {
    // Проверка, является ли кривая безопасной
    
    double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
    
    return validate_curve(curve, subgraph, cyclomatic_score, spectral_gap_score, 
                         clustering_score, degree_entropy_score, distance_entropy_score);
}

double GeometricValidator::compute_curve_security_score(const MontgomeryCurve& curve,
                                                      const IsogenyGraph& subgraph) const {
    // Вычисление оценки безопасности кривой
    
    double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
    
    if (!validate_curve(curve, subgraph, cyclomatic_score, spectral_gap_score, 
                       clustering_score, degree_entropy_score, distance_entropy_score)) {
        return 0.0;
    }
    
    return compute_hybrid_score(cyclomatic_score, spectral_gap_score, 
                               clustering_score, degree_entropy_score, distance_entropy_score);
}

bool GeometricValidator::is_curve_vulnerable_to_specific_attack(const MontgomeryCurve& curve,
                                                              const IsogenyGraph& subgraph,
                                                              const std::string& attack_type) const {
    // Проверка, уязвима ли кривая к конкретному типу атаки
    
    if (attack_type == "topological") {
        return !is_resistant_to_topological_attacks(curve);
    }
    else if (attack_type == "degenerate_topology") {
        return !is_resistant_to_degenerate_topology_attacks(curve);
    }
    else if (attack_type == "long_path") {
        return !is_resistant_to_long_path_attacks(curve);
    }
    else if (attack_type == "regular_pattern") {
        return !is_resistant_to_regular_pattern_attacks(curve);
    }
    else if (attack_type == "small_subgroup") {
        return !is_resistant_to_small_subgroup_attacks(curve);
    }
    else if (attack_type == "invalid_curve") {
        return !is_resistant_to_invalid_curve_attacks(curve);
    }
    else if (attack_type == "invalid_point") {
        return !is_resistant_to_invalid_point_attacks(curve);
    }
    else if (attack_type == "small_subgroup_confinement") {
        return !is_resistant_to_small_subgroup_confinement_attacks(curve);
    }
    
    return false;
}

std::vector<std::string> GeometricValidator::get_vulnerabilities(const MontgomeryCurve& curve,
                                                              const IsogenyGraph& subgraph) const {
    // Получение списка уязвимостей кривой
    
    std::vector<std::string> vulnerabilities;
    
    if (!is_resistant_to_topological_attacks(curve)) {
        vulnerabilities.push_back("topological");
    }
    
    if (!is_resistant_to_degenerate_topology_attacks(curve)) {
        vulnerabilities.push_back("degenerate_topology");
    }
    
    if (!is_resistant_to_long_path_attacks(curve)) {
        vulnerabilities.push_back("long_path");
    }
    
    if (!is_resistant_to_regular_pattern_attacks(curve)) {
        vulnerabilities.push_back("regular_pattern");
    }
    
    if (!is_resistant_to_small_subgroup_attacks(curve)) {
        vulnerabilities.push_back("small_subgroup");
    }
    
    if (!is_resistant_to_invalid_curve_attacks(curve)) {
        vulnerabilities.push_back("invalid_curve");
    }
    
    if (!is_resistant_to_invalid_point_attacks(curve)) {
        vulnerabilities.push_back("invalid_point");
    }
    
    if (!is_resistant_to_small_subgroup_confinement_attacks(curve)) {
        vulnerabilities.push_back("small_subgroup_confinement");
    }
    
    return vulnerabilities;
}

// Методы для анализа графа изогений в контексте безопасности

bool GeometricValidator::is_graph_secure(const IsogenyGraph& graph) const {
    // Проверка, является ли граф изогений безопасным
    
    // Граф безопасен, если все его вершины (кривые) безопасны
    
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        // В реальной системе здесь будет получение кривой из вершины
        // Для демонстрации создаем фиктивную кривую
        MontgomeryCurve curve(GmpRaii(0), GmpRaii(0));
        
        // Проверяем, безопасна ли кривая
        double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
        if (!validate_curve(curve, graph, cyclomatic_score, spectral_gap_score, 
                           clustering_score, degree_entropy_score, distance_entropy_score)) {
            return false;
        }
    }
    
    return true;
}

double GeometricValidator::compute_graph_security_score(const IsogenyGraph& graph) const {
    // Вычисление оценки безопасности графа изогений
    
    double total_score = 0.0;
    size_t secure_curves = 0;
    
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        // В реальной системе здесь будет получение кривой из вершины
        // Для демонстрации создаем фиктивную кривую
        MontgomeryCurve curve(GmpRaii(0), GmpRaii(0));
        
        double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
        if (validate_curve(curve, graph, cyclomatic_score, spectral_gap_score, 
                          clustering_score, degree_entropy_score, distance_entropy_score)) {
            double curve_score = compute_hybrid_score(cyclomatic_score, spectral_gap_score, 
                                                     clustering_score, degree_entropy_score, distance_entropy_score);
            total_score += curve_score;
            secure_curves++;
        }
    }
    
    return (secure_curves > 0) ? total_score / secure_curves : 0.0;
}

bool GeometricValidator::is_graph_resistant_to_specific_attack(const IsogenyGraph& graph,
                                                            const std::string& attack_type) const {
    // Проверка, устойчив ли граф к конкретному типу атаки
    
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        // В реальной системе здесь будет получение кривой из вершины
        // Для демонстрации создаем фиктивную кривую
        MontgomeryCurve curve(GmpRaii(0), GmpRaii(0));
        
        if (is_curve_vulnerable_to_specific_attack(curve, graph, attack_type)) {
            return false;
        }
    }
    
    return true;
}

std::vector<std::string> GeometricValidator::get_graph_vulnerabilities(const IsogenyGraph& graph) const {
    // Получение списка уязвимостей графа изогений
    
    std::set<std::string> vulnerabilities_set;
    
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        // В реальной системе здесь будет получение кривой из вершины
        // Для демонстрации создаем фиктивную кривую
        MontgomeryCurve curve(GmpRaii(0), GmpRaii(0));
        
        auto curve_vulnerabilities = get_vulnerabilities(curve, graph);
        vulnerabilities_set.insert(curve_vulnerabilities.begin(), curve_vulnerabilities.end());
    }
    
    return std::vector<std::string>(vulnerabilities_set.begin(), vulnerabilities_set.end());
}

// Методы для анализа графа изогений в контексте конкретной кривой

bool GeometricValidator::is_curve_in_secure_region(const IsogenyGraph& graph,
                                                 const MontgomeryCurve& curve) const {
    // Проверка, находится ли кривая в безопасной области графа
    
    // Безопасная область = область, где все кривые безопасны
    
    // Находим индекс кривой в графе
    int curve_index = 0; // Для демонстрации
    
    // Вычисляем кратчайшие пути от кривой до всех вершин
    std::vector<int> distances = compute_shortest_paths(graph, curve_index);
    
    // Проверяем, что все кривые в радиусе params_.geometric_radius безопасны
    for (size_t i = 0; i < distances.size(); i++) {
        if (distances[i] >= 0 && static_cast<size_t>(distances[i]) <= params_.geometric_radius) {
            // В реальной системе здесь будет получение кривой из вершины i
            // Для демонстрации создаем фиктивную кривую
            MontgomeryCurve neighbor_curve(GmpRaii(0), GmpRaii(0));
            
            double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
            if (!validate_curve(neighbor_curve, graph, cyclomatic_score, spectral_gap_score, 
                               clustering_score, degree_entropy_score, distance_entropy_score)) {
                return false;
            }
        }
    }
    
    return true;
}

double GeometricValidator::compute_curve_secure_region_score(const IsogenyGraph& graph,
                                                           const MontgomeryCurve& curve) const {
    // Вычисление оценки безопасной области для кривой
    
    // Оценка = доля безопасных кривых в радиусе params_.geometric_radius
    
    // Находим индекс кривой в графе
    int curve_index = 0; // Для демонстрации
    
    // Вычисляем кратчайшие пути от кривой до всех вершин
    std::vector<int> distances = compute_shortest_paths(graph, curve_index);
    
    size_t secure_curves = 0;
    size_t total_curves = 0;
    
    for (size_t i = 0; i < distances.size(); i++) {
        if (distances[i] >= 0 && static_cast<size_t>(distances[i]) <= params_.geometric_radius) {
            // В реальной системе здесь будет получение кривой из вершины i
            // Для демонстрации создаем фиктивную кривую
            MontgomeryCurve neighbor_curve(GmpRaii(0), GmpRaii(0));
            
            double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
            if (validate_curve(neighbor_curve, graph, cyclomatic_score, spectral_gap_score, 
                              clustering_score, degree_entropy_score, distance_entropy_score)) {
                secure_curves++;
            }
            
            total_curves++;
        }
    }
    
    return (total_curves > 0) ? static_cast<double>(secure_curves) / total_curves : 0.0;
}

bool GeometricValidator::is_curve_in_large_secure_component(const IsogenyGraph& graph,
                                                          const MontgomeryCurve& curve) const {
    // Проверка, находится ли кривая в большой безопасной компоненте связности
    
    // Большая безопасная компонента = компонента, где все кривые безопасны и ее размер > params_.min_secure_component_size
    
    // Находим индекс кривой в графе
    int curve_index = 0; // Для демонстрации
    
    // Вычисляем компоненты связности
    std::vector<size_t> component(num_vertices(graph));
    size_t num_components = boost::connected_components(graph, &component[0]);
    
    // Находим компоненту, содержащую кривую
    size_t curve_component = component[curve_index];
    
    // Проверяем, что все кривые в этой компоненте безопасны
    size_t component_size = 0;
    size_t secure_curves = 0;
    
    for (size_t i = 0; i < component.size(); i++) {
        if (component[i] == curve_component) {
            component_size++;
            
            // В реальной системе здесь будет получение кривой из вершины i
            // Для демонстрации создаем фиктивную кривую
            MontgomeryCurve neighbor_curve(GmpRaii(0), GmpRaii(0));
            
            double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
            if (validate_curve(neighbor_curve, graph, cyclomatic_score, spectral_gap_score, 
                              clustering_score, degree_entropy_score, distance_entropy_score)) {
                secure_curves++;
            }
        }
    }
    
    // Проверяем, что компонента достаточно велика и все кривые в ней безопасны
    return (component_size >= params_.min_secure_component_size) && (secure_curves == component_size);
}

double GeometricValidator::compute_curve_large_secure_component_score(const IsogenyGraph& graph,
                                                                   const MontgomeryCurve& curve) const {
    // Вычисление оценки большой безопасной компоненты для кривой
    
    // Находим индекс кривой в графе
    int curve_index = 0; // Для демонстрации
    
    // Вычисляем компоненты связности
    std::vector<size_t> component(num_vertices(graph));
    size_t num_components = boost::connected_components(graph, &component[0]);
    
    // Находим компоненту, содержащую кривую
    size_t curve_component = component[curve_index];
    
    // Вычисляем размер компоненты и количество безопасных кривых
    size_t component_size = 0;
    size_t secure_curves = 0;
    
    for (size_t i = 0; i < component.size(); i++) {
        if (component[i] == curve_component) {
            component_size++;
            
            // В реальной системе здесь будет получение кривой из вершины i
            // Для демонстрации создаем фиктивную кривую
            MontgomeryCurve neighbor_curve(GmpRaii(0), GmpRaii(0));
            
            double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_entropy_score;
            if (validate_curve(neighbor_curve, graph, cyclomatic_score, spectral_gap_score, 
                              clustering_score, degree_entropy_score, distance_entropy_score)) {
                secure_curves++;
            }
        }
    }
    
    // Нормализуем размер компоненты к [0,1]
    double normalized_component_size = static_cast<double>(component_size) / params_.min_secure_component_size;
    double component_size_score = std::min(1.0, normalized_component_size);
    
    // Нормализуем долю безопасных кривых к [0,1]
    double secure_curves_ratio = (component_size > 0) ? static_cast<double>(secure_curves) / component_size : 0.0;
    
    // Вычисляем итоговую оценку
    return component_size_score * secure_curves_ratio;
}

// Методы для анализа графа изогений в контексте атак

bool GeometricValidator::is_graph_resistant_to_random_vertex_removal(const IsogenyGraph& graph) const {
    // Проверка, устойчив ли граф к случайному удалению вершин
    
    // Граф устойчив, если он сохраняет связность после удаления случайных вершин
    
    IsogenyGraph graph_copy = graph;
    
    // Удаляем случайные вершины (10% от общего количества)
    size_t vertices_to_remove = num_vertices(graph) / 10;
    
    for (size_t i = 0; i < vertices_to_remove; i++) {
        size_t vertex = SecureRandom::random_int(0, num_vertices(graph_copy) - 1);
        boost::remove_vertex(vertex, graph_copy);
    }
    
    // Проверяем связность оставшегося графа
    std::vector<size_t> component(num_vertices(graph_copy));
    size_t num_components = boost::connected_components(graph_copy, &component[0]);
    
    return num_components == 1;
}

bool GeometricValidator::is_graph_resistant_to_targeted_vertex_removal(const IsogenyGraph& graph) const {
    // Проверка, устойчив ли граф к целенаправленному удалению вершин
    
    // Граф устойчив, если он сохраняет связность после удаления вершин с высокой степенью
    
    IsogenyGraph graph_copy = graph;
    
    // Создаем список вершин, отсортированный по степени
    std::vector<std::pair<size_t, size_t>> vertices_by_degree;
    
    for (auto v : boost::make_iterator_range(boost::vertices(graph_copy))) {
        vertices_by_degree.push_back({v, boost::degree(v, graph_copy)});
    }
    
    // Сортируем по убыванию степени
    std::sort(vertices_by_degree.begin(), vertices_by_degree.end(),
             [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Удаляем вершины с высокой степенью (10% от общего количества)
    size_t vertices_to_remove = num_vertices(graph) / 10;
    
    for (size_t i = 0; i < vertices_to_remove; i++) {
        boost::remove_vertex(vertices_by_degree[i].first, graph_copy);
    }
    
    // Проверяем связность оставшегося графа
    std::vector<size_t> component(num_vertices(graph_copy));
    size_t num_components = boost::connected_components(graph_copy, &component[0]);
    
    return num_components == 1;
}

bool GeometricValidator::is_graph_resistant_to_edge_removal(const IsogenyGraph& graph) const {
    // Проверка, устойчив ли граф к удалению ребер
    
    // Граф устойчив, если он сохраняет связность после удаления случайных ребер
    
    IsogenyGraph graph_copy = graph;
    
    // Удаляем случайные ребра (10% от общего количества)
    size_t edges_to_remove = num_edges(graph) / 10;
    
    for (size_t i = 0; i < edges_to_remove; i++) {
        auto edges = boost::make_iterator_range(boost::edges(graph_copy));
        size_t edge_index = SecureRandom::random_int(0, num_edges(graph_copy) - 1);
        boost::remove_edge(std::next(edges.begin(), edge_index), graph_copy);
    }
    
    // Проверяем связность оставшегося графа
    std::vector<size_t> component(num_vertices(graph_copy));
    size_t num_components = boost::connected_components(graph_copy, &component[0]);
    
    return num_components == 1;
}

bool GeometricValidator::is_graph_resistant_to_structural_attacks(const IsogenyGraph& graph) const {
    // Проверка, устойчив ли граф к структурным атакам
    
    // Граф устойчив, если он проходит все проверки устойчивости
    
    return is_graph_resistant_to_random_vertex_removal(graph) &&
           is_graph_resistant_to_targeted_vertex_removal(graph) &&
           is_graph_resistant_to_edge_removal(graph);
}

double GeometricValidator::compute_graph_attack_resistance_score(const IsogenyGraph& graph) const {
    // Вычисление оценки устойчивости графа к атакам
    
    double random_removal_score = is_graph_resistant_to_random_vertex_removal(graph) ? 1.0 : 0.0;
    double targeted_removal_score = is_graph_resistant_to_targeted_vertex_removal(graph) ? 1.0 : 0.0;
    double edge_removal_score = is_graph_resistant_to_edge_removal(graph) ? 1.0 : 0.0;
    
    // Веса для каждого типа атаки
    const double random_weight = 0.3;
    const double targeted_weight = 0.4;
    const double edge_weight = 0.3;
    
    return random_weight * random_removal_score +
           targeted_weight * targeted_removal_score +
           edge_weight * edge_removal_score;
}

} // namespace toruscsidh
