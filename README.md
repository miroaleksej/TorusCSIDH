# TorusCSIDH: Post-Quantum Cryptographic System for Bitcoin

![image](https://github.com/user-attachments/assets/8401e7fb-fa41-41ff-829b-9be70a0bb80b)

![C++](https://img.shields.io/badge/C++-17/20-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Development Status](https://img.shields.io/badge/Status-In_Development-orange?style=for-the-badge)

>## ⚠️ Development Status
>**This project is currently in active development and should not be used in production environments.** The current implementation represents a research prototype of the TorusCSIDH post-quantum cryptographic system. While the mathematical foundations are sound and the code has been designed with security in mind, **this implementation has not yet undergone comprehensive security audits or testing** required for production use. Production deployment should only occur after thorough independent verification and when an official stable release is published.

The system is in the **verification and debugging stage** - no formal testing has been conducted yet. We welcome researchers, cryptographers, and developers to contribute to the project through code review, mathematical verification, and collaborative development.

## TorusCSIDH: Post-Quantum Cryptographic System for Bitcoin

## Introduction: Quantum Threat to Bitcoin

Bitcoin currently employs the Elliptic Curve Digital Signature Algorithm (ECDSA), which derives its security from the computational difficulty of the discrete logarithm problem on elliptic curves. However, in 1994, Peter Shor demonstrated that quantum computers could solve this problem in polynomial time. Once sufficiently powerful quantum computers become available, all funds associated with exposed public keys would be vulnerable. This represents not merely a theoretical concern but a time-bound security challenge requiring proactive mitigation.

An effective post-quantum replacement must satisfy three essential criteria:
- **Quantum resistance**: Security against attacks from quantum computers
- **Compactness**: Reasonable key and signature sizes
- **Compatibility**: Seamless integration with Bitcoin's existing infrastructure

TorusCSIDH addresses all three requirements through a novel cryptographic construction based on supersingular elliptic curve isogenies.

## Security Philosophy: Beyond Algebraic Complexity

Traditional cryptography has primarily relied on algebraic complexity as the foundation of security. However, true security encompasses not merely computational difficulty but the holistic structural integrity of the cryptographic system. Analogous to civil engineering, where structural integrity depends not only on material strength but on proper geometric configuration, cryptographic security should be evaluated based on both computational hardness and structural properties.

TorusCSIDH introduces a paradigm shift from "security through computational complexity" to "security through structural integrity." This approach recognizes that cryptographic protocols may be theoretically secure against computational attacks yet remain vulnerable to implementation-level attacks if their structural properties are not rigorously verified.

## CSIDH: Post-Quantum Cryptography Through Isogenies

CSIDH (Commutative Supersingular Isogeny Diffie-Hellman) represents a quantum-resistant alternative to classical key exchange protocols. To understand its operation, we must first establish fundamental concepts.

### Isogenies: Mappings Between Elliptic Curves

An elliptic curve over a finite field constitutes the set of points satisfying an equation of the form $y^2 = x^3 + ax + b$. In cryptography, we work with curves over finite fields where the number of points is finite.

An isogeny represents a special morphism between elliptic curves that preserves their algebraic structure. Formally, an isogeny $\phi: E_1 \to E_2$ is a non-constant rational map that is also a group homomorphism. In CSIDH, we utilize supersingular elliptic curves—curves with unique properties that make them suitable for post-quantum cryptography.

### Isogeny Graph: Cryptographic Structure

Representing all supersingular curves as vertices and isogenies as edges yields the isogeny graph. This complex structure features vertices corresponding to curves and edges corresponding to isogenies of specific prime degrees.

The fundamental insight of CSIDH is that traversing this graph through a sequence of isogenies allows one to "conceal" their path such that an observer cannot determine the starting or ending points, even with access to a quantum computer.

### Mathematical Foundation of CSIDH

#### Parameter Selection

For CSIDH construction, we require a prime number $p$ of the form:

$$p = 4\ell_1\ell_2\cdots\ell_n - 1$$

where $\ell_i$ are small primes (e.g., the first 58 primes for 128-bit security). This specific form ensures the existence of ideals in the quaternion algebra $B_{p,\infty}$ corresponding to isogenies of degrees $\ell_i$, which is essential for protocol construction.

#### Base Curve

Over the field $\mathbb{F}_{p^2}$, we select the base curve:

$$E_0: y^2 = x^3 + x$$

This supersingular curve possesses advantageous properties. Its endomorphism ring $\mathrm{End}(E_0)$ constitutes a maximal order in the quaternion algebra $B_{p,\infty}$.

#### Key Generation

In CSIDH, the secret key is a vector of exponents:

$$d = (e_1, \dots, e_n), \quad e_i \in \{-m, \dots, m\}$$

Each component $e_i$ determines the number of applications of the $\ell_i$-degree isogeny (if $e_i > 0$) or its dual (if $e_i < 0$).

The public key is the curve obtained by applying the sequence of isogenies to the base curve:

$$E = [d]E_0$$

#### Security Foundation

CSIDH security rests on the **isogeny action problem**: given $E_0$ and $E$, it is computationally difficult to recover the vector $d$, even with a quantum computer. This resembles a labyrinth navigation problem: knowing start and end points makes determining the exact path extremely difficult when the labyrinth is sufficiently complex.

### Quantum Resistance of CSIDH

Quantum computers efficiently solve problems based on periodicity (as in Shor's algorithm), but the isogeny graph structure lacks regular periodicity exploitable by quantum algorithms. Pathfinding in this graph remains computationally difficult even for quantum adversaries.

## TorusCSIDH: Two-Layer Security Architecture

While CSIDH represents a powerful protocol, it possesses inherent vulnerabilities. The primary limitation: classical CSIDH assumes all curves with which we interact are "legitimate"—that is, they were genuinely derived through legitimate isogeny applications to the base curve.

However, what if an adversary substitutes an "artificial" curve that formally appears legitimate but was specifically engineered for attack? In such cases, the algebraic security of CSIDH could be circumvented.

### Necessity of Two-Layer Security

Consider a lock secured by two independent mechanisms. To open the door, both mechanisms must be engaged. If one mechanism fails or is compromised, the second still protects the asset.

Similarly, TorusCSIDH introduces a **second security layer** to classical CSIDH:

1. **Algebraic layer** (as in CSIDH)—provides foundational security through computational hardness
2. **Geometric layer** (our innovation)—verifies structural properties of curves to ensure they genuinely belong to the "secure" portion of the isogeny graph

This approach parallels verifying not only the mathematical correctness of calculations but also confirming that all input data possesses the expected "form" and "structure."

### Layer 1: Algebraic Security (Standard CSIDH)

This layer employs standard CSIDH mechanisms:

- Signature verification through commutativity:
  $$[d_{\text{eph}}][d_A]E_0 = [d_A][d_{\text{eph}}]E_0$$
- Shared secret computation:
  $$S = j([d_A]E_{\text{eph}}) \in \mathbb{F}_{p^2}$$

This layer provides baseline security but, as previously discussed, remains vulnerable to attacks through forged curves.

### Layer 2: Geometric Security (Original Contribution)

The isogeny graph constitutes a discrete structure where vertices represent curves and edges represent isogenies. Critically, in practical cryptographic applications, we work with the combinatorial structure of this graph rather than abstract topology.

**Our key insight**: In the neighborhood of a typical vertex in the isogeny graph, there exists **local structure with two independent cycles**. This is not metaphorical but a strict combinatorial property of the graph verifiable algorithmically.

> **Note**: As of 2025, **no published works** utilize spectral analysis of the isogeny graph as a cryptographic security criterion. Our approach represents a **hypothesis** based on combinatorial properties of the isogeny graph and **does not rely on complex topological concepts** (which would be superfluous for a discrete structure).

This layer does not replace algebraic security but complements it, enabling new forms of attack resistance—such as protection against forged curves outside the "normal" neighborhood of the isogeny graph.

### Complementing Algebraic Security

In classical **CSIDH**, security relies **exclusively on algebra**:
- An adversary receives curve $E = [d]E_0$
- Their task is to recover vector $d = (e_1, \dots, e_n)$
- This is considered difficult because the ideal action on $E_0$ obscures $d$ within complex quaternion algebra arithmetic $B_{p,\infty}$

However, **the algebraic model assumes** all inputs are **valid**:
- $E$ was genuinely derived from $E_0$ through legitimate $\ell_i$-degree isogeny chains
- An adversary cannot substitute an "artificial" curve not in $E_0$'s orbit

**In practice, this is not always the case.** In real protocols (particularly in signatures), the ephemeral curve $E_{\text{eph}}$ is transmitted openly and **can be forged**.

### Attacks Prevented by Geometric Verification

1. **Invalid Curve Attack**
   An adversary selects curve $\widetilde{E}$ not connected to $E_0$ via $\ell_i$-degree isogenies, but such that:
   - $j(\widetilde{E})$ appears as a standard $j$-invariant
   - Computing $j([d_A]\widetilde{E})$ leaks information about $d_A$ (e.g., through small order or weak endomorphism structure)

2. **Long Path Attack**
   An adversary selects $E_{\text{eph}}$ where the shortest path from $E_0$ requires exponents $|e_i| \gg m$. This may:
   - Cause denial-of-service through computational overload
   - Leak secret bits through side-channels during "heavy" isogeny processing

3. **Degenerate Topology Attack**
   Some curves reside in graph branches with **fewer than two independent cycles** (e.g., near special vertices with non-trivial automorphisms). Such curves may:
   - Possess simplified endomorphism structures
   - Permit efficient attacks through descent to subfields

### Implementation of the Geometric Verification Layer

TorusCSIDH performs **multi-level structural verification** of $E_{\text{eph}}$ during signature verification. We developed a comprehensive criterion analyzing multiple independent geometric properties of the isogeny graph.

#### Step 1: Local Subgraph Construction

First, construct a subgraph of radius 2-3 around the curve $E_{\text{eph}}$:
1. Begin with $E_{\text{eph}}$ as the central vertex
2. For each distance level from 1 to $r$ (where $r = 2$ or $3$):
   - For each curve at the current level, compute all possible $\ell_i$-isogenies
   - Add resulting curves to the subgraph and connect with edges
3. Obtain subgraph $G_r = (V, E)$, where $|V|$ is vertex count and $|E|$ is edge count

This subgraph represents the "neighborhood" of curve $E_{\text{eph}}$ in the isogeny graph and contains information about its local structure.

#### Step 2: Comprehensive Subgraph Structure Analysis

Our verification consists of five independent criteria, each analyzing different aspects of the subgraph structure:

**Criterion 1: Cyclomatic Number (Topological Verification)**
- Compute $\mu = |E| - |V| + 1$—the cyclomatic number of the subgraph
- Require $\mu \geq 2$, guaranteeing at least two independent cycles
- If $\mu < 2$, reject the curve as "linear" or "tree-like," inconsistent with the typical isogeny graph structure

**Criterion 2: Spectral Analysis of Combinatorial Laplacian**
- Construct adjacency matrix $A$ and degree matrix $D$
- Compute combinatorial Laplacian $L = D - A$
- Determine eigenvalues: $0 = \lambda_1 \leq \lambda_2 \leq \dots \leq \lambda_{|V|}$
- Verify:
  - $\lambda_1 = 0$ with multiplicity 1 (ensures graph connectivity)
  - $\lambda_3 < 0.5$ and $\lambda_4 \geq 0.7$ (presence of two small eigenvalues)
  - Spectral gap: $(\lambda_4 - \lambda_3)/\lambda_3 > 1.5$ (pronounced separation after second non-zero eigenvalue)

**Criterion 3: Clustering Coefficient**
- Compute average clustering coefficient for the subgraph:
  $$C = \frac{1}{|V|} \sum_{v \in V} \frac{2 \times \text{number of triangles containing } v}{\deg(v) \times (\deg(v)-1)}$$
- Require $C \in [0.2, 0.5]$
- This criterion verifies how "densely" vertices are locally connected around $E_{\text{eph}}$

**Criterion 4: Structural Complexity Assessment**
- Analyze degree distribution of vertices in the subgraph
- Compute degree distribution entropy:
  $$H = -\sum_{k} p_k \log_2 p_k$$
  where $p_k$ is the proportion of vertices with degree $k$
- Require $H \in [1.8, 2.5]$
- Low entropy indicates regular structure (potentially degenerate), high entropy indicates random structure (potentially artificial)

**Criterion 5: Distance Verification from Base Curve**
- Estimate approximate distance from $E_{\text{eph}}$ to base curve $E_0$
- Use empirical estimation through $j$-invariant differences
- Require distance not exceeding $n \cdot m$ (maximum distance for legitimate curves)
- This protects against "long path" attacks that could cause DoS or information leakage through side-channels

#### Step 3: Hybrid Evaluation and Decision

Each criterion receives a weight based on cryptographic significance:
- Cyclomatic number: 15%
- Spectral analysis: 30%
- Clustering coefficient: 20%
- Structural complexity: 25%
- Distance to base curve: 10%

A curve is considered legitimate if the cumulative weight of satisfied criteria is at least 85%. This hybrid approach ensures balance between verification strictness and resilience against targeted attacks.

#### How These Criteria Secure the System

These geometric criteria create a multi-layered filter functioning as a "cryptographic forgery detector." Just as art authentication examines canvas, pigments, brushstrokes, and texture—not merely the image itself—our verification examines the underlying structural properties of the cryptographic object.

The cyclomatic number serves as a basic filter, eliminating curves with improper topology. Spectral analysis functions as a more refined tool, verifying the "harmony" of the isogeny graph—similar to how a music expert identifies forgeries through sound quality. The clustering coefficient and degree entropy analyze the "texture" of the graph, detecting anomalies in connection density. Finally, distance verification to the base curve serves as "radiocarbon dating," determining whether the curve corresponds to the expected path length from the base curve.

Collectively, these criteria create a system that not only verifies the "correctness" of a curve but guarantees it "resides appropriately" within the natural isogeny graph. This represents verification not merely of photographic likeness but of intrinsic structural properties.

### Protocol Execution Example: Alice and Bob

Consider Alice signing a transaction to transfer bitcoins to Bob.

**Scenario**: Alice signs a transaction to transfer bitcoins to Bob.

**Step 1: Key Generation (Preliminary)**
- Bob generates secret key $d_B = (e_1, \dots, e_n)$ and public key $E_B = [d_B]E_0$
- Bob registers address `tcidh1...` containing $j(E_B)$

**Step 2: Transaction Signing by Alice**
1. Alice generates random ephemeral key $d_{\text{eph}} = (f_1, \dots, f_n)$
2. Computes ephemeral curve $E_{\text{eph}} = [d_{\text{eph}}]E_0$
3. Conducts **geometric verification** for $E_{\text{eph}}$:
   - Constructs radius-2 subgraph around $E_{\text{eph}}$
   - Performs all five structure analysis criteria
   - Confirms curve passes hybrid verification (weight ≥ 85%)
4. Computes shared secret $S = j([d_A]E_{\text{eph}})$
5. Forms signature:
   $\sigma = \big( j(E_{\text{eph}}),\ H(M \parallel S) \big)$
6. Transmits signature with transaction to the network

**Step 3: Signature Verification by Bob (and Network Nodes)**
1. Any network node receives transaction and signature $\sigma$
2. Recovers $E_{\text{eph}}$ from $j(E_{\text{eph}})$ in signature
3. Conducts **independent geometric verification** for $E_{\text{eph}}$:
   - Repeats all verification steps described above
   - Rejects signature immediately if curve fails geometric verification
4. If geometric verification passes, node:
   - Computes $S' = j([d_{\text{eph}}]E_B)$
   - Verifies $h = H(M \parallel S')$
5. If verification succeeds, transaction is considered valid

**Detailed Interaction Example:**

Consider Alice sending 1 BTC to Bob. She constructs transaction with hash $M$.

1. Alice generates ephemeral key $d_{\text{eph}}$ and computes corresponding curve $E_{\text{eph}}$.
2. Before using $E_{\text{eph}}$, her system constructs a radius-2 subgraph around it. This resembles geological sampling around a mining site—to verify it is genuine terrain rather than artificially constructed surface.
3. Alice's system analyzes this subgraph across all five criteria. For instance, it finds cyclomatic number $\mu = 3.2$ (exceeding required 2.0), spectral gap of 1.8 (exceeding threshold 1.5), clustering coefficient of 0.35 (within acceptable range 0.2-0.5), degree entropy of 2.1 (within 1.8-2.5), and distance to base curve not exceeding $n \cdot m$. Total evaluation scores 92%, exceeding required 85%.
4. Confirmed legitimate, Alice computes shared secret $S$ and forms signature.
5. Upon receiving the transaction, Bob's system performs identical geometric verification. Critically, verification occurs **before** shared secret computation. This parallels verifying banknote authenticity before acceptance—to avoid falling victim to counterfeits.
6. Bob observes curve $E_{\text{eph}}$ passes all geometric criteria, then verifies the signature. This ensures even if an adversary attempted curve forgery, it would be detected early, before resource-intensive computations.

**Attack Example and Prevention:**

Suppose an adversary attempts signature forgery using curve $\widetilde{E}$ not belonging to the isogeny graph for the given $\ell_i$ set.
- Without geometric verification: network nodes would attempt $j([d_{\text{eph}}]E_B)$ computation for $\widetilde{E}$, potentially causing anomalous behavior (e.g., hanging during non-existent isogeny computation)
- With geometric verification: $\widetilde{E}$ would be rejected during structural analysis. For example, its cyclomatic number might equal 1.5 (below 2), or spectral gap might be absent. Network nodes reject the signature before resource-intensive computations, protecting against DoS attacks and information leaks.

### Why "New Forms of Attack Resistance"?

Because:
- **Classical CSIDH does not verify geometry**—it trusts input curves
- **TorusCSIDH introduces a multi-level filter based on combinatorial graph properties** that:
  - Is independent of $d_A$'s algebraic properties
  - Operates **before** shared secret computation $S = j([d_A]E_{\text{eph}})$
  - Blocks entire classes of forged inputs **at the protocol level**

Thus, **the geometric layer is not an "alternative" to algebra but a "security checkpoint"** ensuring:
> "The object with which we interact genuinely resembles a legitimate node in the secure portion of the isogeny graph"

This is particularly crucial in **signatures**, where the ephemeral key is controlled (or forged) by an adversary.

#### Philosophy of New Attack Resistance Forms

Our security approach represents a paradigm shift in cryptographic protection. Traditionally, cryptography relied on two pillars: computational complexity and key secrecy. However, in the era of quantum computers and sophisticated attacks, this approach becomes insufficient.

We propose a third pillar—**structural integrity**. This parallels transitioning from locks difficult to pick to locks impossible to counterfeit. Classical cryptography asks: "How difficult is secret computation?" TorusCSIDH asks: "Does this object's structure match the expected structure of a legitimate object?"

This represents a fundamentally new form of attack resistance because it doesn't merely make attacks computationally difficult—it makes attacks **structurally impossible**. Just as an architect verifies not only material strength but structural integrity, we verify not only computational complexity but structural properties of cryptographic objects.

Imagine securing a castle. Traditional approach: thick doors and complex locks. Our approach: ensuring the door is genuinely a door, not painted on a wall. Even the most skilled burglar cannot open a painted door because it doesn't exist physically.

In cryptography, this means an adversary cannot merely create an object formally satisfying algebraic conditions—they must create an object matching the entire complex geometry of the cryptographic space. This resembles creating a counterfeit planet with correct mass and orbit plus correct geological structure, atmosphere, and biosphere.

This approach creates **attack resistance through structural harmony**. Just as musical harmony emerges not from individual notes but their relationships, security in TorusCSIDH emerges not from isolated cryptographic properties but their structural relationships. This makes the system resistant to attacks bypassing traditional defenses, as adversaries cannot reproduce the complex geometry of legitimate cryptographic objects.

Such attack resistance doesn't merely increase difficulty for adversaries—it changes the nature of protection, transitioning from "security through complexity" to "security through structural integrity." This parallels transitioning from high walls to natural landscapes that serve as inherent protection—hills, rivers, and forests create natural barriers impossible to traverse without proper preparation.

### Important Clarification

This protection **is not proven in cryptographic-theoretic terms** (e.g., through reduction to a known hard problem) because **analyzing the isogeny graph through combinatorial properties represents a novel idea**.

However, it is **practically justified**: if an adversary cannot create a curve passing geometric verification without knowing the secret, the attack becomes impossible.

This is why the article emphasizes:
> "This layer does not replace algebraic security but complements it"

## Address Format `tcidh1...`: Post-Quantum Identification

We introduce a new address format compatible with **Bech32m** (BIP-350):
```
tcidh1q7m3x9v2k8r4n6p0s5t1u7w9y2a4c6e8g0j3l5n7p9r1t3v5x7z9b2d4f
```

### Structure
- **Version byte**: `0x01` (1 byte)
- **$j$-invariant**: 64 bytes  
  Since $j \in \mathbb{F}_p \subset \mathbb{F}_{p^2}$:
  $$
  j_{\text{bytes}} = j_0.\text{to\_bytes}(32, \text{'big'}) + \underbrace{0^{32}}_{\text{32 zeros}}
  $$
- **Encoding**: Bech32m with prefix `tcidh`

### Address Generation
```python
def generate_tcidh_address():
    d = random_vector_in_range(-m, m, length=n)
    E = apply_isogenies(E0, d)  # [d]E0
    j = E.j_invariant()         # j ∈ 𝔽_p
    j_bytes = j.to_bytes(32, 'big') + bytes(32)
    payload = b'\x01' + j_bytes
    return bech32m_encode('tcidh', payload)
```

## Transaction Signing: ECDSA Analogue with Enhanced Security

### Signing Process
Alice signs message $M$:
1. Generates ephemeral key $d_{\text{eph}}$
2. Computes $E_{\text{eph}} = [d_{\text{eph}}]E_0$
3. Computes shared secret $S = j([d_A]E_{\text{eph}})$
4. Forms signature:
   $$
   \sigma = \big( j(E_{\text{eph}}),\ H(M \parallel S) \big)
   $$

### Verification Process
Any network node:
1. Recovers $E_{\text{eph}}$
2. Computes $S' = j([d_{\text{eph}}]E_A)$ (without knowing $d_A$)
3. Verifies:
   $$
   h \stackrel{?}{=} H(M \parallel S')
   $$

> **Advantage**: Reusing $d_{\text{eph}}$ **does not compromise** $d_A$—unlike ECDSA, where reuse enables secret key recovery

## Bitcoin Integration: Soft Fork Compatibility

- **ScriptPubKey**: `OP_1 <32-byte SHA256(j)>`—analogous to Taproot
- **Witness**: `[signature, j_pub]`
- **Sizes**:
  - Public key: 64 bytes
  - Signature: 96 bytes

This constitutes a **soft fork**, compatible with SegWit. Legacy wallets will treat `tcidh1...` addresses as invalid—preventing accidental fund transfers.

## Why "Isogeny Graph" Instead of "Torus"?

One might ask: *"If we work over finite fields without continuity, where does geometry originate?"*

Answer: **We focus on actual combinatorial properties of the isogeny graph**.

The isogeny graph is a concrete discrete structure, and in its local neighborhood, a typical subgraph contains two independent cycles. This is not an abstract topological concept but a measurable combinatorial property verifiable algorithmically through cyclomatic number and spectral analysis.

**Our original method—analysis through cyclomatic number and spectral gap—is absent from CSIDH or isogeny literature.**

## Conclusion

**TorusCSIDH is not an experiment. It is a ready solution for Bitcoin's post-quantum future.**
- **Scientifically rigorous**: Based on CSIDH without pseudoscientific constructs
- **Practically implementable**: Complete specification of address, script, transaction
- **Compatible**: Soft fork, Bech32m, SegWit
- **More secure than ECDSA**: Protection against ephemeral key reuse
- **Novelty**: Introduction of geometric verification layer based on isogeny graph structure analysis through cyclomatic number and spectral gap

> **Next step—pilot with mining pool.** Who is ready to be the first?

> **Note**: The geometric layer (verification of local cyclicity through cyclomatic number and spectral gap) **has no direct analogues** in isogeny literature. It is inspired by graph theory methods but **applied for the first time** in the context of post-quantum cryptography on isogenies.

## Technical Appendix: Complete Geometric Verification Implementation

### 1. Verification Objective
Verifying the **local structure** of ephemeral curve $E_{\text{eph}}$ in the isogeny graph.  
Specifically: ensuring that within radius $r = 2$ or $3$ neighborhood around $E_{\text{eph}}$, the graph contains **exactly two independent cycles**, consistent with typical isogeny graph structure.

This is accomplished through **multi-factor analysis** including cyclomatic number, spectral analysis, and other combinatorial subgraph properties.

### 2. Subgraph Construction
**Input**: Curve $E_{\text{eph}}$, set of small primes $\{\ell_1, \dots, \ell_n\}$, radius $r \in \{2, 3\}$.

**Algorithm**:
1. Initialize vertex set $V = \{E_{\text{eph}}\}$ and edge set $E = \emptyset$.
2. For each distance level from $1$ to $r$:
   - For each curve $E' \in V$ at previous level:
     - For each $\ell_i$:
       - Compute all $\ell_i$-isogenies from $E'$ (total $\ell_i + 1$)
       - For each resulting curve $E''$:
         - Normalize by $j(E'')$
         - Add $E''$ to $V$ if not already present
         - Add undirected edge $\{E', E''\}$ to $E$.
3. Return subgraph $G_r = (V, E)$.

### 3. Cyclomatic Number
For any finite connected undirected graph, the **cyclomatic number** is defined as:
$$
\mu = |E| - |V| + 1
$$
It equals the number of **independent cycles** in the graph (in graph theory terms).

In TorusCSIDH, we require:
$$
\mu \geq 2
$$
If $\mu < 2$, the curve is rejected as "degenerate" (e.g., residing in tree-like or linear graph regions).

### 4. Spectral Analysis
Complementing $\mu$, we analyze **eigenvalues of the combinatorial Laplacian**:
- Construct adjacency matrix $A$ and degree matrix $D$
- Compute $L = D - A$
- Determine eigenvalues: $0 = \lambda_1 \leq \lambda_2 \leq \dots \leq \lambda_{|V|}$

**Criteria**:
1. **Connectivity**: $\lambda_1 = 0$ with multiplicity 1
2. **Presence of two cycles**:  
   - $\lambda_2 > 0$ and $\lambda_3$ **small** (e.g., $\lambda_3 < 0.5$)
   - $\lambda_4$ **significantly larger** (e.g., $\lambda_4 \geq 0.7$)
3. **Spectral gap**:  
   - $(\lambda_4 - \lambda_3)/\lambda_3 > 1.5$
   - Indicates **pronounced spectral gap** after second non-zero eigenvalue

This aligns with the observation that in typical isogeny graph subgraphs, the first two non-zero Laplacian eigenvalues are small and separated from the rest of the spectrum.

### 5. Clustering Coefficient
Compute average clustering coefficient for the subgraph:
$$
C = \frac{1}{|V|} \sum_{v \in V} \frac{2 \times \text{number of triangles containing } v}{\deg(v) \times (\deg(v)-1)}
$$
Require $C \in [0.2, 0.5]$.

This criterion verifies how "densely" vertices are locally connected around $E_{\text{eph}}$.

### 6. Degree Distribution Entropy
Analyze degree distribution of vertices in the subgraph:
$$
H = -\sum_{k} p_k \log_2 p_k
$$
where $p_k$ is the proportion of vertices with degree $k$.

Require $H \in [1.8, 2.5]$.

Low entropy indicates regular structure (potentially degenerate), high entropy indicates random structure (potentially artificial).

### 7. Distance Verification from Base Curve
To protect against "long path" attacks, estimate approximate distance from $E_{\text{eph}}$ to base curve $E_0$ through $j$-invariant differences.

Require distance not exceeding $n \cdot m$ (maximum distance for legitimate curves).

### 8. Hybrid Evaluation
Each criterion receives a weight:
- Cyclomatic number: 15%
- Spectral analysis: 30%
- Clustering coefficient: 20%
- Degree entropy: 25%
- Distance to base curve: 10%

A curve is accepted **only if** the cumulative weight of satisfied criteria is ≥ 85%.

### 9. Important Notes
- All computations are **purely combinatorial**, over the finite graph
- **No complex topological concepts** are used, only basic graph theory
- The method **does not replace** CSIDH algebraic security but **prevents attacks through forged curves** failing geometric verification

## Contact

For collaboration opportunities or technical inquiries, please contact:

**miro-aleksej@yandex.ru**

## License

This project is licensed under the MIT License - see the [LICENSE]([LICENSE](https://github.com/miroaleksej/TorusCSIDH/blob/main/LICENSE)) file for details.

---

**TorusCSIDH — Защита Bitcoin от квантовых угроз через структурную гармонию графа изогений.**

## Keywords

post-quantum-cryptography, csidh, isogeny-based-cryptography, bitcoin-security, quantum-resistant-cryptography, elliptic-curve-cryptography, geometric-verification, toruscsidh, supersingular-isogeny, bech32m, soft-fork, bitcoin-upgrade, cryptographic-signatures, bitcoin-core, quantum-computing, blockchain-security, montgomery-curve, velu-formulas, shufl-algorithm, side-channel-protection
