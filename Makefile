# Makefile for TorusCSIDH Formal Verification
# Mathematical security proofs for post-quantum cryptography

# Configuration variables
COQBIN ?= $(shell which coqc 2>/dev/null || echo '')
COQDEP ?= $(shell which coqdep 2>/dev/null || echo '')
COQCHK ?= $(shell which coqchk 2>/dev/null || echo '')

# Directories
SRC_DIR = src
PROOF_DIR = proofs
FP_ARITH_DIR = $(PROOF_DIR)/arithmetic_fp
FP2_ARITH_DIR = $(PROOF_DIR)/arithmetic_fp2
CURVE_DIR = $(PROOF_DIR)/elliptic_curves
SECURITY_DIR = $(PROOF_DIR)/security

# File patterns
VO_FILES = $(shell find $(PROOF_DIR) -name '*.vo' 2>/dev/null || echo '')
V_FILES = $(shell find $(PROOF_DIR) -name '*.v' 2>/dev/null || echo '')

# Default target
all: check-dependencies build-proofs verify-proofs generate-report

# Check for required dependencies
check-dependencies:
ifndef COQBIN
	$(error Coq compiler (coqc) not found. Please install Coq >= 8.15)
endif
ifndef COQDEP
	$(error Coq dependency tool (coqdep) not found. Please install Coq >= 8.15)
endif
ifndef COQCHK
	$(error Coq checker (coqchk) not found. Please install Coq >= 8.15)
endif
	@echo "✅ All dependencies verified"
	@coqc --version
	@echo "CoqPATH: $(COQPATH)"

# Build all proofs
build-proofs: $(VO_FILES)
	@echo "✅ All Coq proofs successfully compiled"

# Verify all proofs using coqchk
verify-proofs: build-proofs
	@echo "🔍 Verifying proofs with coqchk for additional security..."
	@coqchk -silent -o $(PROOF_DIR)/theories $(V_FILES)

# Explicit compilation rules
$(PROOF_DIR)/%.vo: $(PROOF_DIR)/%.v
	@echo "Compiling $< -> $@"
	@mkdir -p $(@D)
	@coqc -q -R $(PROOF_DIR) TorusCSIDH $<

# Generate verification report
generate-report: verify-proofs
	@echo "📊 Generating formal verification report..."
	@coqtop -batch -require $(PROOF_DIR)/theories/TorusCSIDH_Security.v -l $(PROOF_DIR)/theories/report.v > verification_report.txt
	@echo "✅ Verification report generated: verification_report.txt"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@find $(PROOF_DIR) -name '*.vo' -delete 2>/dev/null || true
	@find $(PROOF_DIR) -name '*.glob' -delete 2>/dev/null || true
	@find $(PROOF_DIR) -name '*.v.d' -delete 2>/dev/null || true
	@rm -f verification_report.txt 2>/dev/null || true
	@echo "✅ Cleaned all build artifacts"

# Run specific proof
run-proof:
ifdef PROOF
	@coqc -q -R $(PROOF_DIR) TorusCSIDH $(PROOF_DIR)/$(PROOF).v
else
	$(error Please specify PROOF variable, e.g., make run-proof PROOF=arithmetic_fp/Fp_Correctness)
endif

# Print dependency graph
dependencies:
	@echo "🔍 Analyzing proof dependencies..."
	@coqdep -R . TorusCSIDH $(V_FILES) > dependencies.dot
	@echo "✅ Dependency graph generated: dependencies.dot"
	@echo "💡 To visualize: dot -Tpng dependencies.dot -o dependencies.png"

# Run test suite
test: build-proofs
	@echo "🧪 Running formal verification test suite..."
	@coqtop -batch -require $(PROOF_DIR)/theories/TestSuite.v -l $(PROOF_DIR)/theories/test_runner.v

# Install dependencies
install-deps:
	@echo "📦 Installing Coq dependencies..."
	@opam init --disable-sandboxing --yes || true
	@eval $$(opam env)
	@opam install -y coq coq-mathcomp-ssreflect coq-mathcomp-algebra coq-stdpp coq-serapi

# Help target
help:
	@echo "TorusCSIDH Formal Verification Makefile"
	@echo "======================================"
	@echo "Targets:"
	@echo "  all             - Build and verify all proofs"
	@echo "  build-proofs    - Compile all Coq proofs"
	@echo "  verify-proofs   - Verify compiled proofs with coqchk"
	@echo "  generate-report - Generate verification report"
	@echo "  test            - Run formal verification test suite"
	@echo "  clean           - Clean all build artifacts"
	@echo "  install-deps    - Install required Coq dependencies"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                   # Full build and verification"
	@echo "  make clean             # Clean build artifacts"
	@echo "  make install-deps      # Install Coq dependencies"
	@echo "  make run-proof PROOF=arithmetic_fp/Fp_Correctness"

.PHONY: all check-dependencies build-proofs verify-proofs generate-report clean run-proof dependencies test install-deps help
