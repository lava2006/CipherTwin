"""Unit and Integration tests for QAPRE (Quantum-Assisted Policy Reoptimization Engine)."""
import os
import numpy as np
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.policy import Policy, PolicyImprovement, PolicyChange
from app.models.risk import RiskDecision
from app.services.qubo_builder import build_policy_qubo, evaluate_solution_cost
from app.services.quantum_optimizer import QuantumOptimizer, qubo_to_ising, build_qaoa_hamiltonians


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    # Seed test policies
    p1 = Policy(name="Strict Lockout", rule="deny_if:risk>60", weight=1.0, false_positive_rate=0.08, false_negative_rate=0.05)
    p2 = Policy(name="Database Guard", rule="restricted_if:resource==database", weight=1.0, false_positive_rate=0.06, false_negative_rate=0.04)
    p3 = Policy(name="USB Policy", rule="allow_if:device==trusted", weight=1.0, false_positive_rate=0.04, false_negative_rate=0.02)
    db.add_all([p1, p2, p3])

    # Seed test risk decision
    d1 = RiskDecision(risk_score=75.0, decision="deny", confidence=0.9)
    db.add(d1)
    db.commit()

    yield db
    db.close()


def test_qaoa_circuit_execution_on_lightning_qubit():
    """Verify QAOA circuit executes on PennyLane lightning.qubit and returns real expectation value."""
    import pennylane as qml
    from pennylane import numpy as pnp

    units = [
        {"id": "u1", "risk_score": 25.0, "trust_score": 75.0},
        {"id": "u2", "risk_score": 85.0, "trust_score": 15.0},
    ]
    Q, offset, var_names, _ = build_policy_qubo(units, decoy_capacity=1)
    num_qubits = len(var_names)

    h, J, h0 = qubo_to_ising(Q, offset)
    cost_h, mixer_h = build_qaoa_hamiltonians(h, J, num_qubits)

    dev = qml.device("lightning.qubit", wires=num_qubits)
    p = 2

    def circuit(params):
        for w in range(num_qubits):
            qml.Hadamard(wires=w)
        for layer in range(p):
            qml.qaoa.cost_layer(params[0][layer], cost_h)
            qml.qaoa.mixer_layer(params[1][layer], mixer_h)

    @qml.qnode(dev, diff_method="adjoint")
    def cost_qnode(params):
        circuit(params)
        return qml.expval(cost_h)

    params = pnp.array([
        [0.1, 0.2],
        [0.2, 0.1],
    ], requires_grad=True)

    exp_val = cost_qnode(params)
    assert not np.isnan(float(exp_val)), "Expectation value must not be NaN"
    assert isinstance(float(exp_val), float), "Expectation value must be a valid float"


def test_qaoa_optimization_end_to_end(test_db):
    """Integration test: feed policies through QUBO -> QAOA (lightning.qubit) -> SA baseline -> Policy update."""
    optimizer = QuantumOptimizer(test_db)
    state_before = optimizer.current_state()
    assert len(state_before["policies"]) == 3

    # Run real QAOA optimization
    result = optimizer.optimize(layers=2, iterations=10)

    # Verify result contract
    assert result.before_score > 0
    assert result.after_score > 0
    assert result.iterations == 10
    assert result.duration_ms > 0
    assert len(result.changes) == 3
    assert result.qaoa_cost is not None
    assert result.classical_cost is not None
    assert result.classical_duration_ms is not None

    # Verify database persistence
    history = optimizer.history(limit=5)
    assert len(history) >= 1
    assert "lightning.qubit" in history[0].algorithm
    assert history[0].summary is not None
    assert len(history[0].summary) > 20

    # Assert policies actually changed in the database
    policies_after = test_db.query(Policy).all()
    assert any(p.weight != 1.0 for p in policies_after), "Policies must be reweighted"

    # Assert policy change audit records were created
    changes = test_db.query(PolicyChange).all()
    assert len(changes) == 3
    assert changes[0].change_type == "quantum_reoptimized"
