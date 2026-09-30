"""Unit and Integration tests for QAPRE (Quantum-Assisted Policy Reoptimization Engine)."""
import os
import numpy as np
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.policy import Policy, PolicyImprovement, PolicyChange
from app.models.risk import RiskDecision
from app.models.twin import TwinNode
from app.models.user import User
from app.services.deception import DeceptionEngine
from app.services.qubo_builder import build_policy_qubo, decode_solution, evaluate_solution_cost
from app.services.quantum_optimizer import (
    OptimizationResult,
    QuantumOptimizer,
    build_qaoa_hamiltonians,
    qubo_to_ising,
)


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
    assert result.method == "quantum"
    assert result.fallback_reason is None
    assert np.isfinite(result.qaoa_cost)
    assert result.qubits == 11
    assert len(result.bitstring) == 9

    # Verify database persistence
    history = optimizer.history(limit=5)
    assert len(history) >= 1
    assert "lightning.qubit" in history[0].algorithm
    assert history[0].method == "quantum"
    assert history[0].fallback_reason is None
    assert history[0].summary is not None
    assert len(history[0].summary) > 20

    # Assert policies actually changed in the database
    policies_after = test_db.query(Policy).all()
    assert any(p.weight != 1.0 for p in policies_after), "Policies must be reweighted"

    # Assert policy change audit records were created
    changes = test_db.query(PolicyChange).all()
    assert len(changes) == 3
    assert changes[0].change_type == "quantum_reoptimized"


def test_qaoa_training_converges_and_returns_a_feasible_sample():
    units = [
        {"id": "u1", "risk_score": 25.0, "trust_score": 75.0},
        {"id": "u2", "risk_score": 85.0, "trust_score": 15.0},
    ]
    capacity = 1
    Q, offset, _, _ = build_policy_qubo(units, decoy_capacity=capacity)

    bitstring, cost, steps, duration, cost_history = QuantumOptimizer(None)._solve_qaoa(
        Q, offset, units, p_layers=2, iterations=10, decoy_capacity=capacity
    )

    valid, assignments, counts = decode_solution(bitstring, units)
    assert steps == 10
    assert duration > 0
    assert bitstring and len(bitstring) == Q.shape[0]
    assert np.isfinite(cost)
    assert np.isfinite(cost_history).all()
    assert min(cost_history[1:]) < cost_history[0]
    assert valid
    assert counts["restrict"] <= capacity
    assert len(assignments) == len(units)


def test_classical_fallback_is_reported_and_persisted(test_db, monkeypatch, caplog):
    optimizer = QuantumOptimizer(test_db)

    def fail_qaoa(**_kwargs):
        raise RuntimeError("injected lightning failure")

    monkeypatch.setattr(optimizer, "_solve_qaoa", fail_qaoa)
    result = optimizer.optimize(layers=2, iterations=5)

    record = optimizer.history(limit=1)[0]
    assert result.method == "classical_fallback"
    assert result.fallback_reason == "RuntimeError: injected lightning failure"
    assert result.qaoa_cost is None
    assert np.isfinite(result.classical_cost)
    assert record.method == "classical_fallback"
    assert record.fallback_reason == result.fallback_reason
    assert record.to_dict()["method"] == "classical_fallback"
    assert record.to_dict()["fallback_reason"] == result.fallback_reason
    assert "injected lightning failure" in record.summary
    assert "injected lightning failure" in caplog.text
    assert all(change.change_type == "classical_fallback_reoptimized" for change in test_db.query(PolicyChange).all())


def test_optimization_api_returns_solver_provenance(test_db, monkeypatch):
    from app.api.optimization import run_optimization

    result = OptimizationResult(
        before_score=1.0,
        after_score=0.8,
        before_fp=0.1,
        after_fp=0.08,
        before_fn=0.1,
        after_fn=0.08,
        iterations=0,
        duration_ms=12,
        changes=[],
        method="classical_fallback",
        fallback_reason="TimeoutError: QAOA timed out",
        qubits=5,
        qaoa_cost=None,
        classical_cost=8.1,
        decoy_method="classical_fallback",
        decoy_fallback_reason="batch too large",
        decoy_assignments=[{"node_id": "asset-1", "action": "restrict"}],
    )
    monkeypatch.setattr(QuantumOptimizer, "optimize", lambda self, **_kwargs: result)

    response = run_optimization(
        payload={"iterations": 5},
        db=test_db,
        user=User(username="admin", email="admin@example.test", hashed_password="", role="admin"),
    )

    assert response["method"] == "classical_fallback"
    assert response["fallback_reason"] == "TimeoutError: QAOA timed out"
    assert response["qubits"] == 5
    assert response["qaoa_cost"] is None
    assert response["classical_cost"] == 8.1
    assert response["decoy_method"] == "classical_fallback"
    assert response["decoy_fallback_reason"] == "batch too large"
    assert response["decoy_assignments"] == [{"node_id": "asset-1", "action": "restrict"}]


def test_decoy_placement_changes_with_risk_and_respects_capacity(test_db):
    scenario_a = [45.0, 50.0, 10.0, 15.0, 20.0, 30.0, 70.0, 90.0]
    scenario_b = [10.0, 15.0, 20.0, 30.0, 45.0, 50.0, 70.0, 90.0]
    for index, risk in enumerate(scenario_a):
        test_db.add(TwinNode(
            id=f"asset-{index}",
            label=f"Asset {index}",
            type="server",
            trust_score=100.0 - risk,
            risk_score=risk,
            status="online",
        ))
    test_db.commit()

    optimizer = QuantumOptimizer(test_db)
    first = optimizer._optimize_decoy_placement(decoy_capacity=2, layers=2, iterations=10)
    first_ids = {assignment["node_id"] for assignment in first["assignments"]}

    for index, risk in enumerate(scenario_b):
        node = test_db.query(TwinNode).filter(TwinNode.id == f"asset-{index}").one()
        node.risk_score = risk
        node.trust_score = 100.0 - risk
    second = optimizer._optimize_decoy_placement(decoy_capacity=2, layers=2, iterations=10)
    second_ids = {assignment["node_id"] for assignment in second["assignments"]}

    assert len(first_ids) == 2
    assert len(second_ids) == 2
    assert first_ids != second_ids
    assert first["method"] == second["method"] == "classical_fallback"
    assert "batch too large" in first["fallback_reason"]
    assigned_tags = {
        node.id
        for node in test_db.query(TwinNode).all()
        if "optimized_honeypot" in (node.tags or "").split(",")
    }
    assert assigned_tags == second_ids

    decoy_session = DeceptionEngine(test_db).open_decoy(
        actor="risk-scenario-test",
        source_ip="192.0.2.25",
        threat_id=None,
        risk_score=85.0,
        event_type="ssh_attempt",
    )
    assert decoy_session.target_node_id in second_ids
    assert decoy_session.to_dict()["target_node_id"] == decoy_session.target_node_id
