"""Unit tests for the QUBO builder module."""
import numpy as np
import pytest
from app.services.qubo_builder import (
    build_policy_qubo,
    evaluate_solution_cost,
    decode_solution,
    ACTION_ALLOW,
    ACTION_RESTRICT,
    ACTION_DENY,
)


def test_qubo_matrix_dimensions_and_structure():
    units = [
        {"id": "u-admin", "risk_score": 20.0, "trust_score": 90.0},
        {"id": "u-suspicious", "risk_score": 85.0, "trust_score": 15.0},
        {"id": "u-moderate", "risk_score": 55.0, "trust_score": 50.0},
    ]
    Q, offset, var_names, qubo_dict = build_policy_qubo(units, decoy_capacity=2)

    assert Q.shape == (9, 9)
    assert len(var_names) == 9
    assert np.allclose(Q, np.triu(Q)), "Q matrix must be upper triangular"
    assert offset > 0.0
    assert len(qubo_dict) > 0


def test_qubo_one_hot_penalty_enforcement():
    units = [
        {"id": "test_unit", "risk_score": 10.0, "trust_score": 90.0}
    ]
    Q, offset, _, _ = build_policy_qubo(units, lambda_onehot=20.0)

    # Valid one-hot solutions
    cost_allow = evaluate_solution_cost([1, 0, 0], Q, offset)
    cost_restrict = evaluate_solution_cost([0, 1, 0], Q, offset)
    cost_deny = evaluate_solution_cost([0, 0, 1], Q, offset)

    # Invalid solutions (0-hot or 2-hot)
    cost_zero_hot = evaluate_solution_cost([0, 0, 0], Q, offset)
    cost_two_hot = evaluate_solution_cost([1, 1, 0], Q, offset)

    # One-hot solutions should be significantly lower energy than invalid configurations
    assert cost_zero_hot > cost_allow
    assert cost_two_hot > cost_allow


def test_qubo_risk_preference():
    """Low risk should prefer Allow; High risk should prefer Deny or Restrict."""
    low_risk_unit = [{"id": "low_risk", "risk_score": 10.0, "trust_score": 90.0}]
    Q_low, off_low, _, _ = build_policy_qubo(low_risk_unit)
    c_allow = evaluate_solution_cost([1, 0, 0], Q_low, off_low)
    c_deny = evaluate_solution_cost([0, 0, 1], Q_low, off_low)
    assert c_allow < c_deny, "Low risk principal must incur lower cost under Allow"

    high_risk_unit = [{"id": "high_risk", "risk_score": 90.0, "trust_score": 10.0}]
    Q_high, off_high, _, _ = build_policy_qubo(high_risk_unit)
    c_allow_h = evaluate_solution_cost([1, 0, 0], Q_high, off_high)
    c_deny_h = evaluate_solution_cost([0, 0, 1], Q_high, off_high)
    assert c_deny_h < c_allow_h, "High risk principal must incur lower cost under Deny"


def test_decode_solution():
    units = [
        {"id": "u1", "risk_score": 20.0},
        {"id": "u2", "risk_score": 80.0},
    ]
    # Valid bitstring: u1 -> allow, u2 -> deny
    is_valid, assignments, counts = decode_solution([1, 0, 0, 0, 0, 1], units)
    assert is_valid is True
    assert assignments[0]["action"] == "allow"
    assert assignments[1]["action"] == "deny"
    assert counts["allow"] == 1
    assert counts["deny"] == 1
    assert counts["restrict"] == 0
