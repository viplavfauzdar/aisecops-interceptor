import pytest
from aisecops_interceptor.core.execution import ExecutionGate
from aisecops_interceptor.core.decision import DecisionResult, DecisionType


def dummy_tool():
    return "ok"


def test_allow_execution():
    gate = ExecutionGate()
    result = gate.execute(DecisionResult(DecisionType.ALLOW), dummy_tool)
    assert result == "ok"


def test_block_execution():
    gate = ExecutionGate()
    with pytest.raises(RuntimeError):
        gate.execute(DecisionResult(DecisionType.BLOCK, "policy"), dummy_tool)
