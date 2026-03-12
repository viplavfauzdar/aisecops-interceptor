from aisecops_interceptor.core.context import RuntimeContext


def test_context_creation():
    ctx = RuntimeContext(agent_name="demo-agent", user_id="user1")
    assert ctx.agent_name == "demo-agent"
    assert ctx.data_classification is None
    assert ctx.source is None
    assert ctx.sensitivity_level is None


def test_context_creation_with_data_classification_fields():
    ctx = RuntimeContext(
        agent_name="demo-agent",
        user_id="user1",
        data_classification="pii",
        source="crm",
        sensitivity_level="high",
    )
    assert ctx.data_classification == "pii"
    assert ctx.source == "crm"
    assert ctx.sensitivity_level == "high"
