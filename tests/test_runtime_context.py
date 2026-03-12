from aisecops_interceptor.core.context import RuntimeContext


def test_context_creation():
    ctx = RuntimeContext(agent_name="demo-agent", user_id="user1")
    assert ctx.agent_name == "demo-agent"
