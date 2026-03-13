import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.exceptions import PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


def read_customer(customer_id: str) -> dict:
    return {"customer_id": customer_id, "status": "active"}


def delete_database(name: str) -> dict:
    return {"deleted": name}


if __name__ == "__main__":
    policy = PolicyEngine.from_yaml_file()
    audit = AuditLogger()
    interceptor = AgentInterceptor(policy_engine=policy, audit_logger=audit)

    tools = {
        "read_customer": read_customer,
        "delete_database": delete_database,
    }

    ok = interceptor.execute(
        agent_name="sales_agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
        tool_registry=tools,
    )
    print("ALLOWED:", ok)

    try:
        interceptor.execute(
            agent_name="sales_agent",
            tool_call=ToolCall(name="delete_database", arguments={"name": "prod"}),
            tool_registry=tools,
        )
    except PolicyViolationError as exc:
        print("BLOCKED:", exc)
