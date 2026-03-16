from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.policy.loader import PolicyLoader
from aisecops_interceptor.policy.schema import CapabilityBundleValidationError


def test_loads_valid_capability_yaml(tmp_path) -> None:
    capability_path = tmp_path / "capabilities.yaml"
    capability_path.write_text(
        "\n".join(
            [
                "capabilities:",
                "  cap_service_ops:",
                "    tools:",
                "      - restart_service",
                "      - stop_service",
                "  cap_customer_read:",
                "    tools:",
                "      - read_customer",
            ]
        ),
        encoding="utf-8",
    )

    bundle = PolicyLoader.from_capabilities_yaml(str(capability_path))
    assert bundle.capabilities == {
        "cap_service_ops": ("restart_service", "stop_service"),
        "cap_customer_read": ("read_customer",),
    }


def test_invalid_capability_yaml_raises_validation_error(tmp_path) -> None:
    capability_path = tmp_path / "capabilities.yaml"
    capability_path.write_text(
        "\n".join(
            [
                "capabilities:",
                "  cap_service_ops:",
                "    tools: restart_service",
            ]
        ),
        encoding="utf-8",
    )

    try:
        PolicyLoader.from_capabilities_yaml(str(capability_path))
        assert False, "Expected invalid capability YAML to fail validation"
    except CapabilityBundleValidationError as exc:
        assert "field 'tools' must be a list" in str(exc)


def test_registry_from_yaml_allows_configured_tool(tmp_path) -> None:
    capability_path = tmp_path / "capabilities.yaml"
    capability_path.write_text(
        "\n".join(
            [
                "capabilities:",
                "  cap_service_ops:",
                "    tools:",
                "      - restart_service",
            ]
        ),
        encoding="utf-8",
    )

    registry = CapabilityRegistry.from_yaml(str(capability_path))
    assert registry.is_tool_allowed("restart_service", ["cap_service_ops"]) is True
    assert registry.is_tool_allowed("restart_service", ["cap_customer_read"]) is False


def test_direct_python_mapping_remains_supported() -> None:
    registry = CapabilityRegistry(
        {
            "cap_service_ops": ["restart_service"],
            "cap_customer_read": ["read_customer"],
        }
    )

    assert registry.is_tool_allowed("restart_service", ["cap_service_ops"]) is True
    assert registry.required_capabilities_for_tool("read_customer") == ("cap_customer_read",)


def test_registry_defaults_to_external_capability_bundle_path() -> None:
    registry = CapabilityRegistry.from_yaml()

    assert registry.is_tool_allowed("restart_service", ["cap_service_ops"]) is True
    assert registry.required_capabilities_for_tool("read_customer") == ("cap_customer_read",)
