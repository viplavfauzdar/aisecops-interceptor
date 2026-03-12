from aisecops_interceptor.guard.output_inspector import inspect_output


def test_secret_detection():
    result = inspect_output("Here is the api_key: 123")
    assert len(result.findings) > 0
