import importlib.util
from pathlib import Path


TEST_PATH = Path(__file__).resolve().parents[2] / "tests" / "pep" / "test_t8_rust_pep.py"
SPEC = importlib.util.spec_from_file_location("aegis_t8", TEST_PATH)
assert SPEC is not None and SPEC.loader is not None
t8 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(t8)


def main() -> None:
    t8.test_flow_request_uses_policy_action_block_not_response_decision()
    t8.test_wfp_flow_response_contract_is_complete()
    print("P0 static contract assertions: PASS (2)")


if __name__ == "__main__":
    main()
