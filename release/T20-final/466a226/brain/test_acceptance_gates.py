import unittest

from brain.acceptance_gates import lifecycle_gate, tier3_gate, wfp_host_effect_gate


class AcceptanceGateTests(unittest.TestCase):
    def test_lifecycle_requires_shield_and_forensic_recovery(self):
        before = {"records": 2}
        after = {
            "records": 3,
            "rust_shield": {"state": "READY", "pep_ready": True, "policy_authority": True},
            "forensic": {"verified": True},
            "workers": {
                "pipeline_ready": True,
                "sensor_ready": True,
                "nose_ready": True,
                "etw_ready": True,
                "fim_ready": True,
                "registry_ready": True,
            },
            "overall_gate": False,
        }
        self.assertTrue(lifecycle_gate(before, after))

    def test_tier3_requires_all_capabilities_not_artifact_only(self):
        health = {"tier3": {"artifact_present": True, "dependency_ready": True, "provider_ready": False, "host_effect_capable": False, "ready": False}}
        self.assertFalse(tier3_gate(health))

    def test_wfp_requires_receipt_and_postcondition(self):
        health = {"rust_shield": {"provider_ready": True, "host_effect_capable": True}}
        receipt = {"status": "ENFORCED", "host_effect_confirmed": True}
        self.assertTrue(wfp_host_effect_gate(health, receipt, {"verified": True}))
        self.assertFalse(wfp_host_effect_gate(health, receipt, {"verified": False}))


if __name__ == "__main__":
    unittest.main()
