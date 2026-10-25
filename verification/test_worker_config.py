import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkerRouteConfig(unittest.TestCase):
    def test_only_repository_hosts_are_bound_as_custom_domains(self):
        config = json.loads((ROOT / "worker" / "wrangler.jsonc").read_text())
        routes = config["routes"]
        self.assertEqual(
            routes,
            [
                {"pattern": "repo.apt.to", "custom_domain": True},
                {"pattern": "early.apt.to", "custom_domain": True},
            ],
        )
        self.assertFalse(config["workers_dev"])


if __name__ == "__main__":
    unittest.main()
