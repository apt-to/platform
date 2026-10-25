import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkerRouteConfig(unittest.TestCase):
    def test_site_and_repository_hosts_are_bound_as_custom_domains(self):
        config = json.loads((ROOT / "worker" / "wrangler.jsonc").read_text())
        routes = config["routes"]
        self.assertEqual(
            routes,
            [
                {"pattern": "apt.to", "custom_domain": True},
                {"pattern": "repo.apt.to", "custom_domain": True},
                {"pattern": "early.apt.to", "custom_domain": True},
            ],
        )
        self.assertFalse(config["workers_dev"])

    def test_snapshot_schedule_is_opt_in_until_repository_infrastructure_is_ready(self):
        workflow = (ROOT / ".github" / "workflows" / "repository-snapshot.yml").read_text()
        self.assertRegex(
            workflow,
            r"build-indexes:\n\s+if: >-\n\s+vars\.APTTO_REPOSITORY_ENABLED == 'true' &&",
        )


if __name__ == "__main__":
    unittest.main()
