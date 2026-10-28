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
                {"pattern": "getpatched.dev", "custom_domain": True},
                {"pattern": "repo.getpatched.dev", "custom_domain": True},
                {"pattern": "early.getpatched.dev", "custom_domain": True},
            ],
        )
        self.assertFalse(config["workers_dev"])

    def test_snapshot_schedule_is_opt_in_until_repository_infrastructure_is_ready(self):
        workflow = (ROOT / ".github" / "workflows" / "repository-snapshot.yml").read_text()
        self.assertRegex(
            workflow,
            r"build-indexes:\n\s+if: >-\n\s+vars\.GETPATCHED_REPOSITORY_ENABLED == 'true' &&",
        )

    def test_snapshot_rollback_is_manual_and_requires_the_protected_signing_environment(self):
        workflow = (ROOT / ".github" / "workflows" / "repository-snapshot.yml").read_text()
        self.assertRegex(workflow, r"operation:\n\s+description:.*\n\s+type: choice\n\s+required: true\n\s+default: publish\n\s+options: \[publish, rollback, prune\]")
        self.assertRegex(workflow, r"vars\.GETPATCHED_REPOSITORY_ENABLED == 'true' &&\n\s+\(github\.event_name != 'workflow_dispatch' \|\| github\.event\.inputs\.operation != 'rollback'\) &&")
        self.assertRegex(workflow, r"rollback:\n\s+if: >-\n(?:\s+.*\n){3}\s+github\.event\.inputs\.operation == 'rollback'")
        self.assertRegex(workflow, r"rollback:\n(?:.*\n){0,12}\s+environment: getpatched-signing")
        self.assertIn("python3 scripts/rollback-apt-snapshot.py", workflow)

    def test_snapshot_workflow_skips_signing_when_both_channels_are_unchanged(self):
        workflow = (ROOT / ".github" / "workflows" / "repository-snapshot.yml").read_text()
        self.assertIn('snapshot_ids = {row["channel"]: row["snapshot_build"] for row in rows if row.get("snapshot_build")}', workflow)
        self.assertIn("needs.build-indexes.outputs.snapshot_ids != '{}'", workflow)

    def test_snapshot_retention_is_weekly_or_manual_and_runs_in_the_protected_signing_environment(self):
        workflow = (ROOT / ".github" / "workflows" / "repository-snapshot.yml").read_text()
        self.assertIn('- cron: "25 3 * * 0"', workflow)
        self.assertIn("options: [publish, rollback, prune]", workflow)
        self.assertRegex(workflow, r"snapshot-retention:\n(?:.*\n){0,16}\s+environment: getpatched-signing")
        self.assertIn("needs: [build-indexes, sign-and-publish]", workflow)
        self.assertIn("python3 scripts/retain-apt-snapshots.py --channel both", workflow)

    def test_worker_deployment_runs_on_main_push_and_keeps_manual_confirmation(self):
        workflow = (ROOT / ".github" / "workflows" / "worker-deploy.yml").read_text()
        self.assertRegex(workflow, r"push:\n\s+branches:\n\s+- main")
        self.assertRegex(workflow, r"confirm_production:\n\s+description:.*\n\s+type: boolean\n\s+required: true\n\s+default: false")
        self.assertNotIn("GETPATCHED_WORKER_DEPLOY_ENABLED", workflow)
        self.assertEqual(workflow.count("github.ref == 'refs/heads/main'"), 2)
        self.assertEqual(workflow.count("github.event_name == 'push'"), 2)
        self.assertEqual(workflow.count("inputs.confirm_production == true"), 2)
        self.assertRegex(workflow, r"deploy:\n\s+needs: verify\n(?:.*\n){0,10}\s+environment: getpatched-worker-deploy")
        self.assertIn("cloudflare/wrangler-action@953926a2e2182532811c01a25e53647d93bf07c0 # v4.1.3", workflow)
        self.assertIn('wranglerVersion: "4.151.3"', workflow)
        self.assertIn("secrets.CLOUDFLARE_API_TOKEN", workflow)
        self.assertIn("secrets.CLOUDFLARE_BOOTSTRAP_TOKEN", workflow)
        self.assertIn("secrets.CLOUDFLARE_ACCOUNT_ID", workflow)
        self.assertIn('"https://getpatched.dev${path}"', workflow)


if __name__ == "__main__":
    unittest.main()
