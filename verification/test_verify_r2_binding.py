import importlib.util
import io
import os
from pathlib import Path
import unittest
import urllib.error
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("verify_r2_binding", ROOT / "scripts/verify-r2-binding.py")
VERIFY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(VERIFY)


class VerifyR2BindingClientTests(unittest.TestCase):
    def test_identity_is_limited_to_the_manual_main_workflow(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "getpatched/platform",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": VERIFY.WORKFLOW_REF,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/example",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "temporary-test-token",
        }
        with patch.dict(os.environ, environment, clear=True):
            VERIFY.validate_identity()
            for name, value in (
                ("GITHUB_EVENT_NAME", "push"),
                ("GITHUB_REPOSITORY", "someone-else/platform"),
                ("GITHUB_REF", "refs/heads/feature"),
                ("GITHUB_WORKFLOW_REF", "getpatched/platform/.github/workflows/package-verification.yml@refs/heads/main"),
                ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.invalid/token"),
            ):
                with self.subTest(name=name), patch.dict(os.environ, {name: value}):
                    with self.assertRaises(RuntimeError):
                        VERIFY.validate_identity()

    def test_request_uses_no_redirect_handler_and_returns_oidc_value(self):
        environment = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/request?existing=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "temporary-test-token",
        }
        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return io.BytesIO(b'{"value":"signed-test-oidc"}')

        opener = Opener()
        with patch.dict(os.environ, environment, clear=True), patch.object(VERIFY.urllib.request, "build_opener", return_value=opener) as build_opener:
            result = VERIFY.request_token()
        self.assertEqual(result, "signed-test-oidc")
        self.assertEqual(opener.timeout, 20)
        self.assertIn("audience=getpatched-release-gateway", opener.request.full_url)
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer temporary-test-token")
        self.assertTrue(any(isinstance(handler, VERIFY.NoRedirect) for handler in build_opener.call_args.args))

    def test_endpoint_call_does_not_accept_redirect_or_incomplete_report(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "getpatched/platform",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": VERIFY.WORKFLOW_REF,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/example",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "temporary-test-token",
        }
        class Opener:
            def __init__(self, body):
                self.body = body
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                response = io.BytesIO(self.body)
                response.status = 200
                return response

        successful = Opener(b'{"ok":true,"operation":"write-read-delete","cleaned":true,"bytes":64,"sha256":"' + b"a" * 64 + b'","run_id":7}')
        with patch.dict(os.environ, environment, clear=True), patch.object(VERIFY, "request_token", return_value="signed-test-oidc"), \
                patch.object(VERIFY.urllib.request, "build_opener", return_value=successful):
            report = VERIFY.verify_remote_binding()
        self.assertEqual(report["run_id"], 7)
        self.assertEqual(successful.request.full_url, VERIFY.ENDPOINT)
        self.assertEqual(successful.request.method, "POST")
        self.assertEqual(successful.request.get_header("Authorization"), "Bearer signed-test-oidc")

        incomplete = Opener(b'{"ok":true,"operation":"write-read-delete","cleaned":false,"bytes":64,"sha256":"' + b"a" * 64 + b'","run_id":7}')
        with patch.dict(os.environ, environment, clear=True), patch.object(VERIFY, "request_token", return_value="signed-test-oidc"), \
                patch.object(VERIFY.urllib.request, "build_opener", return_value=incomplete):
            with self.assertRaisesRegex(RuntimeError, "incomplete or unsuccessful"):
                VERIFY.verify_remote_binding()

    def test_failed_remote_cleanup_surfaces_only_the_scoped_diagnostic_key(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "getpatched/platform",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": VERIFY.WORKFLOW_REF,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/example",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "temporary-test-token",
        }
        object_key = "diagnostics/r2-self-test/7-1-test-nonce.bin"
        body = ('{"error":"R2 storage self-test failed","stage":"cleanup","cleaned":false,"object_key":"' + object_key + '"}').encode()
        def raise_http_error(*_args, **_kwargs):
            raise urllib.error.HTTPError(VERIFY.ENDPOINT, 502, "Bad Gateway", {}, io.BytesIO(body))

        with patch.dict(os.environ, environment, clear=True), patch.object(VERIFY, "request_token", return_value="signed-test-oidc"), \
                patch.object(VERIFY.urllib.request, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = raise_http_error
            with self.assertRaisesRegex(RuntimeError, object_key):
                VERIFY.verify_remote_binding()

    def test_http_error_reports_bounded_json_error_message(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "getpatched/platform",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": VERIFY.WORKFLOW_REF,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/example",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "temporary-test-token",
        }
        body = b'{"error":"edge policy denied request","detail":"must not be logged"}'
        def raise_http_error(*_args, **_kwargs):
            raise urllib.error.HTTPError(VERIFY.ENDPOINT, 403, "Forbidden", {}, io.BytesIO(body))

        with patch.dict(os.environ, environment, clear=True), patch.object(VERIFY, "request_token", return_value="signed-test-oidc"), \
                patch.object(VERIFY.urllib.request, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = raise_http_error
            with self.assertRaisesRegex(RuntimeError, "HTTP 403: edge policy denied request") as raised:
                VERIFY.verify_remote_binding()
        self.assertNotIn("must not be logged", str(raised.exception))

    def test_malformed_gateway_error_preserves_http_status(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "getpatched/platform",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": VERIFY.WORKFLOW_REF,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/example",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "temporary-test-token",
        }
        def raise_http_error(*_args, **_kwargs):
            raise urllib.error.HTTPError(VERIFY.ENDPOINT, 502, "Bad Gateway", {}, io.BytesIO(b'["unexpected"]'))

        with patch.dict(os.environ, environment, clear=True), patch.object(VERIFY, "request_token", return_value="signed-test-oidc"), \
                patch.object(VERIFY.urllib.request, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = raise_http_error
            with self.assertRaisesRegex(RuntimeError, "HTTP 502$"):
                VERIFY.verify_remote_binding()


if __name__ == "__main__":
    unittest.main()
