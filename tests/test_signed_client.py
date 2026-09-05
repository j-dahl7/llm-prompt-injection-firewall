import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock
from botocore.credentials import Credentials

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signed_client', ROOT / 'scripts/invoke-firewall.py')
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class Response(io.BytesIO):
    status = 200


class SignedClientTests(unittest.TestCase):
    endpoint = 'https://abc123def4.execute-api.us-east-1.amazonaws.com/prompt'

    def test_sdk_signs_the_exact_route_with_temporary_credentials_and_bounded_transport(self):
        opener = Mock()
        opener.open.return_value = Response(b'{"status":"allowed"}')
        status, body = client.invoke(self.endpoint, 'abc123def4', 'us-east-1', 'Hello', 'x' * 32,
                                     Credentials('TESTACCESSKEY', 'test-only-secret', 'test-session'), opener)
        self.assertEqual(status, 200)
        self.assertEqual(body, {'status': 'allowed'})
        request = opener.open.call_args.args[0]
        headers = {k.lower(): v for k, v in request.headers.items()}
        self.assertEqual(request.full_url, self.endpoint)
        self.assertIn('/us-east-1/execute-api/aws4_request', headers['authorization'])
        self.assertEqual(headers['x-amz-security-token'], 'test-session')
        self.assertEqual(headers['x-api-key'], 'x' * 32)
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 20)

    def test_foreign_hosts_paths_query_credentials_and_invalid_input_never_reach_transport(self):
        opener = Mock()
        for endpoint in ['http://' + self.endpoint[8:], self.endpoint + '?code=value',
                         self.endpoint.replace('abc123def4', 'foreign123'),
                         self.endpoint.replace('/prompt', '/other'),
                         self.endpoint.replace('https://', 'https://user:password@'),
                         self.endpoint.replace('.amazonaws.com', '.amazonaws.com.attacker.example')]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                client.invoke(endpoint, 'abc123def4', 'us-east-1', 'Hello', 'x' * 32, None, opener)
        with self.assertRaises(ValueError):
            client.invoke(self.endpoint, 'abc123def4', 'us-east-1', 'Hello', 'x' * 32 + '\nInjected: y', None, opener)
        opener.open.assert_not_called()

    def test_redirects_cannot_forward_credentials(self):
        with self.assertRaisesRegex(ValueError, 'redirects are refused'):
            client.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://attacker.example/')

    def test_gateway_requires_iam_and_only_grants_lambda_invocation_for_the_prompt_route(self):
        terraform = (ROOT / 'terraform/main.tf').read_text()
        self.assertIn('authorization_type = "AWS_IAM"', terraform)
        self.assertNotIn('authorization_type = "NONE"', terraform)
        self.assertIn('${aws_apigatewayv2_api.prompt_api.execution_arn}/*/POST/prompt', terraform)
        self.assertNotIn('aws_iam_user', terraform)
        self.assertNotIn('aws_iam_access_key', terraform)


if __name__ == '__main__':
    unittest.main()
