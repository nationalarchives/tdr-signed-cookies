from src import sign_cookies
from unittest.mock import MagicMock
from unittest import TestCase
from moto import mock_kms
import boto3
import json
import os
import base64
import unittest
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

sign_cookies.thirty_minutes = MagicMock(return_value=123456)
token = "test"


def encrypt(key, kms, value):
    return base64.b64encode(kms.encrypt(
        KeyId=key,
        Plaintext=bytearray(value, 'utf-8'),
        EncryptionContext={
            'LambdaFunctionName': 'test-function-name'
        }
    )['CiphertextBlob']).decode('utf-8')


def private_key():
    rsa_key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    return base64.encodebytes(rsa_key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )).decode("utf-8")


def origin_test_data(environment, origin, allowed_origin, frontend_url):
    return {"environment": environment,
            "origin": origin,
            "allowed_origin": allowed_origin,
            "frontend_url": frontend_url},


class TestStringMethods(TestCase):
    mock_kms = mock_kms()

    def setUp(self):
        self.mock_kms.start()
        kms = boto3.client("kms")
        kms_key = kms.create_key(
            Policy='string',
            Description='string',
        )['KeyMetadata']['KeyId']
        os.environ["ENVIRONMENT"] = encrypt(kms_key, kms, "integration")
        os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "test-function-name"
        os.environ["KEY_PAIR_ID"] = encrypt(kms_key, kms, "key-pair-id")
        os.environ["PRIVATE_KEY"] = encrypt(kms_key, kms, private_key())
        os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
        os.environ['AWS_SECURITY_TOKEN'] = 'testing'
        os.environ['AWS_SESSION_TOKEN'] = 'testing'
        os.environ['AWS_REGION'] = 'eu-west-2'

    def test_unauthorised_for_invalid_token(self):
        event = {
            "headers": {
                "Authorization": "Bearer test",
                "Origin": "https://localhost:9000"
            }
        }
        sign_cookies.user_id_from_token = MagicMock(side_effect=Exception())
        response = sign_cookies.handler(event, None)
        self.assertEqual(response["statusCode"], 401)

    def test_ok_with_valid_token(self):
        event = {
            "headers": {
                "Authorization": "Bearer test",
                "Origin": "https://localhost:9000"
            }
        }
        sign_cookies.user_id_from_token = MagicMock(return_value="c49940c1-2d77-4a41-9c37-6e4fb35f8a28")
        response = sign_cookies.handler(event, None)
        self.assertEqual(response["statusCode"], 200)

    def test_ok_with_lower_case_origin(self):
        event = {
            "headers": {
                "Authorization": "Bearer test",
                "origin": "https://localhost:9000"
            }
        }
        sign_cookies.user_id_from_token = MagicMock(return_value="c49940c1-2d77-4a41-9c37-6e4fb35f8a28")
        response = sign_cookies.handler(event, None)
        self.assertEqual(response["statusCode"], 200)

    def test_access_control_origin(self):
        localhost = "http://localhost:9000"
        integration = "https://tdr-integration.nationalarchives.gov.uk"
        staging = "https://tdr-staging.nationalarchives.gov.uk"
        production = "https://tdr.nationalarchives.gov.uk"
        another_domain = "https://another-domain.com"
        for data in (
                origin_test_data("integration", localhost, localhost, integration),
                origin_test_data("integration", integration, integration, integration),
                origin_test_data("integration", another_domain, integration, integration),
                origin_test_data("staging", staging, staging, staging),
                origin_test_data("staging", another_domain, staging, staging),
                origin_test_data("production", production, production, production),
                origin_test_data("production", another_domain, production, production)
        ):
            with self.subTest(data=data):
                cookies = {"signature": "test_signature", "policy": "test_policy", "key_pair_id": "test_key_pair_id"}
                response = sign_cookies.generate_response(cookies, data[0]["environment"], data[0]["frontend_url"],
                                                          data[0]["origin"])
                self.assertEqual(data[0]["allowed_origin"], response["headers"]["Access-Control-Allow-Origin"])

    def test_create_cookie_policy(self):
        url = "https://example.com"
        cookie_policy, cookie_policy_b64 = sign_cookies.generate_policy_cookie(url)
        policy = json.loads(cookie_policy)
        self.assertEqual(policy["Statement"][0]["Resource"], url)
        self.assertEqual(policy["Statement"][0]["Condition"]["DateLessThan"]["AWS:EpochTime"], 123456)


if __name__ == '__main__':
    unittest.main()
