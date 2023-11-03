import base64
import json
import math
import os
import time
from unittest.mock import Mock

import jwt
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

current_time = time.time()
mock_time = Mock()
mock_time_return_value = 123456
mock_time.return_value = mock_time_return_value


def get_event(token):
    return {
        "headers": {
            "Authorization": f"Bearer {token}",
            "Origin": "https://localhost:9000"
        }
    }


def get_token_keys():
    token_key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    token_public_numbers = token_key.public_key().public_numbers()
    encoded_token_key = token_key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )

    def to_string(num):
        length = math.ceil(num.bit_length() / 8)
        return base64.b64encode(num.to_bytes(length, byteorder='big')).decode("ascii")

    return {
        "private": encoded_token_key,
        "e": to_string(token_public_numbers.e),
        "n": to_string(token_public_numbers.n)
    }


token_keys = get_token_keys()
token_private_key = token_keys["private"]


def get_token(user_id=None, expiry=None):
    expiry = math.ceil(time.time()) + 3600 if expiry is None else expiry
    base_payload = {"aud": "tdr-fe", "exp": expiry}
    payload = {"user_id": user_id, **base_payload} if user_id is not None else base_payload
    return jwt.encode(payload, token_private_key, algorithm="RS256", headers={"kid": "kid"})


def get_cert_response() -> object:
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "kid",
                "n": token_keys["n"],
                "e": token_keys["e"],
            }
        ]
    }


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


def set_up(kms, httpserver):
    path = "/realms/tdr/protocol/openid-connect/certs"
    httpserver.expect_request(path).respond_with_json(get_cert_response())
    kms_key = kms.create_key(
        Policy='string',
        Description='string',
    )['KeyMetadata']['KeyId']
    os.environ["AUTH_URL"] = httpserver.url_for("/")
    os.environ["ENVIRONMENT"] = "integration"
    os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "test-function-name"
    os.environ["KEY_PAIR_ID"] = encrypt(kms_key, kms, "key-pair-id")
    os.environ["PRIVATE_KEY"] = encrypt(kms_key, kms, private_key())
    os.environ["UPLOAD_DOMAIN"] = "upload.example.com"
    os.environ["FRONTEND_URL"] = "test"
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-2'
    os.environ['COOKIE_EXPIRY_MINUTES'] = '60'


def decode_string(cookie_string):
    replaced_str = cookie_string.replace("-", "+") \
        .replace("_", "=") \
        .replace("~", "/")
    decoded_string = base64.b64decode(replaced_str)
    return json.loads(decoded_string)


def origin_test_values():
    localhost = "http://localhost:9000"
    integration = "https://tdr-integration.nationalarchives.gov.uk"
    staging = "https://tdr-staging.nationalarchives.gov.uk"
    production = "https://tdr.nationalarchives.gov.uk"
    another_domain = "https://another-domain.com"

    return [
        ("integration", localhost, localhost, integration),
        ("integration", integration, integration, integration),
        ("integration", another_domain, integration, integration),
        ("staging", staging, staging, staging),
        ("staging", another_domain, staging, staging),
        ("production", production, production, production),
        ("production", another_domain, production, production)
    ]
