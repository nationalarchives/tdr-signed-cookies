import time
import json
import base64
import traceback

import jwt
from jwt import PyJWKClient
import boto3
import os
from base64 import b64decode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def thirty_minutes():
    return int(time.time()) + (60 * 30)


def _replace_unsupported_chars(some_str):
    return some_str.replace("+", "-") \
        .replace("=", "_") \
        .replace("/", "~")


def rsa_signer(message, key):
    private_key = serialization.load_pem_private_key(
        key,
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())
    return signature


def generate_policy_cookie(url):
    policy_dict = {
        "Statement": [
            {
                "Resource": url,
                "Condition": {
                    "DateLessThan": {
                        "AWS:EpochTime": thirty_minutes()
                    }
                }
            }
        ]
    }

    policy_json = json.dumps(policy_dict, separators=(",", ":"))

    policy_64 = str(base64.b64encode(policy_json.encode("utf-8")), "utf-8")
    policy_64 = _replace_unsupported_chars(policy_64)
    return policy_json, policy_64


def generate_signature(policy, key):
    sig_bytes = rsa_signer(policy.encode("utf-8"), key)
    sig_64 = _replace_unsupported_chars(str(base64.b64encode(sig_bytes), "utf-8"))
    return sig_64


def decode(env_var_name):
    client = boto3.client("kms")
    decoded = client.decrypt(CiphertextBlob=b64decode(os.environ[env_var_name]),
                             EncryptionContext={"LambdaFunctionName": os.environ["AWS_LAMBDA_FUNCTION_NAME"]})
    return decoded["Plaintext"].decode("utf-8")


def user_id_from_token(token, url):
    jwks_client = PyJWKClient(f"{url}/realms/tdr/protocol/openid-connect/certs")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    options = {"verify_exp": True, "verify_signature": True}
    payload = jwt.decode(token, signing_key.key, audience="tdr", algorithms=["RS256"], options=options)
    return payload["user_id"]


def sign_cookies(event):
    headers = event["headers"]
    token = headers["Authorization"].removeprefix("Bearer ")
    origin = headers["Origin"] if "Origin" in headers else headers["origin"]

    environment = os.environ["ENVIRONMENT"]
    key_pair_id = decode("KEY_PAIR_ID")
    private_key = b64decode(decode("PRIVATE_KEY"))

    subdomain = f"tdr-{environment}.nationalarchives.gov.uk"
    auth_url = os.environ["AUTH_URL"]
    upload_domain = f"upload.{subdomain}"
    frontend_url = f"https://{subdomain}"
    user_id = user_id_from_token(token, auth_url)
    cookies = generate_signed_cookies(f"https://{upload_domain}/{user_id}/*", private_key, key_pair_id)
    return generate_response(cookies, environment, frontend_url, origin)


def generate_response(cookies, environment, frontend_url, origin):
    allowed_origin = origin if environment == "integration" and origin == "http://localhost:9000" else frontend_url
    suffix = "Path=/; Secure; HttpOnly; SameSite=None"
    return {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Credentials": "true"
        },
        "multiValueHeaders": {
            "Set-Cookie": [
                f"CloudFront-Policy={cookies['policy']}; {suffix}",
                f"CloudFront-Key-Pair-Id={cookies['key_pair_id']}; {suffix}",
                f"CloudFront-Signature={cookies['signature']}; {suffix}"
            ]
        },
        "isBase64Encoded": False
    }


def generate_signed_cookies(url, key, key_pair_id):
    policy_json, policy_64 = generate_policy_cookie(url)
    signature = generate_signature(policy_json, key)
    return {
        "policy": policy_64,
        "signature": signature,
        "key_pair_id": key_pair_id
    }


# noinspection PyBroadException
def handler(event, context):
    try:
        return sign_cookies(event)
    except Exception:
        traceback.print_exc()
        return {
            "statusCode": 401
        }
