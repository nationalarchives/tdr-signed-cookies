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


def cookie_expiry():
    expiry_mins = os.environ["COOKIE_EXPIRY_MINUTES"]
    return int(time.time()) + (60 * int(expiry_mins))


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
                        "AWS:EpochTime": cookie_expiry()
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


def sharepoint_domain(origin):
    return "sharepoint.com" in origin


def get_audience(origin):
    if sharepoint_domain(origin):
        return "tdr-sharepoint"
    else:
        return "tdr-fe"


def get_allowed_origin(origin, environment, frontend_url):
    if sharepoint_domain(origin) or (environment == "integration" and origin == "http://localhost:9000"):
        return origin
    else:
        return frontend_url


def user_id_from_token(token, url, origin):
    audience = get_audience(origin)
    jwks_client = PyJWKClient(f"{url}/realms/tdr/protocol/openid-connect/certs")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    options = {"verify_exp": True, "verify_signature": True}
    payload = jwt.decode(token, signing_key.key, audience=audience, algorithms=["RS256"], options=options)
    return payload["user_id"]


def sign_cookies(event):
    headers = event["headers"]
    token = headers["Authorization"].split(" ")[1]
    origin = headers["Origin"] if "Origin" in headers else headers["origin"]

    environment = os.environ["ENVIRONMENT"]
    key_pair_id = decode("KEY_PAIR_ID")
    private_key = b64decode(decode("PRIVATE_KEY"))

    auth_url = os.environ["AUTH_URL"]
    upload_domain = os.environ["UPLOAD_DOMAIN"]
    frontend_url = os.environ["FRONTEND_URL"]
    user_id = user_id_from_token(token, auth_url, origin)
    cookies = generate_signed_cookies(f"https://{upload_domain}/{user_id}/*", private_key, key_pair_id)
    return generate_response(cookies, environment, frontend_url, origin)


def generate_response(cookies, environment, frontend_url, origin):
    allowed_origin = get_allowed_origin(origin, environment, frontend_url)
    suffix = "Path=/; Secure; HttpOnly; SameSite=None"
    return {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Credentials": "true",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
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
