import uuid
from collections import ChainMap
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws
from pytest_httpserver import HTTPServer
from utils.utils import *

from src import signed_cookies


@pytest.fixture(scope='function')
def kms():
    with mock_aws():
        yield boto3.client('kms', region_name='eu-west-2')


def test_unauthorised_for_invalid_token(kms, httpserver: HTTPServer):
    set_up(kms, httpserver)
    event = get_event("invalid_token")
    response = signed_cookies.handler(event, None)
    assert response["statusCode"] == 401


def test_ok_with_valid_token(kms, httpserver: HTTPServer):
    set_up(kms, httpserver)
    token = get_token(user_id=str(uuid.uuid4()))
    event = get_event(token)
    response = signed_cookies.handler(event, None)
    assert response["statusCode"] == 200


def test_unauthorised_with_expired_token(kms, httpserver: HTTPServer):
    set_up(kms, httpserver)
    token = get_token(user_id=str(uuid.uuid4()), expiry=math.ceil(time.time()) - 3600)
    event = get_event(token)
    response = signed_cookies.handler(event, None)
    assert response["statusCode"] == 401


def test_unauthorised_with_missing_user_id(kms, httpserver: HTTPServer):
    set_up(kms, httpserver)
    token = get_token()
    event = get_event(token)
    response = signed_cookies.handler(event, None)
    assert response["statusCode"] == 401


def test_ok_with_lower_case_origin(kms, httpserver: HTTPServer):
    set_up(kms, httpserver)
    token = get_token(user_id=str(uuid.uuid4()))
    event = get_event(token)
    response = signed_cookies.handler(event, None)
    assert response["statusCode"] == 200


@pytest.mark.parametrize("environment, origin, allowed_origin, frontend_url", origin_test_values())
def test_access_control_origin(environment, origin, allowed_origin, frontend_url, kms, httpserver: HTTPServer):
    set_up(kms, httpserver)
    cookies = {"signature": "test_signature", "policy": "test_policy", "key_pair_id": "test_key_pair_id"}
    response = signed_cookies.generate_response(cookies, environment, frontend_url, origin)
    assert allowed_origin == response["headers"]["Access-Control-Allow-Origin"]


@patch('time.time', mock_time)
def test_create_cookie_policy(kms, httpserver: HTTPServer):
    expected_time = mock_time_return_value + (60 * 60)
    token_expiry_time = math.ceil(current_time) + 3600
    user_id = str(uuid.uuid4())
    url = f"https://upload.example.com/{user_id}/*"
    set_up(kms, httpserver)
    token = get_token(user_id=user_id, expiry=token_expiry_time)
    event = get_event(token)
    response = signed_cookies.handler(event, None)

    def cookie_obj(cookie_string):
        cookie_arr = cookie_string.split("=")
        return {cookie_arr[0]: cookie_arr[1].split(";")[0]}

    cookies = response["multiValueHeaders"]["Set-Cookie"]
    cookie_object = dict(ChainMap(*[cookie_obj(cookie) for cookie in cookies]))
    policy = decode_string(cookie_object["CloudFront-Policy"])
    assert policy["Statement"][0]["Resource"] == url
    assert policy["Statement"][0]["Condition"]["DateLessThan"]["AWS:EpochTime"] == expected_time
