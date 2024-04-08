# TDR Signed Cookies

This lambda provides the response when the front end makes a request to upload.tdr.nationalarchives.gov.uk. The request goes:

Route53 -> Cloudfront -> API Gateway -> Lambda

The lambda carries out the following steps.

1. Decodes the incoming json from API gateway and retrieves the access token.
2. Validates the token with the jwt library. If this has expired or is otherwise invalid, the lambda returns 401.
3. Creates the signed cookies using the private key from the environment variables.
4. Creates the response with the correct `Set-Cookies` headers set
5. Sets the `Access-Control-Allow-Origin` header based on the environment and origin header.
6. Returns a 200 response.

## Building the lambda
The lambda code uses the cryptography Python library which needs some OS level libraries which are not available in the AWS Lambda runtime.
Because of this, the lambda has to be built inside a Docker container running Amazon Linux. 

The docker image is built from `Dockerfile` in the root of the project and the function is built using the `build-dependencies.sh` script.

This is built using GitHub actions in the `.github/workflows/build.yml` file.

## Running Locally
There is a `signed_cookies_runner` file with some example json. To run this, you will need to set the environment variables to the same values as the integration lambda. You can get these by running this command with integration credentials

`aws lambda get-function --function-name tdr-sign-cookies-intg --query  'Configuration.Environment.Variables'`  

You will also need to set an environment variable called `AWS_LAMBDA_FUNCTION_NAME` with the value `tdr-sign-cookies-intg` This is set automatically by the lambda but has to be set manually here.

You will need to make sure that you have integration credentials set before running `LambdaRunner`, either by setting them in `~/.aws/credentials` or by setting environment variables in the run configuration. You will need permissions to access KMS keys for this to work.

The expected response will be `{"statusCode":401,"headers":null,"multiValueHeaders":null,"isBase64Encoded":false}` because the token has expired. If you want a 200 response, you will need to replace the existing token with an active token.

## Running the tests locally.
You can run the tests from your terminal using a Python virtual environment.
```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python -m pytest
```

You can also run them in PyCharm or IntelliJ by right clicking on the `test` directory and clicking `Debug 'pytest in test'`
