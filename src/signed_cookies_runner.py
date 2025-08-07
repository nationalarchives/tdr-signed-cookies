import signed_cookies

# This is a demo token from jwt.io. You will need to replace this with a valid integration token from the tdr-fe client.
# Open developer tools in your browser, go to the Network tab, and find the request to the tdr-fe client.
# Start a file upload in the tdr-fe client
# Look for the cookies request. Headers -> Authorization bearer and copy the token value.
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" \
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
event = {
  "headers": {
    "Authorization": f"Bearer {token}",
    "origin": "http://localhost:9000"
  }
}

print(signed_cookies.handler(event, None))
