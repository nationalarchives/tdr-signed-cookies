import signed_cookies

# This is a demo token from jwt.io. You will need to replace this with a valid integration token from the tdr-fe client.
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" \
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
event = {
  "headers": {
    "Authorization": f"Bearer {token}",
    "origin": "http://localhost:9000"
  }
}

signed_cookies.handler(event, None)
