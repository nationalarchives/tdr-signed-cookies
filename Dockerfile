FROM amazonlinux:2023
COPY requirements-runtime.txt /requirements.txt
COPY build-dependencies.sh src/signed_cookies.py /
RUN ./build-dependencies.sh
