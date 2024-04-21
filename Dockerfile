FROM amazonlinux:2.0.20240412.0
COPY requirements-runtime.txt /requirements.txt
COPY build-dependencies.sh src/signed_cookies.py /
RUN ./build-dependencies.sh
