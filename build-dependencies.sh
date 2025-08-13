#!/bin/bash
dnf install -y wget zip
dnf install -y python3.11
python3.11 -m ensurepip --upgrade

mkdir /pip
python3.11 -m pip install --upgrade pip
pip3.11 install --requirement requirements.txt --target /pip
python3.11 -m pip install setuptools_rust
pip3.11 install --platform manylinux2010_x86_64 --implementation cp --only-binary=:all: --upgrade --target /pip cryptography

cd /pip
rm -r *.dist-info
find . -name __pycache__ | xargs rm -r

mv _cffi_backend.cpython-311-x86_64-linux-gnu.so _cffi_backend.so
cd cryptography/hazmat/bindings
mv _openssl.abi3.so _openssl.so

mkdir /lambda
cp -r /pip/* /lambda
cd /lambda
zip -r function.zip *
zip -g function.zip /signed_cookies.py
