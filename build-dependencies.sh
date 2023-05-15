#!/bin/bash
dnf install -y wget zip
dnf install -y python3.9
python3.9 -m ensurepip --upgrade

mkdir /pip
pip3.9 install --requirement requirements.txt --target /pip

cd /pip
rm -r *.dist-info
find . -name __pycache__ | xargs rm -r
mv  _cffi_backend.cpython-38-x86_64-linux-gnu.so _cffi_backend.so
cd cryptography/hazmat/bindings
mv _openssl.abi3.so _openssl.so

mkdir /lambda
cp -r /pip/* /lambda
cd /lambda
zip -r function.zip *
zip -g function.zip /signed_cookies.py
