#!/bin/bash

yum update -y
yum install -y python3-pip python3-devel

mkdir /pip
pip3 install --requirement requirements.txt --target /pip

cd /pip
rm -r *.dist-info *.egg-info
find . -name __pycache__ | xargs rm -r
mv _cffi_backend.cpython-37m-x86_64-linux-gnu.so _cffi_backend.so
cd cryptography/hazmat/bindings
mv _openssl.abi3.so _openssl.so
mv _padding.abi3.so _padding.so

mkdir /lambda
cp -r /pip/* /lambda
cd /lambda
zip -r function.zip *
zip -g function.zip /signed_cookies.py
