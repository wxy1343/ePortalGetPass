#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time    : 2022/3/26 2:24
# @Author  : wxy1343
# @File    : PBEWITHMD5andDES.py
from hashlib import md5

from pyDes import des, CBC

salt = b'\xc7\x73\x21\x8c\x7e\xc8\xee\x99'
iterations = 20
password = '12'


def get_derived_key():
    m = md5()
    m.update(password.encode())
    m.update(salt)
    result = m.digest()
    for i in range(1, iterations):
        m = md5()
        m.update(result)
        result = m.digest()
    return result[:8], result[8:]


def encrypt(text: bytes) -> str:
    key, iv = get_derived_key()
    padding = 8 - len(text) % 8
    text += chr(padding).encode() * padding
    encoder = des(key, CBC, iv)
    encrypted = encoder.encrypt(text)
    return encrypted.hex()


def decrypt(text: str) -> bytes:
    key, iv = get_derived_key()
    encrypted = bytes.fromhex(text)
    encoder = des(key, CBC, iv)
    text = encoder.decrypt(encrypted)
    padding = text[-1]
    text = text[:-padding]
    return text


if __name__ == '__main__':
    print(encrypt(b'123456'))
    print(decrypt(encrypt(b'123456')))
