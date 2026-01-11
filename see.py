#!/usr/bin/env python3
import os
import base64
import argparse
from lxml import etree
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

p = argparse.ArgumentParser()
p.add_argument("--encrypted", required=True)
p.add_argument("--keys", required=True)
args = p.parse_args()

root = etree.parse(args.encrypted).getroot()
blob = base64.b64decode(root.findtext("body").strip())

enc_key = blob[:512]
nonce = blob[512:524]
ciphertext = blob[524:]

def try_decrypt(priv_key):
    aes_key = priv_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes = AESGCM(aes_key)
    return aes.decrypt(nonce, ciphertext, None)

for file in os.listdir(args.keys):
    if not file.endswith("_private.xml"):
        continue

    path = os.path.join(args.keys, file)
    try:
        root = etree.parse(path).getroot()
        priv = serialization.load_pem_private_key(
            base64.b64decode(root.findtext("public").strip()),
            password=None
        )
        plaintext = try_decrypt(priv)
        try:
            print(plaintext.decode())
        except:
            import sys
            sys.stdout.buffer.write(plaintext)
        break
    except Exception:
        continue
else:
    print("Не удалось расшифровать сообщение ни одним ключом")
