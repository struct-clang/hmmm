#!/usr/bin/env python3
import os
import base64
import argparse
from lxml import etree
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

p = argparse.ArgumentParser()
p.add_argument("--keys", required=True)
p.add_argument("--text", required=True)
p.add_argument("--for", dest="to", required=True)
args = p.parse_args()

def load_public(path):
    root = etree.parse(path).getroot()
    return serialization.load_pem_public_key(
        base64.b64decode(root.findtext("public").strip())
    )

pub_path = os.path.join(args.keys, f"{args.to}_public.xml")
pub = load_public(pub_path)

with open(args.text, "rb") as f:
    plaintext = f.read()

aes_key = os.urandom(32)
nonce = os.urandom(12)

aes = AESGCM(aes_key)
ciphertext = aes.encrypt(nonce, plaintext, None)

enc_key = pub.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

blob = base64.b64encode(enc_key + nonce + ciphertext).decode()

root = etree.Element("message")

body = etree.SubElement(root, "body")
body.text = blob

recv = etree.SubElement(root, "reciver")
recv.text = args.to

out_name = f"message_{args.to}.xml"
with open(out_name, "wb") as f:
    f.write(etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="utf-8"))

print(out_name)
