#!/usr/bin/env python3
import os
import base64
from lxml import etree
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

nick = input("Введите ник: ").strip()
os.makedirs("keys", exist_ok=True)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

public_key = private_key.public_key()

priv_pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)

pub_pem = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

def write_key(path, data):
    root = etree.Element("key")
    pub = etree.SubElement(root, "public")
    pub.text = base64.b64encode(data).decode()
    with open(path, "wb") as f:
        f.write(etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="utf-8"))

write_key(f"keys/{nick}_private.xml", priv_pem)
write_key(f"keys/{nick}_public.xml", pub_pem)

print("OK")
