"""
Utilidades criptográficas para el proyecto de QR seguro.

Contiene las funciones de más bajo nivel:
    - Cálculo de hash SHA-256.
    - Generación de par de claves Ed25519.
    - Firma y verificación de firmas Ed25519.
    - Cifrado/descifrado simétrico opcional (desafío adicional).

Se apoya en la librería estándar `hashlib` y en `cryptography`,
una librería madura y auditada para primitivas criptográficas en Python.
"""

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet


# ---------------------------------------------------------------------------
# 1. Hashing (SHA-256)
# ---------------------------------------------------------------------------

def sha256_hex(data: str) -> str:
    """Devuelve el hash SHA-256 (en hexadecimal) del texto recibido."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 2. Generación y persistencia de claves Ed25519
# ---------------------------------------------------------------------------

def generar_par_de_claves(directorio: str = "keys") -> tuple[str, str]:
    """
    Genera un par de claves Ed25519 (privada/pública) y las guarda en disco
    en formato PEM dentro de `directorio`.

    Devuelve las rutas (privada, publica).
    """
    Path(directorio).mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    ruta_privada = Path(directorio) / "private_key.pem"
    ruta_publica = Path(directorio) / "public_key.pem"

    ruta_privada.write_bytes(private_bytes)
    ruta_publica.write_bytes(public_bytes)

    return str(ruta_privada), str(ruta_publica)


def cargar_clave_privada(ruta: str) -> Ed25519PrivateKey:
    with open(ruta, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def cargar_clave_publica(ruta: str) -> Ed25519PublicKey:
    with open(ruta, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ---------------------------------------------------------------------------
# 3. Firma digital Ed25519
# ---------------------------------------------------------------------------

def firmar(mensaje: str, private_key: Ed25519PrivateKey) -> str:
    """
    Firma `mensaje` (normalmente el hash SHA-256 del contenido) con la
    clave privada Ed25519 y devuelve la firma codificada en base64,
    lista para incluir en el QR.
    """
    firma_bytes = private_key.sign(mensaje.encode("utf-8"))
    return base64.b64encode(firma_bytes).decode("ascii")


def verificar_firma(mensaje: str, firma_b64: str, public_key: Ed25519PublicKey) -> bool:
    """
    Verifica que `firma_b64` sea una firma Ed25519 válida de `mensaje`
    generada con la clave privada correspondiente a `public_key`.

    Devuelve True si es válida, False si no lo es (firma corrupta,
    clave incorrecta o mensaje alterado).
    """
    try:
        firma_bytes = base64.b64decode(firma_b64)
        public_key.verify(firma_bytes, mensaje.encode("utf-8"))
        return True
    except Exception:
        # cryptography lanza InvalidSignature si no coincide; cualquier
        # otro problema (base64 corrupto, etc.) también se trata como
        # "firma inválida" para el usuario final.
        return False


# ---------------------------------------------------------------------------
# 4. Cifrado simétrico opcional (desafío adicional)
# ---------------------------------------------------------------------------
# Permite que el contenido dentro del QR no sea legible directamente al
# escanearlo: solo quien posea la clave simétrica (Fernet, basada en
# AES-128 + HMAC) puede descifrarlo antes de comprobar hash y firma.

def generar_clave_simetrica() -> bytes:
    return Fernet.generate_key()


def cifrar_contenido(contenido: str, clave: bytes) -> str:
    f = Fernet(clave)
    token = f.encrypt(contenido.encode("utf-8"))
    return token.decode("ascii")


def descifrar_contenido(token: str, clave: bytes) -> str:
    f = Fernet(clave)
    return f.decrypt(token.encode("ascii")).decode("utf-8")
