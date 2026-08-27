"""
Desafío adicional: QR seguro + cifrado del contenido.

Además de firmar el contenido (integridad + autenticidad), esta variante
cifra el campo `content` con una clave simétrica (Fernet = AES-128-CBC +
HMAC-SHA256) antes de meterlo en el QR. De esta forma:

    - Cualquiera puede ESCANEAR el QR, pero solo verá un texto cifrado
      ilegible (confidencialidad).
    - Solo quien tenga la clave simétrica puede DESCIFRAR el contenido.
    - La firma Ed25519 se calcula sobre el hash del texto cifrado, por lo
      que también se puede verificar integridad/autenticidad sin
      necesidad de descifrar primero.

Esto ilustra la diferencia entre AUTENTICIDAD (firma) y
CONFIDENCIALIDAD (cifrado): son propiedades independientes y este
ejemplo aplica ambas a la vez.
"""

import argparse
import json
from pathlib import Path

from crypto_utils import (
    sha256_hex,
    firmar,
    verificar_firma,
    cargar_clave_privada,
    cargar_clave_publica,
    generar_clave_simetrica,
    cifrar_contenido,
    descifrar_contenido,
)
from generar_qr_seguro import generar_qr_desde_payload
from verificar_qr import leer_qr_desde_imagen


def generar_qr_cifrado(contenido: str, ruta_clave_privada: str, ruta_salida: str, clave_simetrica: bytes = None):
    """Cifra `contenido`, lo firma y genera el QR. Devuelve (payload, clave_simetrica)."""
    if clave_simetrica is None:
        clave_simetrica = generar_clave_simetrica()

    contenido_cifrado = cifrar_contenido(contenido, clave_simetrica)

    private_key = cargar_clave_privada(ruta_clave_privada)
    hash_cifrado = sha256_hex(contenido_cifrado)
    firma = firmar(hash_cifrado, private_key)

    payload = {
        "content": contenido_cifrado,  # ilegible sin la clave simétrica
        "hash": hash_cifrado,
        "sig": firma,
        "enc": True,
    }
    generar_qr_desde_payload(payload, ruta_salida)

    print(f"[+] Contenido original:  {contenido}")
    print(f"[+] Contenido cifrado:   {contenido_cifrado}")
    print(f"[+] QR cifrado y firmado guardado en: {ruta_salida}")

    return payload, clave_simetrica


def verificar_y_descifrar_qr(ruta_imagen: str, ruta_clave_publica: str, clave_simetrica: bytes):
    texto_qr = leer_qr_desde_imagen(ruta_imagen)
    payload = json.loads(texto_qr)

    contenido_cifrado = payload["content"]
    hash_declarado = payload["hash"]
    firma = payload["sig"]

    # 1) Integridad sobre el texto cifrado.
    if sha256_hex(contenido_cifrado) != hash_declarado:
        return False, "Hash inválido: el contenido cifrado fue alterado.", None

    # 2) Autenticidad de la firma.
    public_key = cargar_clave_publica(ruta_clave_publica)
    if not verificar_firma(hash_declarado, firma, public_key):
        return False, "Firma inválida: no fue firmado por la clave privada esperada.", None

    # 3) Solo si lo anterior es válido, se intenta descifrar.
    try:
        contenido_original = descifrar_contenido(contenido_cifrado, clave_simetrica)
    except Exception:
        return False, "No se pudo descifrar el contenido con la clave simétrica provista.", None

    return True, "Contenido auténtico y descifrado correctamente.", contenido_original


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo de QR firmado + cifrado (desafío adicional).")
    sub = parser.add_subparsers(dest="accion", required=True)

    p_gen = sub.add_parser("generar")
    p_gen.add_argument("contenido")
    p_gen.add_argument("--clave-privada", default="keys/private_key.pem")
    p_gen.add_argument("--salida", default="output/qr_cifrado.png")
    p_gen.add_argument("--clave-simetrica-out", default="keys/symmetric_key.bin")

    p_ver = sub.add_parser("verificar")
    p_ver.add_argument("imagen")
    p_ver.add_argument("--clave-publica", default="keys/public_key.pem")
    p_ver.add_argument("--clave-simetrica-in", default="keys/symmetric_key.bin")

    args = parser.parse_args()

    if args.accion == "generar":
        payload, clave = generar_qr_cifrado(args.contenido, args.clave_privada, args.salida)
        Path(args.clave_simetrica_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.clave_simetrica_out).write_bytes(clave)
        print(f"[+] Clave simétrica guardada en: {args.clave_simetrica_out}")

    elif args.accion == "verificar":
        clave = Path(args.clave_simetrica_in).read_bytes()
        ok, motivo, contenido = verificar_y_descifrar_qr(args.imagen, args.clave_publica, clave)
        estado = "✅ AUTÉNTICO" if ok else "❌ ALTERADO / NO AUTÉNTICO"
        print(f"{estado} — {motivo}")
        if ok:
            print(f"[+] Contenido descifrado: {contenido}")
