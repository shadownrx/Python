"""
Generación de un código QR "seguro".

El QR no contiene únicamente la URL/mensaje, sino un paquete JSON con:
    - content : el mensaje u URL original.
    - hash    : SHA-256 del contenido (integridad).
    - sig     : firma Ed25519 del hash, en base64 (autenticidad).

Ese paquete es lo que efectivamente se codifica dentro del código QR.
Cualquier lector de QR estándar puede leer el texto, pero solo un
verificador que conozca la clave pública correspondiente puede
confirmar que el contenido es auténtico.
"""

import argparse
import json
from pathlib import Path

import qrcode

from crypto_utils import sha256_hex, firmar, cargar_clave_privada


def construir_payload(contenido: str, private_key) -> dict:
    """Arma el diccionario {content, hash, sig} para un contenido dado."""
    hash_contenido = sha256_hex(contenido)
    firma = firmar(hash_contenido, private_key)
    return {
        "content": contenido,
        "hash": hash_contenido,
        "sig": firma,
    }


def generar_qr_desde_payload(payload: dict, ruta_salida: str) -> str:
    """Codifica el payload como JSON compacto dentro de una imagen QR."""
    texto_qr = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    qr = qrcode.QRCode(
        version=None,  # se ajusta automáticamente al tamaño del contenido
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(texto_qr)
    qr.make(fit=True)

    imagen = qr.make_image(fill_color="black", back_color="white")

    Path(ruta_salida).parent.mkdir(parents=True, exist_ok=True)
    imagen.save(ruta_salida)
    return texto_qr


def generar_qr_seguro(contenido: str, ruta_clave_privada: str, ruta_salida: str) -> dict:
    """
    Flujo completo: firma el contenido con la clave privada indicada y
    genera la imagen QR resultante en `ruta_salida`.
    Devuelve el payload generado (útil para tests/demo).
    """
    private_key = cargar_clave_privada(ruta_clave_privada)
    payload = construir_payload(contenido, private_key)
    texto_qr = generar_qr_desde_payload(payload, ruta_salida)

    print(f"[+] Contenido:      {contenido}")
    print(f"[+] SHA-256:        {payload['hash']}")
    print(f"[+] Firma Ed25519:  {payload['sig'][:32]}...")
    print(f"[+] QR generado en: {ruta_salida}")
    print(f"[+] Bytes codificados en el QR ({len(texto_qr)} caracteres):")
    print(f"    {texto_qr}")

    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Genera un QR firmado digitalmente (Ed25519).")
    parser.add_argument("contenido", help="Mensaje o URL a codificar, p. ej. https://sitio-oficial.com")
    parser.add_argument("--clave-privada", default="keys/private_key.pem")
    parser.add_argument("--salida", default="output/qr_original.png")
    args = parser.parse_args()

    generar_qr_seguro(args.contenido, args.clave_privada, args.salida)
