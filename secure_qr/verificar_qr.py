"""
Lectura y verificación de un código QR seguro.

Pasos:
    1. Decodifica la imagen QR y obtiene el texto (JSON) almacenado.
       Esta parte es pura "lectura" de QR: usa Reed-Solomon para
       recuperar los datos aunque la imagen esté parcialmente dañada,
       pero NO indica si el contenido es confiable.
    2. Recalcula el SHA-256 del campo `content` y lo compara con el
       campo `hash` -> comprueba INTEGRIDAD.
    3. Verifica la firma Ed25519 del campo `hash` con la clave pública
       -> comprueba AUTENTICIDAD (que fue firmado por el dueño de la
       clave privada, y no alterado después).
    4. Informa AUTÉNTICO o ALTERADO / NO AUTÉNTICO.
"""

import argparse
import json

import cv2

from crypto_utils import sha256_hex, verificar_firma, cargar_clave_publica


class ResultadoVerificacion:
    def __init__(self, es_autentico, motivo, payload):
        self.es_autentico = es_autentico
        self.motivo = motivo
        self.payload = payload

    def __str__(self):
        estado = "✅ AUTÉNTICO" if self.es_autentico else "❌ ALTERADO / NO AUTÉNTICO"
        return f"{estado} — {self.motivo}"


def leer_qr_desde_imagen(ruta_imagen: str) -> str:
    """Decodifica un QR desde un archivo de imagen usando OpenCV."""
    imagen = cv2.imread(ruta_imagen)
    if imagen is None:
        raise FileNotFoundError(f"No se pudo abrir la imagen: {ruta_imagen}")

    detector = cv2.QRCodeDetector()
    texto, _puntos, _rectificado = detector.detectAndDecode(imagen)

    if not texto:
        raise ValueError("No se detectó ningún QR legible en la imagen.")

    return texto


def verificar_payload(payload: dict, ruta_clave_publica: str) -> ResultadoVerificacion:
    """
    Aplica las comprobaciones de integridad (hash) y autenticidad (firma)
    sobre un payload ya decodificado.
    """
    contenido = payload.get("content")
    hash_declarado = payload.get("hash")
    firma = payload.get("sig")

    if contenido is None or hash_declarado is None or firma is None:
        return ResultadoVerificacion(False, "El QR no tiene el formato esperado.", payload)

    # 1) Integridad: el hash recalculado debe coincidir con el declarado.
    hash_real = sha256_hex(contenido)
    if hash_real != hash_declarado:
        return ResultadoVerificacion(
            False,
            "El contenido no coincide con su hash SHA-256 "
            "(el texto fue modificado después de generarse el QR).",
            payload,
        )

    # 2) Autenticidad: la firma Ed25519 debe ser válida para ese hash.
    public_key = cargar_clave_publica(ruta_clave_publica)
    if not verificar_firma(hash_declarado, firma, public_key):
        return ResultadoVerificacion(
            False,
            "La firma digital Ed25519 no es válida para este contenido "
            "(no fue firmado con la clave privada esperada, o el hash fue alterado).",
            payload,
        )

    return ResultadoVerificacion(True, "El contenido coincide con su hash y la firma es válida.", payload)


def verificar_qr_imagen(ruta_imagen: str, ruta_clave_publica: str) -> ResultadoVerificacion:
    texto_qr = leer_qr_desde_imagen(ruta_imagen)
    try:
        payload = json.loads(texto_qr)
    except json.JSONDecodeError:
        return ResultadoVerificacion(False, "El QR no contiene un payload JSON válido.", {"raw": texto_qr})

    return verificar_payload(payload, ruta_clave_publica)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verifica un QR firmado digitalmente (Ed25519).")
    parser.add_argument("imagen", help="Ruta a la imagen PNG del QR a verificar.")
    parser.add_argument("--clave-publica", default="keys/public_key.pem")
    args = parser.parse_args()

    resultado = verificar_qr_imagen(args.imagen, args.clave_publica)

    print(f"[+] Contenido leído: {resultado.payload.get('content')}")
    print(str(resultado))
