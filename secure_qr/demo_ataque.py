"""
Demostración de seguridad end-to-end.

1. Genera un par de claves Ed25519 (si no existen).
2. Genera un QR "legítimo" para https://sitio-oficial.com, firmado.
3. Verifica ese QR legítimo -> debe dar AUTÉNTICO.
4. Simula un atacante que modifica el contenido del payload
   (cambia la URL por https://sitio-falso.com) SIN tener la clave
   privada, y genera un QR "modificado" con ese payload alterado.
5. Verifica el QR modificado -> debe dar ALTERADO / NO AUTÉNTICO,
   porque el hash y la firma ya no corresponden al nuevo contenido.

Esto demuestra que la corrección de errores Reed-Solomon del QR no
tiene nada que ver con esta detección: el QR modificado se lee
perfectamente bien (no está dañado), pero su firma no es válida.
"""

import json
import os

from crypto_utils import generar_par_de_claves
from generar_qr_seguro import generar_qr_seguro, generar_qr_desde_payload
from verificar_qr import verificar_qr_imagen, verificar_payload

CLAVE_PRIVADA = "keys/private_key.pem"
CLAVE_PUBLICA = "keys/public_key.pem"

URL_ORIGINAL = "https://sitio-oficial.com"
URL_FALSA = "https://sitio-falso.com"

QR_ORIGINAL = "output/qr_original.png"
QR_MODIFICADO = "output/qr_modificado.png"


def asegurar_claves():
    if not (os.path.exists(CLAVE_PRIVADA) and os.path.exists(CLAVE_PUBLICA)):
        print("[*] No se encontraron claves, generando par Ed25519 nuevo...")
        generar_par_de_claves("keys")
    else:
        print("[*] Usando claves existentes en keys/")


def separador(titulo):
    print("\n" + "=" * 70)
    print(titulo)
    print("=" * 70)


def main():
    asegurar_claves()

    # ------------------------------------------------------------------
    # Paso 1: generar el QR legítimo
    # ------------------------------------------------------------------
    separador("PASO 1 — Generación del QR original (legítimo)")
    payload_original = generar_qr_seguro(URL_ORIGINAL, CLAVE_PRIVADA, QR_ORIGINAL)

    # ------------------------------------------------------------------
    # Paso 2: verificar el QR legítimo
    # ------------------------------------------------------------------
    separador("PASO 2 — Verificación del QR original")
    resultado_original = verificar_qr_imagen(QR_ORIGINAL, CLAVE_PUBLICA)
    print(f"Contenido leído: {resultado_original.payload.get('content')}")
    print(resultado_original)

    # ------------------------------------------------------------------
    # Paso 3: un atacante intercepta el payload y cambia la URL,
    # SIN acceso a la clave privada (solo puede editar el JSON/imagen).
    # ------------------------------------------------------------------
    separador("PASO 3 — Ataque: modificación del contenido del QR")
    payload_atacado = dict(payload_original)  # el atacante copia hash y firma originales
    payload_atacado["content"] = URL_FALSA    # ...pero cambia la URL
    print(f"[!] El atacante reemplaza el contenido:")
    print(f"    original: {payload_original['content']}")
    print(f"    falso:    {payload_atacado['content']}")
    print(f"[!] El atacante NO puede recalcular una firma válida porque no")
    print(f"    posee la clave privada. Reutiliza el hash/firma originales.")
    generar_qr_desde_payload(payload_atacado, QR_MODIFICADO)
    print(f"[+] QR modificado (malicioso) generado en: {QR_MODIFICADO}")

    # ------------------------------------------------------------------
    # Paso 4: verificar el QR modificado
    # ------------------------------------------------------------------
    separador("PASO 4 — Verificación del QR modificado")
    resultado_atacado = verificar_qr_imagen(QR_MODIFICADO, CLAVE_PUBLICA)
    print(f"Contenido leído: {resultado_atacado.payload.get('content')}")
    print(resultado_atacado)

    # ------------------------------------------------------------------
    # Resumen final
    # ------------------------------------------------------------------
    separador("RESUMEN")
    print(f"QR original   ({QR_ORIGINAL}):   {'AUTÉNTICO' if resultado_original.es_autentico else 'ALTERADO'}")
    print(f"QR modificado ({QR_MODIFICADO}): {'AUTÉNTICO' if resultado_atacado.es_autentico else 'ALTERADO'}")

    assert resultado_original.es_autentico, "El QR original debería ser válido"
    assert not resultado_atacado.es_autentico, "El QR modificado NO debería ser válido"
    print("\n[✔] La demostración confirma que la firma Ed25519 detecta la alteración del contenido.")


if __name__ == "__main__":
    main()
