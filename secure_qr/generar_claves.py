"""Script simple para generar (o regenerar) el par de claves Ed25519."""

import argparse

from crypto_utils import generar_par_de_claves

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Genera un par de claves Ed25519 en formato PEM.")
    parser.add_argument("--directorio", default="keys")
    args = parser.parse_args()

    ruta_privada, ruta_publica = generar_par_de_claves(args.directorio)
    print(f"[+] Clave privada guardada en: {ruta_privada}  (¡NUNCA la compartas ni la subas a un repo real!)")
    print(f"[+] Clave pública guardada en:  {ruta_publica}")
