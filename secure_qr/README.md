# QR Seguro con Ed25519 y SHA-256

Trabajo práctico de Redes y Seguridad Informática — QR ≠ seguridad.
QR + criptografía + verificación = sistema de comunicación más seguro.

**Autor:** Salvador Juarez

## ¿Qué hace este proyecto?

1. Genera un código QR a partir de un mensaje o URL.
2. Calcula el hash **SHA-256** del contenido.
3. Genera una **firma digital Ed25519** con una clave privada.
4. Codifica dentro del QR un paquete JSON `{content, hash, sig}`.
5. Lee el QR (desde la imagen) y verifica la firma con la clave pública.
6. Informa si el contenido es:
   - ✅ **AUTÉNTICO** (hash y firma válidos), o
   - ❌ **ALTERADO / NO AUTÉNTICO** (hash o firma no coinciden).

También incluye una variante opcional (`qr_cifrado.py`) que además
**cifra** el contenido, para que quien escanee el QR no pueda leer el
mensaje sin la clave simétrica correspondiente (desafío adicional).

El informe conceptual (SHA-256, Ed25519, Reed-Solomon, tipos de ataque,
etc.) está en [`docs/INFORME.md`](docs/INFORME.md).

## Estructura del proyecto

```
secure_qr/
├── crypto_utils.py        # hashing, claves Ed25519, firma/verificación, cifrado opcional
├── generar_claves.py      # genera el par de claves Ed25519 (keys/)
├── generar_qr_seguro.py   # arma el payload firmado y genera la imagen QR
├── verificar_qr.py        # lee un QR (OpenCV) y valida hash + firma
├── qr_cifrado.py          # desafío adicional: QR firmado + cifrado
├── demo_ataque.py         # demo end-to-end: QR válido vs. QR modificado
├── requirements.txt
├── keys/
│   ├── public_key.pem     # clave pública (incluida en el repo)
│   └── private_key.pem    # clave privada (NO se sube a git, ver .gitignore)
├── output/
│   ├── qr_original.png    # ejemplo de QR válido
│   ├── qr_modificado.png  # ejemplo de QR alterado por un "atacante"
│   └── qr_cifrado.png     # ejemplo del desafío adicional (cifrado)
└── docs/
    ├── INFORME.md         # respuestas conceptuales + explicación del sistema
    └── demo_output.txt    # captura de la ejecución de la demo
```

> ⚠️ **Nota de seguridad:** en un sistema real, la clave privada **nunca**
> debe compartirse ni subirse a un repositorio. Aquí se ignora vía
> `.gitignore` (`keys/private_key.pem`); si clonás el repo y querés
> reproducir la demo desde cero, generá tu propio par de claves con
> `generar_claves.py` (esto también regenerará `public_key.pem`, y con
> él tendrás que volver a generar los QR de ejemplo).

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Dependencias: `cryptography` (Ed25519), `qrcode` + `pillow` (generación
de QR), `opencv-python-headless` (lectura/decodificación de QR).

## Uso

### 1. Generar las claves

```bash
python generar_claves.py
```

### 2. Generar un QR seguro

```bash
python generar_qr_seguro.py "https://sitio-oficial.com"
# -> output/qr_original.png
```

### 3. Verificar un QR

```bash
python verificar_qr.py output/qr_original.png
```

### 4. Demo completa (QR válido vs. QR modificado / atacado)

```bash
python demo_ataque.py
```

Genera `output/qr_original.png` y `output/qr_modificado.png`, verifica
ambos y muestra por qué el segundo es detectado como no auténtico
aunque se lea perfectamente bien (el QR en sí no está dañado).

### 5. (Desafío adicional) QR firmado + cifrado

```bash
# generar
python qr_cifrado.py generar "https://sitio-oficial.com/pago?monto=1000"

# verificar y descifrar (requiere la clave simétrica generada en el paso anterior)
python qr_cifrado.py verificar output/qr_cifrado.png
```

## Resumen del mecanismo

El QR no guarda solo el texto plano, sino:

```json
{
  "content": "https://sitio-oficial.com",
  "hash": "sha256(content)",
  "sig": "Ed25519_sign(private_key, hash)"
}
```

Al verificar:

1. Se recalcula `sha256(content)` y se compara con `hash` → **integridad**.
2. Se valida `sig` contra `hash` usando la **clave pública** → **autenticidad**.

Si cualquiera de las dos falla, el sistema reporta el QR como
**ALTERADO / NO AUTÉNTICO**, sin importar que la imagen del QR se haya
leído sin errores (Reed-Solomon solo garantiza que se pueda *leer* el
texto, no que ese texto sea confiable).
