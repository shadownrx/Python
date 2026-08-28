# Informe — QR Seguro con SHA-256 y Ed25519

**Materia:** Redes y Seguridad Informática
**Proyecto:** Desarrollo de un QR seguro en Python
**Autor:** Salvador Juarez

---

## 1. Cómo funciona el sistema

El proyecto separa dos cosas que suelen confundirse: **poder leer** un
QR y **poder confiar** en lo que dice. Para eso, el contenido que se
codifica dentro del QR no es el mensaje "pelado", sino un paquete con
tres campos:

```json
{
  "content": "https://sitio-oficial.com",
  "hash": "cf3113919fcf567e450b03786b5f9ba4a2f62c1e992834fbfe8ae87408ce8dff",
  "sig": "6NfWxIWmcfhugc/DsZxLJwGUSrIMLb4G8qvsc+XztLcdHEZ65RGpDJFLdkfpHxqr8Rf22tVtvhQ0N87RyenzAA=="
}
```

**Generación (emisor, dueño de la clave privada):**

1. Se calcula `hash = SHA-256(content)`.
2. Se firma ese hash con la clave privada Ed25519: `sig = Firma(hash, clave_privada)`.
3. Se arma el JSON `{content, hash, sig}` y se codifica como texto dentro
   del QR (con corrección de errores Reed-Solomon estándar, como
   cualquier QR).

**Verificación (receptor, que solo tiene la clave pública):**

1. Escanea el QR y obtiene el JSON.
2. Recalcula `SHA-256(content)` y lo compara con el `hash` recibido
   → si no coincide, el contenido fue **modificado** después de
   generarse el QR (falla de **integridad**).
3. Si el hash coincide, verifica `sig` contra ese hash usando la
   **clave pública** → si no es válida, el QR no fue firmado por el
   dueño legítimo de la clave privada, o el hash fue alterado (falla
   de **autenticidad**).
4. Solo si ambas verificaciones pasan, se informa **✅ AUTÉNTICO**.
   En cualquier otro caso, **❌ ALTERADO / NO AUTÉNTICO**.

## 2. Qué tipo de ataque evita

Evita el **ataque de sustitución/manipulación de contenido de un QR**
(a veces llamado *QR spoofing* o *QRLJacking* de contenido): un
atacante que pega un sticker con otro QR, o que intercepta y modifica
el texto codificado (por ejemplo cambiando una URL legítima por una de
phishing, o un monto/cuenta en un QR de pago), **no tiene la clave
privada** del emisor original. Puede cambiar `content`, pero no puede
generar un `hash`/`sig` que sean consistentes con el nuevo contenido y
válidos para la clave pública que el receptor ya conoce.

Esto es exactamente lo que se demuestra en `demo_ataque.py`:

- QR original → `https://sitio-oficial.com` → **AUTÉNTICO**.
- QR modificado → el atacante cambia el `content` a
  `https://sitio-falso.com` pero reutiliza el `hash`/`sig` originales
  (es lo único que puede hacer sin la clave privada) → el hash
  recalculado ya no coincide → **ALTERADO / NO AUTÉNTICO**.

Lo importante es que el QR modificado **se lee perfectamente bien**
(no está dañado, Reed-Solomon no tiene nada que corregir): el sistema
lo rechaza por criptografía, no por corrección de errores.

Lo que el sistema **no** evita (fuera del alcance de este proyecto): que
alguien reemplace el QR físico completo por uno propio firmado con su
*propia* clave privada, y engañe al usuario para que confíe en esa
clave pública distinta (esto se resuelve con infraestructura de
confianza sobre las claves, p. ej. certificados/CA, fuera del alcance
del TP), o ataques que no dependen del contenido del QR (por ejemplo,
un sitio legítimo comprometido detrás de una URL correctamente
firmada).

## 3. Funcionamiento básico de un código QR

Un código QR (*Quick Response*) es un código de barras bidimensional
que codifica datos (texto, números, binario) como una matriz de
módulos blancos y negros. Incluye patrones fijos (los tres cuadrados
de las esquinas, los patrones de alineación y temporización) que
permiten a un lector ubicar, escalar y corregir la perspectiva del
código, y luego decodificar los bits según el modo de codificación
(numérico, alfanumérico, byte, etc.) y el nivel de corrección de
errores elegido. El QR es simplemente un **contenedor de datos
públicos y legibles por cualquiera**: no tiene, por sí mismo, ningún
mecanismo de seguridad.

## 4. Corrección de errores y Reed–Solomon

Los códigos QR usan códigos Reed–Solomon para poder reconstruir el
mensaje original aunque parte del código esté sucio, rayado o
parcialmente tapado (por ejemplo, con un logo en el centro). Existen
cuatro niveles (L, M, Q, H) que permiten recuperar entre ~7% y ~30% de
módulos dañados. En este proyecto se usa el nivel M.

Reed–Solomon agrega **redundancia matemática** sobre los mismos datos:
si algunos bytes se pierden o se leen mal, el algoritmo puede
recalcularlos a partir de la redundancia. Es un mecanismo de
**disponibilidad/robustez física**, no de seguridad.

## 5. Diferencia entre corrección de errores y seguridad

- **Corrección de errores (Reed–Solomon):** responde a la pregunta
  "¿puedo leer correctamente los bits que fueron impresos, aunque el
  código esté parcialmente dañado?". No sabe nada sobre si esos bits
  representan información *verdadera* o *confiable*.
- **Seguridad (hash + firma digital):** responde a la pregunta "¿estos
  bits, además de leerse bien, son los que realmente escribió el
  emisor legítimo y no fueron cambiados por nadie más?".

Un QR puede leerse perfectamente (Reed–Solomon funcionó sin problemas)
y aun así contener un contenido malicioso, modificado a propósito. Por
eso, en este proyecto, **la corrección de errores no forma parte de la
seguridad**: la seguridad la dan el hash y la firma digital.

## 6. SHA-256 y función hash

SHA-256 es una **función hash criptográfica**: toma una entrada de
cualquier longitud y produce una salida fija de 256 bits (64
caracteres hexadecimales). Propiedades relevantes:

- **Determinista:** el mismo input siempre da el mismo hash.
- **Efecto avalancha:** cambiar un solo carácter del input cambia
  completamente el hash resultante.
- **Resistencia a preimagen y a colisiones:** en la práctica es
  computacionalmente inviable encontrar un input que produzca un hash
  dado, o dos inputs distintos con el mismo hash.

En este proyecto, `SHA-256(content)` actúa como una "huella digital"
del contenido: si el contenido cambia, aunque sea en un carácter, el
hash cambia por completo, lo que permite detectar la alteración.

## 7. Integridad de la información

**Integridad** significa que la información no fue modificada, ni
accidental ni intencionalmente, entre el momento en que se generó y el
momento en que se consume. El hash SHA-256 embebido en el QR permite
**detectar** pérdida de integridad: si el contenido leído no produce el
mismo hash que viaja junto a él, sabemos que algo cambió. Por sí solo,
un hash **no impide** que alguien modifique el contenido *y* recalcule
un nuevo hash acorde — para eso se necesita además autenticidad (punto
siguiente).

## 8. Criptografía de clave pública

Es un esquema criptográfico basado en **pares de claves matemáticamente
relacionadas pero computacionalmente imposibles de derivar una de la
otra**: una clave privada (secreta, solo la conoce el dueño) y una
clave pública (puede compartirse libremente). Lo que se firma o cifra
con una clave del par, solo puede verificarse o descifrarse con la
otra. Esto permite, sin necesidad de compartir ningún secreto por
adelantado, que cualquiera con la clave pública pueda comprobar que
algo fue firmado por el dueño de la clave privada correspondiente.

## 9. Clave privada y clave pública

- **Clave privada:** se genera una sola vez, se guarda en secreto y se
  usa para **firmar**. Si se filtra, cualquiera podría hacerse pasar
  por el emisor legítimo.
- **Clave pública:** se deriva matemáticamente de la privada, se
  distribuye libremente (en este proyecto, como archivo
  `keys/public_key.pem`) y se usa para **verificar** firmas hechas con
  su clave privada correspondiente. Conocer la clave pública no permite
  reconstruir la privada ni falsificar firmas.

## 10. Firma digital Ed25519

Ed25519 es un esquema de firma digital basado en curvas elípticas
(Edwards25519), rápido, con claves y firmas muy compactas (32 y 64
bytes respectivamente) y sin parámetros configurables inseguros (a
diferencia de RSA o ECDSA, donde una mala elección de parámetros puede
debilitar la seguridad). Al firmar un mensaje `m` con la clave privada,
se obtiene una firma `sig`; cualquiera con la clave pública puede
verificar que `sig` corresponde a `m` y a esa clave, sin poder generar
una firma válida para otro mensaje sin la clave privada. En este
proyecto se firma el `hash` SHA-256 del contenido (no el contenido
directo), lo cual es una práctica habitual y además hace explícito el
rol del hash en la integridad.

## 11. Autenticidad vs. confidencialidad

Son dos propiedades de seguridad **independientes**:

- **Autenticidad:** garantiza *quién* generó/firmó la información y
  que no fue alterada después. Se logra con firma digital (Ed25519 en
  este proyecto). El contenido del QR sigue siendo **legible** por
  cualquiera que lo escanee; lo que se garantiza es que, si dice algo,
  es porque el emisor legítimo lo dijo.
- **Confidencialidad:** garantiza que *solo* quien tenga la clave
  correcta puede **leer** la información. Se logra con cifrado
  (en el desafío adicional, cifrado simétrico Fernet/AES). Sin la
  clave simétrica, el contenido del QR es ilegible aunque se escanee
  correctamente.

Se puede tener una sin la otra (un QR firmado pero legible por todos,
como el caso base de este proyecto; o un QR cifrado pero sin firmar,
donde no se podría detectar manipulación del texto cifrado) o ambas a
la vez (el desafío adicional implementado en `qr_cifrado.py`: firma
sobre el texto cifrado).

## 12. Posibles ataques mediante modificación del contenido de un QR

- **Suplantación de URL / phishing con sticker:** pegar un QR falso
  sobre uno legítimo (por ejemplo, en carteles, mesas de restaurantes,
  parquímetros, cupones), redirigiendo a un sitio malicioso que
  imita al original para robar credenciales o datos de pago.
- **Manipulación de QR de pago:** cambiar el alias, CBU/CVU, monto o
  cuenta de destino codificados en un QR de cobro.
- **Inyección de payloads maliciosos:** codificar en el QR comandos,
  enlaces con parámetros manipulados, o texto que explote alguna
  vulnerabilidad de la app lectora (menos común, pero documentado).
- **Man-in-the-middle sobre la distribución del QR:** interceptar el
  QR entre que se genera y se imprime/publica, reemplazándolo por uno
  propio antes de que llegue al usuario final.
- **Reutilización/repetición (replay):** reutilizar un QR válido en un
  contexto distinto al previsto (por ejemplo, un ticket de un solo uso
  reescaneado). Este proyecto no cubre este caso (requeriría, por
  ejemplo, agregar un identificador único y una lista de QRs ya usados
  del lado del verificador).

Este proyecto se enfoca específicamente en el primer y segundo caso:
detectar cuando el **contenido codificado** dentro del QR fue
modificado después de haber sido firmado por el emisor legítimo,
gracias a la combinación de hash SHA-256 (integridad) + firma digital
Ed25519 (autenticidad).

## 13. Conclusión

Un código QR, por sí solo, es solo una forma de **codificar y
transportar texto** de manera robusta ante daños físicos gracias a
Reed–Solomon; no ofrece ninguna garantía de que ese texto sea confiable.

**QR ≠ seguridad.**

Agregando una huella hash SHA-256 y una firma digital Ed25519 sobre el
contenido, y verificándolas del lado del lector con la clave pública
del emisor, se logra detectar cualquier modificación posterior al
contenido, sin importar que el QR se lea perfectamente bien.

**QR + criptografía + verificación = sistema de comunicación más
seguro.**
