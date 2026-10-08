# Buzón Seguro

Herramienta de línea de comandos para enviar documentos de forma confidencial,
íntegra y autenticada, aun sobre un canal público.
Proyecto de la asignatura Gestión de Sistemas de Seguridad de la Información
(GSSI), Universidad de Oriente (UNIVO).

**Equipo N.º:** _(completar)_
**Integrantes:** _(completar: nombre, carné y rol)_

## Esquema criptográfico

| Propósito | Algoritmo |
|---|---|
| Acuerdo de claves | X25519 (ECDH, clave efímera por documento) |
| Derivación de clave | HKDF-SHA256 |
| Cifrado autenticado | AES-256-GCM (nonce aleatorio de 12 bytes, metadatos como AAD) |
| Firma digital | Ed25519 |
| Integridad | SHA-256 |
| Protección de claves privadas | PKCS#8 con BestAvailableEncryption |

## Requisitos

- Python 3.10 o superior (probado con 3.13)
- Windows, macOS o Linux

## Instalación

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# 1. Cada usuario crea su identidad (pide contraseña con getpass)
python main.py generar --usuario ana.lopez
python main.py generar --usuario beto.martinez

# 2. Comparar huellas por un segundo canal y marcar como verificado
python main.py huella --usuario ana.lopez
python main.py verificar --usuario ana.lopez

# 3. Cifrar y firmar un documento
python main.py cifrar --archivo solicitud.pdf --de ana.lopez --para beto.martinez

# 4. Recibir y descifrar
python main.py descifrar --paquete solicitud.buzon --usuario beto.martinez

# 5. Auditar la bitácora encadenada
python main.py auditar
```

## Pruebas

```bash
pytest
```

Escenarios cubiertos: P1 a P8 (ver informe técnico).

## Estructura

```
main.py            Punto de entrada
buzon.py           Lógica de la aplicación
tests/             Pruebas automatizadas (pytest)
datos/             Claves, directorio y bitácora (se crea solo; NO se sube al repo)
```

## Seguridad

- Las claves privadas y contraseñas nunca se guardan en el código ni en el repositorio.
- Los errores de recepción son genéricos para no revelar qué control falló.
- Las pruebas de ataque se realizan solo contra el propio sistema.
