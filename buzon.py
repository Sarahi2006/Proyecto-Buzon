"""
Buzón Seguro · Tarea en equipo GSSI (UNIVO)
Esqueleto integrado del proyecto (rol: Coordinador e integrador).

Cada función indica quién es su RESPONSABLE. Quien la implemente debe
respetar la firma (nombre, parámetros y valor de retorno) para que la
integración no se rompa.

Requisitos: pip install -r requirements.txt
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Constantes y rutas (compartidas por todo el equipo)
# ---------------------------------------------------------------------------
VERSION_PAQUETE = "buzon-seguro-v1"
INFO_HKDF = b"buzon-seguro-v1"
MENSAJE_ERROR_GENERICO = "Operación rechazada: el paquete no es válido."

DIR_BASE = Path("datos")
DIR_PRIVADAS = DIR_BASE / "privadas"        # claves privadas cifradas (NO se suben al repo)
DIR_DIRECTORIO = DIR_BASE / "directorio"    # claves públicas (carpeta compartida)
ARCHIVO_VERIFICADAS = DIR_BASE / "verificadas.json"  # huellas marcadas como verificadas
ARCHIVO_BITACORA = DIR_BASE / "bitacora.log"


class ErrorBuzon(Exception):
    """Error controlado de la aplicación. El mensaje es seguro de mostrar al usuario."""


# ---------------------------------------------------------------------------
# Utilidades comunes (ya implementadas)
# ---------------------------------------------------------------------------
def b64(x: bytes) -> str:
    """Bytes -> texto Base64."""
    return base64.b64encode(x).decode()


def b64d(s: str) -> bytes:
    """Texto Base64 -> bytes."""
    return base64.b64decode(s.encode())


def serializar_metadatos(metadatos: dict) -> bytes:
    """Serialización canónica de los metadatos.

    DEBE usarse siempre, tanto al cifrar/firmar como al verificar/descifrar;
    de lo contrario la firma y el AAD no coincidirán (ver Anexo B).
    """
    return json.dumps(metadatos, sort_keys=True).encode()


def ahora_iso() -> str:
    """Fecha y hora actual con zona horaria, en formato ISO 8601."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def asegurar_directorios() -> None:
    """Crea las carpetas de trabajo si no existen."""
    DIR_PRIVADAS.mkdir(parents=True, exist_ok=True)
    DIR_DIRECTORIO.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# RF1 · Generar identidad            RESPONSABLE: Responsable criptográfico
# ---------------------------------------------------------------------------
def generar_identidad(nombre: str, contrasena: bytes) -> None:
    """RF1: crea un par X25519 (cifrado) y un par Ed25519 (firma).

    Guarda las claves privadas cifradas con la contraseña (PKCS#8 con
    BestAvailableEncryption) en DIR_PRIVADAS y publica las públicas en
    DIR_DIRECTORIO.
    """
    raise NotImplementedError  # TODO


# ---------------------------------------------------------------------------
# RF2 · Huellas y verificación       RESPONSABLE: Responsable criptográfico
# ---------------------------------------------------------------------------
def huella(clave_publica_bytes: bytes) -> str:
    """RF2: huella SHA-256 (hex) de una clave pública, para compararla por otro canal."""
    raise NotImplementedError  # TODO


def huellas_de_usuario(nombre: str) -> dict:
    """RF2: devuelve {'x25519': <huella>, 'ed25519': <huella>} del usuario del directorio."""
    raise NotImplementedError  # TODO


def marcar_verificado(nombre: str) -> None:
    """RF2: registra las huellas actuales del usuario como verificadas (verificadas.json)."""
    raise NotImplementedError  # TODO


def esta_verificado(nombre: str) -> bool:
    """RF2: True solo si las claves públicas ACTUALES coinciden con las huellas verificadas."""
    raise NotImplementedError  # TODO


# ---------------------------------------------------------------------------
# RF3 y RF4 · Cifrar y firmar        RESPONSABLE: Responsable criptográfico
# ---------------------------------------------------------------------------
def cifrar_para(ruta_archivo: str, remitente: str, destinatario: str,
                contrasena: bytes) -> dict:
    """RF3 y RF4: ECDH efímero + HKDF-SHA256 + AES-256-GCM y firma Ed25519.

    - No cifrar para un destinatario no verificado (RF2).
    - Incluir en el contenido cifrado el SHA-256 del original (RF6).
    - Registrar el envío en la bitácora (RF7).
    Devuelve el paquete con el formato del Anexo B.
    """
    raise NotImplementedError  # TODO


# ---------------------------------------------------------------------------
# RF5 y RF6 · Recibir y descifrar    RESPONSABLE: Responsable criptográfico
# ---------------------------------------------------------------------------
def descifrar(paquete: dict, destinatario: str, contrasena: bytes) -> bytes:
    """RF5: verifica la firma ANTES de descifrar; si algo falla, lanza
    ErrorBuzon(MENSAJE_ERROR_GENERICO) sin revelar qué control falló.

    RF6: tras descifrar, comprueba el SHA-256 del original.
    RF7: registra la recepción en la bitácora.
    """
    raise NotImplementedError  # TODO


# ---------------------------------------------------------------------------
# RF7 · Bitácora encadenada          RESPONSABLE: Responsable de pruebas
# ---------------------------------------------------------------------------
def registrar_bitacora(evento: str, remitente: str, destinatario: str,
                       archivo: str) -> None:
    """RF7: agrega una línea a la bitácora que incluye el hash de la línea anterior."""
    raise NotImplementedError  # TODO


def auditar_bitacora() -> int | None:
    """RF7: recorre la bitácora y devuelve el número de la primera línea
    alterada (empezando en 1), o None si la cadena es íntegra."""
    raise NotImplementedError  # TODO


# ---------------------------------------------------------------------------
# Interfaz de línea de comandos      RESPONSABLE: Coordinador e integrador
# ---------------------------------------------------------------------------
def pedir_contrasena(mensaje: str = "Contraseña: ") -> bytes:
    """Solicita la contraseña sin mostrarla en pantalla (nunca en el código)."""
    return getpass.getpass(mensaje).encode()


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="buzon", description="Buzón Seguro")
    sub = p.add_subparsers(dest="accion", required=True)

    s = sub.add_parser("generar", help="RF1: crear la identidad de un usuario")
    s.add_argument("--usuario", required=True)

    s = sub.add_parser("huella", help="RF2: mostrar las huellas de un usuario")
    s.add_argument("--usuario", required=True)

    s = sub.add_parser("verificar", help="RF2: marcar a un usuario como verificado")
    s.add_argument("--usuario", required=True)

    s = sub.add_parser("cifrar", help="RF3/RF4: cifrar y firmar un documento")
    s.add_argument("--archivo", required=True)
    s.add_argument("--de", required=True, dest="remitente")
    s.add_argument("--para", required=True, dest="destinatario")
    s.add_argument("--salida", help="ruta del archivo .buzon (opcional)")

    s = sub.add_parser("descifrar", help="RF5/RF6: verificar y descifrar un paquete")
    s.add_argument("--paquete", required=True)
    s.add_argument("--usuario", required=True, help="destinatario que descifra")
    s.add_argument("--salida", help="ruta donde guardar el documento (opcional)")

    sub.add_parser("auditar", help="RF7: verificar la bitácora encadenada")
    return p


def ejecutar(args: argparse.Namespace) -> None:
    asegurar_directorios()

    if args.accion == "generar":
        generar_identidad(args.usuario, pedir_contrasena("Contraseña nueva: "))
        print(f"Identidad creada para {args.usuario}.")

    elif args.accion == "huella":
        for tipo, valor in huellas_de_usuario(args.usuario).items():
            print(f"{tipo}: {valor}")

    elif args.accion == "verificar":
        huellas = huellas_de_usuario(args.usuario)
        for tipo, valor in huellas.items():
            print(f"{tipo}: {valor}")
        if input("¿Coinciden con las que confirmó por otro canal? (s/n): ").lower() == "s":
            marcar_verificado(args.usuario)
            print(f"{args.usuario} marcado como verificado.")
        else:
            print("No se marcó como verificado.")

    elif args.accion == "cifrar":
        paquete = cifrar_para(args.archivo, args.remitente, args.destinatario,
                              pedir_contrasena())
        salida = Path(args.salida or f"{Path(args.archivo).stem}.buzon")
        salida.write_text(json.dumps(paquete, indent=2), encoding="utf-8")
        print(f"Paquete guardado en {salida}")

    elif args.accion == "descifrar":
        paquete = json.loads(Path(args.paquete).read_text(encoding="utf-8"))
        datos = descifrar(paquete, args.usuario, pedir_contrasena())
        salida = Path(args.salida or paquete["metadatos"]["archivo"])
        salida.write_bytes(datos)
        print(f"Documento recuperado en {salida}")

    elif args.accion == "auditar":
        linea = auditar_bitacora()
        if linea is None:
            print("Bitácora íntegra.")
        else:
            print(f"Bitácora alterada: primera línea inválida = {linea}")


def main() -> None:
    args = construir_parser().parse_args()
    try:
        ejecutar(args)
    except ErrorBuzon as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except NotImplementedError:
        print("Función aún no implementada por el equipo.", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
