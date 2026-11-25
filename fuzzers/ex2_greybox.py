"""
EJERCICIO 2 -- Fuzzing guiado por cobertura (greybox, estilo AFL / libFuzzer)
============================================================================
Idea: en vez de generar desde cero, MUTAMOS entradas que ya tenemos (semillas).
Si una mutacion ejecuta codigo nuevo (nueva cobertura), la guardamos en el
corpus para seguir mutandola. Asi el fuzzer "aprende" el formato poco a poco.

Este fuzzer cabe en ~60 lineas. AFL++ hace lo mismo pero en C,
instrumentando el binario y a millones de ejecuciones por segundo.

TODO 1: completa mutate() con las tres mutaciones
        (cambiar, borrar e insertar un byte). Sin ellas, el fuzzer no muta nada!
TODO 2: anade semillas en seeds/ (ficheros con entradas validas).
        ¿Que pasa si no hay semillas? ¿Y si las hay?

Ejecuta:   python workshop.py ex2            (90 segundos por defecto)

⭐ SI VAS RAPIDO (opcional, elige uno):
   a) Diccionario: anade una cuarta mutacion que inserte una palabra clave
      ("CALC ", "MSG ", "(", ...) en una posicion aleatoria.
      ¿Encuentra bugs nuevos o mas rapido? AFL++ llama a esto "dictionaries".
   b) Sin semillas: mueve los ficheros de seeds/ a otra carpeta y lanzalo.
      ¿Llega a pasar de la cabecera? ¿Por que las semillas importan tanto?
"""
import os
import random
import sys
import time

from harness import CrashCollector, run_one

TARGET_FILE = "egc_parser.py"
SEED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "seeds")


# ---------------------------------------------------------------- cobertura
# Hasta Python 3.11, poner y quitar el trazador en cada ejecucion es gratis.
# Desde 3.12 es lento, y en 3.13+ agota un contador interno de Python
# ("OverflowError: events set too many times") tras ~8 millones de ejecuciones.
# Por eso, desde 3.12 lo instalamos una sola vez y lo dejamos puesto.
KEEP_TRACER = sys.version_info >= (3, 12)
_lines = None    # conjunto donde el trazador apunta las lineas (None = no apuntar)


def _tracer(frame, event, arg):
    """Python llama a esta funcion en cada linea que ejecuta el objetivo."""
    if _lines is None or not frame.f_code.co_filename.endswith(TARGET_FILE):
        return None
    if event == "line":
        _lines.add(frame.f_lineno)
    return _tracer


def coverage_of(data: bytes) -> frozenset:
    """Ejecuta el objetivo y devuelve las lineas que se han ejecutado."""
    global _lines
    if sys.gettrace() is not _tracer:
        sys.settrace(_tracer)
    _lines = lines = set()
    try:
        run_one(data)
    finally:
        _lines = None
        if not KEEP_TRACER:
            sys.settrace(None)
    return frozenset(lines)


# ---------------------------------------------------------------- mutaciones
def mutate(data: bytes) -> bytes:
    if not data:                      # entrada vacia: devolvemos un byte aleatorio
        return bytes([random.randrange(256)])
    data = bytearray(data)
    choice = random.randint(0, 3)
    List= ["CALC","MSG",",","("]
    if choice == 0:
        # TODO: cambiar un byte en una posicion aleatoria por otro aleatorio
        # Pista: random.randrange(len(data)) da una posicion, random.randrange(256) un byte
        r = random.randrange(len(data))
        data[r] =random.randrange(256)

    elif choice == 1:
        # TODO: borrar un byte en una posicion aleatoria
        r = random.randrange(len(data))
        del data[r]

    elif choice == 2:
        # TODO: insertar un byte aleatorio en una posicion aleatoria
        i = random.randrange(len(data))
        b= random.randrange(256)
        data.insert(i,b)

    elif choice == 3:
            # TODO: insertar un byte aleatorio en una posicion aleatoria
        for i in List:
            b= random.randrange(256)
            data.insert(random.randrange(len(data)),i.encode("utf-8"))
                

    return bytes(data)


# ---------------------------------------------------------------- bucle
def load_seeds() -> list:
    seeds = []
    if os.path.isdir(SEED_DIR):
        for name in sorted(os.listdir(SEED_DIR)):
            with open(os.path.join(SEED_DIR, name), "rb") as f:
                seeds.append(f.read())
    return seeds or [b""]


def main(budget: float):
    crashes = CrashCollector("greybox")
    corpus = load_seeds()
    seen = set()
    for s in corpus:
        seen |= coverage_of(s)
    print(f"Corpus inicial: {len(corpus)} semillas, {len(seen)} lineas cubiertas")
    print(f"Fuzzeando durante {budget:.0f}s ... (Ctrl+C para parar)")

    start, execs = time.time(), 0
    while time.time() - start < budget:
        # Como AFL, damos prioridad a las entradas mas recientes (las que mas han "avanzado")
        parent = random.choice(corpus[-3:]) if random.random() < 0.5 else random.choice(corpus)
        child = mutate(parent)
        for _ in range(random.randint(0, 3)):   # a veces, varias mutaciones seguidas
            child = mutate(child)
        execs += 1
        cov = coverage_of(child)
        if crashes.check(child):
            continue
        if not cov <= seen:                       # ¡cobertura nueva!
            seen |= cov
            corpus.append(child)
            print(f"  [{time.time() - start:5.1f}s] +cobertura ({len(seen)} lineas): {child[:60]!r}")

    sys.settrace(None)                            # fin: quitamos el trazador
    print(f"Corpus final: {len(corpus)} entradas")
    if len(corpus) == len(load_seeds()):
        print("   ⚠ El corpus no ha crecido: ninguna mutacion ha descubierto codigo nuevo.\n"
              "     ¿Has completado mutate()? (TODO 1)")
    return crashes.report(execs, time.time() - start)


if __name__ == "__main__":
    try:
        main(float(sys.argv[1]) if len(sys.argv) > 1 else 90)
    except KeyboardInterrupt:
        print("\nInterrumpido.")



""" == greybox: 1743406 ejecuciones en 90.0s (19368/s) ==
   Rechazadas en la cabecera:  73.8%   Rechazadas despues:  25.6%   Validas:   0.6%   Crashes:   0.0%
   - KeyError en enter_debug_mode() linea 54
       b'DEBUG/1MSGf\xaa4:h\x12oa\n' """