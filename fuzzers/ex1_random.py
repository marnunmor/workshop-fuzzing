"""
EJERCICIO 1 -- Fuzzing aleatorio (blackbox)
===========================================
Idea: generar entradas completamente aleatorias y lanzarlas contra el programa.

TODO: completa random_input() para que devuelva bytes aleatorios
      de longitud aleatoria (por ejemplo entre 0 y 100).

Ejecuta:   python workshop.py ex1            (30 segundos por defecto)
           python workshop.py ex1 10         (10 segundos)

Preguntas:
  - ¿Cuantos bugs encuentra? ¿Que tipo de bugs son?
  - ¿Cuantas entradas pasan de la cabecera "EGC/1"? ¿Por que?

⭐ SI VAS RAPIDO (opcional, no pasa nada si lo dejas a medias):
   Haz un fuzzer "con trampa": que la mitad de las veces genere
   b"EGC/1\n" + texto aleatorio. ¿Encuentra mas bugs? ¿Por que no?
   Pista: random.choice("CALCMSG 0123456789()+-*/:") para generar texto "con sentido".
"""
import random
import sys
import time

from harness import CrashCollector


def random_input() -> bytes:
    # TODO: devuelve bytes aleatorios de longitud aleatoria.
    # Pista: random.randint(a, b), random.randbytes(n)
    
    n = random.randint(0,100)
    return random.randbytes(n)


def main(budget: float):
    print("Asi son tus entradas aleatorias (3 ejemplos):")
    for _ in range(3):
        print(f"   {random_input()[:70]!r}")
    print(f"Fuzzeando durante {budget:.0f}s ... (Ctrl+C para parar)")
    crashes = CrashCollector("random")
    start, execs = time.time(), 0
    while time.time() - start < budget:
        crashes.check(random_input())
        execs += 1
    return crashes.report(execs, time.time() - start)


if __name__ == "__main__":
    try:
        main(float(sys.argv[1]) if len(sys.argv) > 1 else 30)
    except KeyboardInterrupt:
        print("\nInterrumpido.")
