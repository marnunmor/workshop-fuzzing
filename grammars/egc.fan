# Gramatica del protocolo EGC/1 para Fandango.
# Documentacion: https://fandango-fuzzer.github.io/

<start>    ::= <header> "\n" <commands>
<header>   ::= "EGC/1"
<commands> ::= <command> | <command> "\n" <commands>
<command>  ::= <calc> | <msg>

# ---- CALC <expresion> ----------------------------------------------------
<calc>     ::= "CALC " <expr>
# EJERCICIO 3 (TODO): una expresion tambien puede ir entre parentesis.
#                     Anade esa alternativa a la regla <expr>.
<expr>     ::= <number> | <expr> <op> <expr> | "(" <expr> ")"
<op>       ::= "+" | "-" | "*" | "/"
<number>   ::= <digit>+
# (<digit> es un digito del 0 al 9: ya viene definido en Fandango)

# ---- MSG <longitud>:<payload> --------------------------------------------
<msg>      ::= "MSG " <length> ":" <payload>
<length>   ::= <digit>+
<payload>  ::= <char>*
<char>     ::= r"[a-zA-Z0-9 !?.]"

# ⭐ EJERCICIO 3, SI VAS RAPIDO: la gramatica solo genera lo que tu le dices.
#    Anade a <number> una alternativa con numeros GIGANTES (5000 digitos):
#        <number> ::= <digit>+ | r"[0-9]{5000}"
#    ¿Bug nuevo? ¿Por que? (Pista: int("9" * 5000). Al acabar, deja <number> como estaba.)

# RETO PARA CASA (TODO): restricciones semanticas. Aqui se esconde el cuarto bug.
# La gramatica genera MSG con longitudes aleatorias que casi nunca coinciden
# con el payload, asi que el parser los rechaza y nunca llega a procesarlos.
#
# Paso 1: quita el "#" de la linea de abajo y completa el "..." para que la
#         longitud declarada coincida con la longitud real del payload.
#         (str(<m>.<payload>) es el payload como texto)
#         Ejecuta (python workshop.py ex3). ¿Aparece algun bug nuevo? ¿Que longitudes salen?
#
# where forall <m> in <msg>: int(<m>.<length>) == ...
#
# Paso 2: ¿y si los mensajes son LARGOS? Anade una segunda restriccion.
#         Ojo: "forall" se cumple aunque no haya ningun MSG. Para OBLIGAR a
#         que exista al menos uno que cumpla algo, usa "exists":
#
# where exists <m> in <msg>: ...
#
# ⭐ Y DESPUES: arregla el bug que acabas de encontrar en
#    target/egc_parser.py (funcion cmd_msg) y vuelve a lanzarlo.
#    ¿Desaparece el bug? Asi se usa el fuzzing en la vida real: encontrar,
#    arreglar y comprobar que no vuelve (test de regresion).
