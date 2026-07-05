# Mini-exemplo concreto para o relatório
# Roda os algoritmos do esquema de Song et al. (2000) em um documento pequeno
# e mostra os valores intermediários em hexadecimal.

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from sse import (
    keygen,
    encrypt,
    trapdoor,
    search,
    decrypt,
    pad_word,
    _aes_ecb_encrypt,
    _prf_f,
    _prf_F,
    _prg,
    N_BYTES,
    M_BYTES,
    L_BYTES,
)

SEP = "=" * 62


def h(b: bytes) -> str:
    """Formata bytes como hex com espaços a cada 8 bytes para legibilidade."""

    s = b.hex()
    return " ".join(s[i : i + 16] for i in range(0, len(s), 16))


def main():
    document = ["the", "cat", "sat", "on", "the", "mat"]

    print(SEP)
    print("Mini-exemplo de Searchable Encryption (Song et al., 2000)")
    print(SEP)
    print(f"\nDocumento de entrada: {document}")
    print(f"Parâmetros: n={N_BYTES*8} bits, m={M_BYTES*8} bits, L={L_BYTES*8} bits\n")

    # ------------------------------------------------------------------
    # KeyGen
    # ------------------------------------------------------------------
    print(SEP)
    print("KeyGen")
    print(SEP)
    K = keygen()
    k_seed, k_prime, k_doubleprime = K
    print(f"  k_seed  (PRG)  = {h(k_seed)}")
    print(f"  k'      (f)    = {h(k_prime)}")
    print(f"  k''     (E)    = {h(k_doubleprime)}")

    # ------------------------------------------------------------------
    # Encrypt para a palavra "cat" (índice 1)
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print('Encrypt para a palavra "cat" (posição 1)')
    print(SEP)

    word = "cat"
    i = 1
    W_i = pad_word(word)
    X_i = _aes_ecb_encrypt(k_doubleprime, W_i)
    L_i = X_i[:L_BYTES]
    R_i = X_i[L_BYTES:]
    k_i = _prf_f(k_prime, L_i)
    S_values = _prg(k_seed, len(document))
    S_i = S_values[i]
    P_i = _prf_F(k_i, S_i)
    T_i = S_i + P_i
    C_i = bytes(a ^ b for a, b in zip(X_i, T_i))

    print(f"  W_{i}  (plaintext, com padding)  = {h(W_i)}")
    print(f'       ("{word}" + {N_BYTES - len(word.encode())} bytes \\x00)')
    print(f"\n  X_{i}  = E(k'', W_{i})            = {h(X_i)}")
    print(f"  L_{i}  = X_{i}[:{L_BYTES}]                  = {h(L_i)}")
    print(f"  R_{i}  = X_{i}[{L_BYTES}:]                  = {h(R_i)}")
    print(f"\n  S_{i}  = G(k_seed)[{i}]            = {h(S_i)}")
    print(f"  k_{i}  = f(k', L_{i})              = {h(k_i)}")
    print(f"  P_{i}  = F(k_{i}, S_{i})             = {h(P_i)}")
    print(f"  T_{i}  = S_{i} || P_{i}              = {h(T_i)}")
    print(f"\n  C_{i}  = X_{i} XOR T_{i}            = {h(C_i)}")
    print(f"  (ciphertext final enviado ao servidor)")

    # Todos os blocos cifrados
    print(f"\n{SEP}")
    print("Encrypt com todos os blocos do documento")
    print(SEP)
    C = encrypt(K, document)
    for idx, (w, block) in enumerate(zip(document, C)):
        print(f'  C[{idx}]  "{w:3}"  ->  {h(block)}')

    # ------------------------------------------------------------------
    # Trapdoor
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print('Trapdoor: gera token de busca para "cat" (enviado ao servidor)')
    print(SEP)
    trap_cat = trapdoor(K, "cat")
    X_trap, k_trap = trap_cat
    print(f"  X  = E(k'', \"cat\")  = {h(X_trap)}")
    print(f"  k  = f(k', X[:{L_BYTES}])  = {h(k_trap)}")
    print(f"  Token enviado ao servidor: (X, k)")
    print(f'  O servidor recebe (X, k) sem saber que a palavra buscada é "cat"')

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print("Search: servidor varre o ciphertext")
    print(SEP)

    queries = [
        ("cat", [1]),
        ("the", [0, 4]),
        ("sat", [2]),
        ("dog", []),
    ]
    all_ok = True
    for word_q, expected in queries:
        pos = search(C, trapdoor(K, word_q))
        status = "OK" if pos == expected else "FALHOU"
        if pos != expected:
            all_ok = False
        print(
            f'  Busca "{word_q:3}"  ->  posições {pos}  (esperado {expected})  [{status}]'
        )

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print("Decrypt: usuário recupera o documento original")
    print(SEP)
    recovered = decrypt(K, C)
    for idx, (original, rec) in enumerate(zip(document, recovered)):
        status = "OK" if original == rec else "FALHOU"
        if original != rec:
            all_ok = False
        print(f'  posição {idx}: "{rec}"  [{status}]')

    # ------------------------------------------------------------------
    # Sigilo provavel: mesma palavra, ciphertexts diferentes
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print('Sigilo provável: "the" aparece nas posições 0 e 4')
    print(SEP)

    the_positions = [i for i, w in enumerate(document) if w == "the"]
    print(f'  "the" esta nas posições: {the_positions}')
    print()
    for pos in the_positions:
        print(f"  C[{pos}]  = {h(C[pos])}")

    iguais = C[the_positions[0]] == C[the_positions[1]]
    print(f"\n  Os dois ciphertexts são iguais? {iguais}")
    print()
    print("  Mesmo que a palavra seja idêntica, cada posição recebe um valor")
    print("  S_i diferente gerado pelo PRG. O resultado é que o servidor ve")
    print("  dois blocos completamente distintos e não tem como saber que")
    print("  ambos correspondem a mesma palavra.")

    # ------------------------------------------------------------------
    # Consulta oculta: o que o servidor ve no trapdoor
    # ------------------------------------------------------------------
    print(f"\n{SEP}")
    print('Consulta oculta: o que o servidor recebe ao buscar "cat"')
    print(SEP)
    print(f"  X  = {h(X_trap)}")
    print(f"  k  = {h(k_trap)}")
    print()
    print("  O servidor recebe apenas esses dois valores. Sem a chave k''")
    print('  é impossivel recuperar "cat" a partir de X, pois X = E(k\'\', "cat")')
    print("  e AES sem a chave é computacionalmente inviável de reverter.")
    print("  O servidor só consegue verificar se um bloco casa, não o que foi buscado.")

    print(f"\n{SEP}")
    if all_ok:
        print("Todos os algoritmos funcionaram corretamente.")
    else:
        print("ERRO: algum algoritmo produziu resultado incorreto.")
    print(SEP)


if __name__ == "__main__":
    main()
