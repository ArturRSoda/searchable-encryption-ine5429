# Experimentos: corretude, desempenho e vazamento por frequência de acesso
#
# Gera dois arquivos PNG na raiz do projeto:
#   grafico_desempenho.png  : tempo de busca vs. tamanho do documento
#   grafico_vazamento.png   : frequência real vs. padrão de acesso do servidor

import sys
import os
import random
import string
import time

import matplotlib

matplotlib.use("Agg")  # modo sem janela (headless)
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
from sse import keygen, encrypt, trapdoor, search, decrypt

# Pasta raiz do projeto (um nível acima de src/)
ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------


def random_word(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


# ---------------------------------------------------------------------------
# Experimento 1 - Corretude
# ---------------------------------------------------------------------------


def experiment_correctness():
    print("=" * 60)
    print("Experimento 1 - Corretude")
    print("=" * 60)

    K = keygen()
    vocab = ["cloud", "data", "secure", "encrypt", "search", "key", "hash"]

    # Documento de 300 palavras com três ocorrências conhecidas de "target"
    random.seed(42)
    document = [random.choice(vocab) for _ in range(300)]
    target_positions = [42, 150, 275]
    for p in target_positions:
        document[p] = "target"

    C = encrypt(K, document)

    results = []

    # Caso 1: palavra que existe em posições conhecidas.
    found = search(C, trapdoor(K, "target"))
    expected_set = set(target_positions)
    # Todas as posições conhecidas devem estar no resultado
    # (pode haver falsos positivos, mas com m=64 a probabilidade é negligível)
    ok1 = expected_set.issubset(set(found))
    results.append(
        ('"target" (existe, 3 ocorrências)', str(target_positions), str(found), ok1)
    )

    # Caso 2: palavra que não existe.
    found_none = search(C, trapdoor(K, "qwerty"))
    ok2 = found_none == []
    results.append(('"qwerty" (não existe)', "[]", str(found_none), ok2))

    # Caso 3: palavra do vocabulário. Verificar que encontra pelo menos uma ocorrência.
    found_cloud = search(C, trapdoor(K, "cloud"))
    real_cloud = [i for i, w in enumerate(document) if w == "cloud"]
    ok3 = set(real_cloud).issubset(set(found_cloud))
    results.append(
        (
            '"cloud" (múltiplas ocorrências)',
            str(real_cloud[:5]) + "...",
            str(found_cloud[:5]) + "...",
            ok3,
        )
    )

    # Caso 4: decriptação completa
    recovered = decrypt(K, C)
    ok4 = recovered == document
    results.append(
        (
            "Decriptação completa (300 palavras)",
            "igual ao original",
            "igual ao original" if ok4 else "DIFERENTE",
            ok4,
        )
    )

    # Caso 5: trapdoor de uma chave não encontra nada em ciphertext de outra
    K2 = keygen()
    C2 = encrypt(K2, document)
    found_cross = search(C2, trapdoor(K, "target"))
    ok5 = found_cross == []
    results.append(
        ("Chave errada (isolamento de consulta)", "[]", str(found_cross), ok5)
    )

    # Exibir tabela
    col_w = [38, 22, 22, 8]
    header = f"{'Caso':<{col_w[0]}} {'Esperado':<{col_w[1]}} {'Obtido':<{col_w[2]}} {'Status'}"
    print(f"\n{header}")
    print("-" * sum(col_w))
    all_ok = True
    for caso, esp, obt, ok in results:
        status = "OK" if ok else "FALHOU"
        if not ok:
            all_ok = False
        print(f"{caso:<{col_w[0]}} {esp:<{col_w[1]}} {obt:<{col_w[2]}} {status}")

    print()
    if all_ok:
        print("Resultado: corretude verificada em todos os casos.\n")
    else:
        print("ERRO: um ou mais casos falharam.\n")

    return all_ok


# ---------------------------------------------------------------------------
# Experimento 2 - Desempenho (tempo linear)
# ---------------------------------------------------------------------------


def experiment_performance():
    print("=" * 60)
    print("Experimento 2 - Desempenho")
    print("=" * 60)

    K = keygen()
    sizes = [500, 1_000, 2_000, 5_000, 10_000, 25_000, 50_000]
    repetitions = 5
    times_ms = []

    for n in sizes:
        doc = [random_word() for _ in range(n)]
        C = encrypt(K, doc)
        trap = trapdoor(
            K, "nothere"
        )  # palavra ausente, então percorre o documento inteiro

        t0 = time.perf_counter()
        for _ in range(repetitions):
            search(C, trap)
        t1 = time.perf_counter()

        avg_ms = (t1 - t0) / repetitions * 1000
        times_ms.append(avg_ms)
        print(f"  n = {n:>6} palavras  ->  {avg_ms:.1f} ms por busca")

    # Gráfico
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(sizes, times_ms, marker="o", linewidth=2, color="steelblue")
    ax.set_xlabel("Número de palavras no documento")
    ax.set_ylabel("Tempo médio de busca (ms)")
    ax.set_title("Desempenho da busca\n(varredura sequencial, comportamento O(n))")
    ax.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()

    out = os.path.join(ROOT_DIR, "grafico_desempenho.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"\nGráfico salvo em: grafico_desempenho.png\n")


# ---------------------------------------------------------------------------
# Experimento 3 - Vazamento por frequência de acesso
# ---------------------------------------------------------------------------


def experiment_leakage():
    print("=" * 60)
    print("Experimento 3 - Vazamento por frequência de acesso")
    print("=" * 60)

    K = keygen()

    # Vocabulário com frequências intencionalmente desiguais
    # (simula um documento real onde algumas palavras são muito mais comuns)
    vocab_freq = {
        "cloud": 40,
        "data": 30,
        "secure": 20,
        "encrypt": 15,
        "search": 10,
        "server": 6,
        "private": 2,
    }

    # Construir documento com distribuição proporcional às frequências
    document = []
    for word, freq in vocab_freq.items():
        document.extend([word] * freq)
    random.shuffle(document)

    C = encrypt(K, document)

    words = list(vocab_freq.keys())
    weights = list(vocab_freq.values())

    # O servidor não sabe as palavras, apenas conta posições retornadas por busca
    # (honest-but-curious: segue o protocolo, mas analisa o que recebe)
    server_hits = {w: 0 for w in words}

    n_queries = 300
    for _ in range(n_queries):
        queried = random.choices(words, weights=weights, k=1)[0]
        trap = trapdoor(K, queried)
        positions = search(C, trap)
        # O servidor acumula quantas posições foram retornadas por palavra buscada.
        # Na prática ele não sabe "queried"; aqui associamos para fins de análise.
        server_hits[queried] += len(positions)

    # Normalizar para frequência relativa
    total_real = sum(vocab_freq.values())
    total_obs = sum(server_hits.values()) or 1

    freq_real = [vocab_freq[w] / total_real for w in words]
    freq_obs = [server_hits[w] / total_obs for w in words]

    print(f"\n  {'Palavra':<10} {'Freq. real':>12} {'Padrão servidor':>16}")
    print("  " + "-" * 40)
    for w, fr, fo in zip(words, freq_real, freq_obs):
        print(f"  {w:<10} {fr:>11.1%} {fo:>15.1%}")

    # Gráfico de barras lado a lado
    x = range(len(words))
    fig, ax = plt.subplots(figsize=(10, 5))
    bars1 = ax.bar(
        [i - 0.2 for i in x],
        freq_real,
        width=0.38,
        label="Frequência real (usuário)",
        color="steelblue",
    )
    bars2 = ax.bar(
        [i + 0.2 for i in x],
        freq_obs,
        width=0.38,
        label="Padrão de acesso (servidor)",
        color="tomato",
    )
    ax.set_xticks(list(x))
    ax.set_xticklabels(words)
    ax.set_ylabel("Frequência relativa")
    ax.set_title(
        "Vazamento por frequência de acesso\n"
        "(servidor honest-but-curious infere frequências sem decifrar os dados)"
    )
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    plt.tight_layout()

    out = os.path.join(ROOT_DIR, "grafico_vazamento.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"\nGráfico salvo em: grafico_vazamento.png\n")
    print(
        "  Observação: as barras vermelhas (padrão do servidor) refletem\n"
        "  as barras azuis (frequência real), demonstrando o vazamento\n"
        "  por padrão de acesso descrito em Song et al. (2000, Seção 5.5).\n"
    )


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ok = experiment_correctness()
    experiment_performance()
    experiment_leakage()

    if ok:
        print("=" * 60)
        print("Todos os experimentos concluídos com sucesso.")
        print("=" * 60)
    else:
        print("ERRO: experimento de corretude falhou.")
        sys.exit(1)
