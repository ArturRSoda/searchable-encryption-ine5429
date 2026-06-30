# Searchable Symmetric Encryption — Song, Wagner e Perrig (2000)
# Esquema IV: busca oculta (hidden search) com varredura sequencial
#
# Parâmetros:
#   n = 128 bits (16 bytes) — tamanho do bloco, alinhado ao AES-128
#   m =  64 bits  (8 bytes) — bits de verificação do PRF
#   L =  64 bits  (8 bytes) — n - m, usado para derivar k_i
#
# Primitivas:
#   E  = AES-128 ECB  (cifra determinística para pré-cifrar palavras)
#   f  = HMAC-SHA256 truncado para 16 bytes  (deriva k_i a partir de L_i)
#   F  = HMAC-SHA256 truncado para  8 bytes  (verificação no servidor)
#   G  = AES-128 CTR  (PRG para gerar a sequência S_1 … S_l)

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Parâmetros globais
# ---------------------------------------------------------------------------

N_BYTES = 16   # tamanho de cada bloco (n = 128 bits)
M_BYTES = 8    # bits de verificação  (m =  64 bits)
L_BYTES = 8    # N_BYTES - M_BYTES    (L =  64 bits)

# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def pad_word(word: str) -> bytes:
    """Converte uma string para um bloco de N_BYTES.
    Trunca se maior que N_BYTES; completa com \\x00 se menor."""
    b = word.encode("utf-8")
    return b[:N_BYTES].ljust(N_BYTES, b"\x00")


def unpad_word(block: bytes) -> str:
    """Remove o padding \\x00 e decodifica para string."""
    return block.rstrip(b"\x00").decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Primitivas criptográficas
# ---------------------------------------------------------------------------

def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """E(key, block): AES-128 ECB — cifra determinística."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def _aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    """E⁻¹(key, block): AES-128 ECB inverso."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(block) + dec.finalize()


def _prf_f(k_prime: bytes, data: bytes) -> bytes:
    """f(k', data): HMAC-SHA256 truncado para N_BYTES (16 bytes).
    Usado para derivar k_i a partir de L_i."""
    h = hmac.HMAC(k_prime, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()[:N_BYTES]


def _prf_F(k_i: bytes, s: bytes) -> bytes:
    """F(k_i, s): HMAC-SHA256 truncado para M_BYTES (8 bytes).
    Usado pelo servidor para verificar se um bloco é match."""
    h = hmac.HMAC(k_i, hashes.SHA256(), backend=default_backend())
    h.update(s)
    return h.finalize()[:M_BYTES]


def _prg(k_seed: bytes, count: int) -> list[bytes]:
    """G(k_seed, count): gera `count` valores S_i de L_BYTES cada.
    Usa AES-128 CTR com IV zero como gerador pseudo-aleatório."""
    nonce = b"\x00" * 16
    cipher = Cipher(
        algorithms.AES(k_seed), modes.CTR(nonce), backend=default_backend()
    )
    enc = cipher.encryptor()
    stream = enc.update(b"\x00" * (L_BYTES * count)) + enc.finalize()
    return [stream[i * L_BYTES : (i + 1) * L_BYTES] for i in range(count)]


# ---------------------------------------------------------------------------
# Algoritmos principais
# ---------------------------------------------------------------------------

def keygen() -> tuple[bytes, bytes, bytes]:
    """KeyGen(λ): gera o trio de chaves secretas do esquema.

    Retorna:
        k_seed        — semente do PRG G (gera a sequência S_i)
        k_prime       — chave de f (deriva k_i a partir de L_i)
        k_doubleprime — chave de E (pré-cifra determinística das palavras)
    """
    k_seed        = os.urandom(N_BYTES)
    k_prime       = os.urandom(N_BYTES)
    k_doubleprime = os.urandom(N_BYTES)
    return k_seed, k_prime, k_doubleprime


def encrypt(K: tuple, document: list[str]) -> list[bytes]:
    """Encrypt(K, D): cifra cada palavra do documento.

    Para cada palavra W_i:
        X_i = E(k'', W_i)              pré-cifra determinística
        L_i = X_i[:L_BYTES]            parte esquerda
        k_i = f(k', L_i)              chave de mascaramento do bloco i
        T_i = S_i || F(k_i, S_i)      token pseudo-aleatório com estrutura especial
        C_i = X_i XOR T_i             ciphertext final

    Retorna:
        Lista de blocos C_i (bytes), um por palavra.
    """
    k_seed, k_prime, k_doubleprime = K
    S_values = _prg(k_seed, len(document))
    C = []
    for i, word in enumerate(document):
        W_i = pad_word(word)
        X_i = _aes_ecb_encrypt(k_doubleprime, W_i)
        L_i = X_i[:L_BYTES]
        k_i = _prf_f(k_prime, L_i)
        S_i = S_values[i]
        T_i = S_i + _prf_F(k_i, S_i)                        # S_i || F(k_i, S_i)
        C_i = bytes(a ^ b for a, b in zip(X_i, T_i))        # X_i XOR T_i
        C.append(C_i)
    return C


def trapdoor(K: tuple, word: str) -> tuple[bytes, bytes]:
    """Trapdoor(K, W): gera o par de busca (X, k) para enviar ao servidor.

    O servidor recebe (X, k) e consegue verificar matches sem aprender W.

    Retorna:
        (X, k) onde X = E(k'', W) e k = f(k', L) com L = X[:L_BYTES]
    """
    _, k_prime, k_doubleprime = K
    X = _aes_ecb_encrypt(k_doubleprime, pad_word(word))
    L = X[:L_BYTES]
    k = _prf_f(k_prime, L)
    return X, k


def search(C: list[bytes], trap: tuple[bytes, bytes]) -> list[int]:
    """Search(C, T_W): executado pelo servidor sobre o ciphertext.

    Para cada bloco C_i, calcula V = C_i XOR X e verifica se
    os últimos M_BYTES de V são iguais a F(k, primeiros_L_BYTES_de_V).
    Se sim, a posição i é retornada como candidata.

    Retorna:
        Lista de índices onde a palavra pode estar (pode incluir falsos positivos).
    """
    X, k = trap
    positions = []
    for i, C_i in enumerate(C):
        V   = bytes(a ^ b for a, b in zip(C_i, X))
        s   = V[:L_BYTES]
        chk = V[L_BYTES:]
        if _prf_F(k, s) == chk:
            positions.append(i)
    return positions


def decrypt(K: tuple, C: list[bytes]) -> list[str]:
    """Decrypt(K, C): recupera as palavras originais a partir do ciphertext.

    Para cada bloco C_i:
        S_i  = G(k_seed)[i]
        L_i  = C_i[:L_BYTES] XOR S_i
        k_i  = f(k', L_i)
        R_i  = C_i[L_BYTES:] XOR F(k_i, S_i)
        X_i  = L_i || R_i
        W_i  = E⁻¹(k'', X_i)

    Retorna:
        Lista de strings com as palavras decifradas.
    """
    k_seed, k_prime, k_doubleprime = K
    S_values = _prg(k_seed, len(C))
    words = []
    for i, C_i in enumerate(C):
        S_i = S_values[i]
        L_i = bytes(a ^ b for a, b in zip(C_i[:L_BYTES], S_i))
        k_i = _prf_f(k_prime, L_i)
        R_i = bytes(a ^ b for a, b in zip(C_i[L_BYTES:], _prf_F(k_i, S_i)))
        X_i = L_i + R_i
        W_i = _aes_ecb_decrypt(k_doubleprime, X_i)
        words.append(unpad_word(W_i))
    return words
