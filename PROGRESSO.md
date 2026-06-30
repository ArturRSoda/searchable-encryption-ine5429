# Progresso do trabalho - Searchable Encryption

INE5429 - Segurança em Computação  
Artur Luiz Rizzato Toru Soda, Davi Menegaz Junkes, Matheus Fernandes Bigolin

---

Esse documento resume o que foi feito até agora no trabalho. A ideia é que todo mundo do grupo leia, entenda o que foi implementado e o que cada parte faz, e aí a gente decide juntos se está bom para partir pro relatório final.

## O que foi feito até agora

O código está todo implementado e funcionando. Temos três arquivos em `src/`:

- `sse.py` — implementação dos 5 algoritmos do esquema
- `demo.py` — exemplo concreto rodando os algoritmos passo a passo
- `experiments.py` — três experimentos com resultados e gráficos

Para rodar tudo:

```bash
pip install -r requirements.txt
python src/demo.py
python src/experiments.py
```

---

## O problema que o trabalho resolve

Antes de entrar no código, vale lembrar o problema que a gente está resolvendo, porque ele é o coração do trabalho.

Imagina que você tem documentos com informações sensíveis e quer guardar tudo na nuvem. A solução óbvia pra proteger a privacidade é cifrar os documentos antes de mandar pro servidor. Mas aí surge um problema: quando você precisar buscar alguma coisa nesses documentos, como faz? Baixar tudo, decifrar localmente e então buscar não faz sentido, porque anula a vantagem de usar um servidor externo.

Searchable Encryption resolve esse problema: o servidor consegue buscar palavras nos dados cifrados sem precisar decifrá-los, e sem aprender qual palavra você buscou.

O algoritmo que implementamos é o de Song, Wagner e Perrig (2000), que foi o primeiro esquema com esse objetivo a ter provas formais de segurança. A ideia central é cifrar cada palavra do documento com uma estrutura matemática especial embutida no ciphertext. Essa estrutura permite que o servidor verifique se uma palavra está presente, sem aprender o que a palavra é.

---

## Como o algoritmo funciona

O esquema tem cinco operações. Aqui estão elas explicadas de forma direta:

**KeyGen** gera três chaves secretas que ficam com o usuário:
- `k_seed`: semente de um gerador pseudo-aleatório
- `k'`: chave de uma função pseudo-aleatória usada internamente
- `k''`: chave de uma cifra simétrica usada para pré-cifrar as palavras

**Encrypt** cifra o documento palavra por palavra. Para cada palavra `W_i`, o processo é:
1. Cifrar a palavra com AES: `X_i = E(k'', W_i)`
2. Dividir `X_i` em duas metades: `L_i` (64 bits) e `R_i` (64 bits)
3. Gerar um valor pseudo-aleatório `S_i` a partir de `k_seed`
4. Calcular `k_i = f(k', L_i)` e `P_i = F(k_i, S_i)`
5. Montar `T_i = S_i || P_i` e calcular `C_i = X_i XOR T_i`

O `C_i` é o que vai pro servidor. Parece barulho aleatório.

**Trapdoor** gera o token de busca para uma palavra `W` sem revelar `W`:
- Calcula `X = E(k'', W)` e `k = f(k', X[:8])`
- Manda o par `(X, k)` pro servidor

**Search** é executado pelo servidor. Para cada bloco `C_i`, ele calcula `V = C_i XOR X` e verifica se os últimos 8 bytes de `V` batem com `F(k, V[:8])`. Se bater, aquela posição é um match.

O ponto chave é que essa verificação só funciona quando `W_i == W`, porque só aí o XOR cancela a pré-cifra e deixa a estrutura `(S_i, F(k_i, S_i))` visível. O servidor não precisa saber `W` pra fazer essa conta.

**Decrypt** usa as chaves pra desfazer tudo e recuperar o documento original.

---

## Implementação (`sse.py`)

As primitivas usadas são:

| Operação | Primitiva | Biblioteca |
|---|---|---|
| E (cifra determinística) | AES-128 ECB | cryptography |
| f (derivar k_i) | HMAC-SHA256 truncado para 16 bytes | cryptography |
| F (verificação) | HMAC-SHA256 truncado para 8 bytes | cryptography |
| G (gerador S_i) | AES-128 CTR com IV zero | cryptography |

Usamos AES-ECB pra `E` porque precisa ser determinístico: a mesma palavra sempre produz o mesmo `X_i`, independente da posição. Isso é necessário pra que o trapdoor funcione em qualquer posição do documento.

O tamanho do bloco é `n = 128 bits` (16 bytes), com `m = 64 bits` para verificação. A taxa de falso positivo é `1/2^64` por posição, o que é desprezível na prática.

O código completo está em `src/sse.py`. Abaixo as assinaturas das funções:

```python
def keygen() -> tuple[bytes, bytes, bytes]
def encrypt(K, document: list[str]) -> list[bytes]
def trapdoor(K, word: str) -> tuple[bytes, bytes]
def search(C: list[bytes], trap: tuple[bytes, bytes]) -> list[int]
def decrypt(K, C: list[bytes]) -> list[str]
```

---

## Mini-exemplo (`demo.py`)

Rodamos o esquema no documento `["the", "cat", "sat", "on", "the", "mat"]` e mostramos cada valor intermediário. Abaixo está o output completo de uma execução:

```
==============================================================
Mini-exemplo - Searchable Encryption (Song et al., 2000)
==============================================================

Documento de entrada: ['the', 'cat', 'sat', 'on', 'the', 'mat']
Parametros: n=128 bits, m=64 bits, L=64 bits

==============================================================
KeyGen
==============================================================
  k_seed  (PRG)  = ebcaa1a50d8dda82 5592931d32ecf516
  k'      (f)    = 6dfc6551bc6c8548 fb141965eaccfd3e
  k''     (E)    = f638607a7f6d3df6 e12c3454d442f149

==============================================================
Encrypt - passo a passo para "cat" (posicao 1)
==============================================================
  W_1  (plaintext, com padding)  = 6361740000000000 0000000000000000
       ("cat" + 13 bytes \x00)

  X_1  = E(k'', W_1)            = c72fe676b0f5cca5 47bc601746ac02d5
  L_1  = X_1[:8]                = c72fe676b0f5cca5
  R_1  = X_1[8:]                = 47bc601746ac02d5

  S_1  = G(k_seed)[1]           = 4a854df46c69f653
  k_1  = f(k', L_1)             = 87b25aa5b62cec8a 596fc66d885c5786
  P_1  = F(k_1, S_1)            = 9a3adc38b890a198
  T_1  = S_1 || P_1             = 4a854df46c69f653 9a3adc38b890a198

  C_1  = X_1 XOR T_1            = 8daaab82dc9c3af6 dd86bc2ffe3ca34d

==============================================================
Encrypt - todos os blocos
==============================================================
  C[0]  "the"  ->  eb6de9d830b6a889 59f9b4b52d90b86a
  C[1]  "cat"  ->  8daaab82dc9c3af6 dd86bc2ffe3ca34d
  C[2]  "sat"  ->  b1915b9b29933112 fe2a8562327f331d
  C[3]  "on"   ->  11a16a04a238abb0 23bfc06d267c9b6b
  C[4]  "the"  ->  170b562afc654a00 881511d34d313758
  C[5]  "mat"  ->  ff74fda8fddf9d85 ff09a6f626a3c531

==============================================================
Trapdoor para "cat"
==============================================================
  X  = c72fe676b0f5cca5 47bc601746ac02d5
  k  = 87b25aa5b62cec8a 596fc66d885c5786
  Token enviado ao servidor: (X, k)

==============================================================
Search
==============================================================
  Busca "cat"  ->  posicoes [1]    (esperado [1])    [OK]
  Busca "the"  ->  posicoes [0, 4] (esperado [0, 4]) [OK]
  Busca "sat"  ->  posicoes [2]    (esperado [2])    [OK]
  Busca "dog"  ->  posicoes []     (esperado [])     [OK]

==============================================================
Decrypt
==============================================================
  posicao 0: "the"  [OK]
  posicao 1: "cat"  [OK]
  posicao 2: "sat"  [OK]
  posicao 3: "on"   [OK]
  posicao 4: "the"  [OK]
  posicao 5: "mat"  [OK]

==============================================================
Sigilo provavel: "the" aparece nas posicoes 0 e 4
==============================================================
  C[0]  = eb6de9d830b6a889 59f9b4b52d90b86a
  C[4]  = 170b562afc654a00 881511d34d313758

  Os dois ciphertexts sao iguais? False

  Mesmo que a palavra seja identica, cada posicao recebe um valor
  S_i diferente gerado pelo PRG. O resultado e que o servidor ve
  dois blocos completamente distintos e nao tem como saber que
  ambos correspondem a mesma palavra.

==============================================================
Consulta oculta: o que o servidor recebe ao buscar "cat"
==============================================================
  X  = c72fe676b0f5cca5 47bc601746ac02d5
  k  = 87b25aa5b62cec8a 596fc66d885c5786

  O servidor recebe apenas esses dois valores. Sem a chave k''
  e impossivel recuperar "cat" a partir de X, pois X = E(k'', "cat")
  e AES sem a chave e computacionalmente inviavel de reverter.
```

Tem alguns pontos que vale destacar na saída acima para a discussão no relatório:

**A palavra "cat" em ASCII é `63 61 74`** (os primeiros 3 bytes de `W_1`). Depois vêm 13 bytes `00` de padding pra completar o bloco de 16 bytes. O valor `X_1 = E(k'', W_1)` já não tem nenhuma relação visual com "cat": é o AES com a chave `k''` aplicado ao bloco.

**O ciphertext `C_1` é o XOR de `X_1` com `T_1`**. O `T_1` é composto por `S_1` (aleatório, diferente pra cada posição) concatenado com `F(k_1, S_1)`. Essa é a estrutura especial que permite a busca: quando o servidor faz `C_i XOR X` com o trapdoor correto, o `X_i` é cancelado e aparece a estrutura `(S_i, F(k_i, S_i))`, que o servidor consegue verificar.

**A seção de sigilo provável** mostra que C[0] e C[4] são completamente diferentes, mesmo ambos sendo ciphertexts de "the". Isso é garantido pelos valores `S_0` e `S_4` que são diferentes, então o XOR final produz resultados distintos.

---

## Experimentos (`experiments.py`)

### Experimento 1 - Corretude

Testamos cinco situações para verificar que o código funciona corretamente:

```
Caso                                   Esperado               Obtido                 Status
--------------------------------------------------------------------------------------------
"target" (existe, 3 ocorrencias)       [42, 150, 275]         [42, 150, 275]         OK
"qwerty" (nao existe)                  []                     []                     OK
"cloud" (multiplas ocorrencias)        [1, 2, 9, 13, 16]...   [1, 2, 9, 13, 16]...   OK
Decriptacao completa (300 palavras)    igual ao original      igual ao original      OK
Chave errada (isolamento de consulta)  []                     []                     OK
```

O quinto caso é importante: tentamos usar o trapdoor gerado com uma chave para buscar no ciphertext gerado com outra chave. O resultado é vazio, como esperado. Isso confirma que só o dono das chaves consegue gerar trapdoors válidos.

### Experimento 2 - Desempenho

Medimos o tempo médio de busca para documentos de tamanhos crescentes:

```
n =    500 palavras  ->   1.8 ms por busca
n =   1000 palavras  ->   3.6 ms por busca
n =   2000 palavras  ->   7.3 ms por busca
n =   5000 palavras  ->  18.3 ms por busca
n =  10000 palavras  ->  35.8 ms por busca
n =  25000 palavras  ->  90.3 ms por busca
n =  50000 palavras  -> 180.8 ms por busca
```

O gráfico abaixo mostra o comportamento:

![Grafico de desempenho](grafico_desempenho.png)

O tempo cresce de forma perfeitamente linear, confirmando o O(n) que o paper afirma. Dobrar o número de palavras dobra o tempo de busca. Isso faz sentido: o algoritmo de busca percorre todos os blocos uma vez, sem atalhos.

### Experimento 3 - Vazamento por frequência de acesso

Esse experimento mostra a principal limitação do esquema. Criamos um documento onde as palavras têm frequências bem diferentes, depois simulamos 300 buscas com probabilidade proporcional a essas frequências, e vimos o que o servidor consegue inferir observando apenas quantas posições são retornadas em cada busca.

```
Palavra      Freq. real  Padrao servidor
----------------------------------------
cloud            32.5%           45.2%
data             24.4%           29.6%
secure           16.3%           10.9%
encrypt          12.2%            9.5%
search            8.1%            3.4%
server            4.9%            1.3%
private           1.6%            0.1%
```

![Grafico de vazamento](grafico_vazamento.png)

A ordem das palavras por frequência é preservada: o que é mais comum segundo o usuário também aparece com mais frequência no padrão de acesso do servidor. Sem decifrar nada, o servidor já consegue construir um ranking aproximado das palavras mais usadas. Isso é chamado de vazamento por padrão de acesso (*access pattern leakage*) e é a razão principal pela qual pesquisas posteriores desenvolveram esquemas mais sofisticados.

---

## O que falta fazer

A implementação está completa. O que ainda precisamos fazer é o relatório final, que deve:

1. Atualizar a seção de introdução (pequena adição mencionando que a implementação foi concluída)
2. Adicionar o mini-exemplo do `demo.py` na seção de desenvolvimento
3. Escrever a seção de implementação descrevendo as escolhas técnicas
4. Escrever a seção de resultados experimentais com os gráficos e análise
5. Escrever a conclusão
6. Adicionar a declaração de uso de IA nas referências

O prazo é 05/07.
