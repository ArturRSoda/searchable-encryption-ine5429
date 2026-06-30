# Searchable Encryption — INE5429

Implementação do esquema de busca em dados cifrados proposto por Song, Wagner e Perrig (2000), desenvolvido como trabalho da disciplina INE5429 — Segurança em Computação da UFSC.

## Integrantes

- Artur Luiz Rizzato Toru Soda (22200349)
- Davi Menegaz Junkes (22200354)
- Matheus Fernandes Bigolin (22200371)

## Referência principal

Dawn Xiaodong Song, D. Wagner and A. Perrig, "Practical techniques for searches on encrypted data," *2000 IEEE Symposium on Security and Privacy*, Berkeley, CA, USA, 2000, pp. 44–55.

## Estrutura do projeto

```
src/
├── sse.py          # Implementação dos algoritmos (KeyGen, Encrypt, Trapdoor, Search, Decrypt)
├── demo.py         # Mini-exemplo concreto com valores de entrada/saída
└── experiments.py  # Experimentos: corretude, desempenho e vazamento por frequência
```

## Como executar

### Pré-requisitos

Python 3.10+ e pip.

### Instalação das dependências

```bash
pip install -r requirements.txt
```

### Executar o mini-exemplo

```bash
python src/demo.py
```

### Executar os experimentos

```bash
python src/experiments.py
```

Os gráficos serão salvos na pasta raiz do projeto:
- `grafico_desempenho.png` — tempo de busca × tamanho do documento
- `grafico_vazamento.png` — frequência real × padrão de acesso observado pelo servidor
