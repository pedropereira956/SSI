# SSI

Markdown

# Projeto SSI - G35

Comunicação cliente-servidor segura com criptografia em Python.

---

## 🗂️ Estrutura do Repositório

* **`/guioes`**: Exercícios das aulas práticas (S3 a S11) abordando vulnerabilidades e criptografia.
* **`/trabalho-pratico`**: Código-fonte principal da aplicação cliente-servidor segura (inclui cliente, servidor e geração de chaves).

---

## 🚀 Como Executar o Programa

Para iniciares, abre o terminal e acede à diretoria do projeto prático:
```bash
cd trabalho-pratico

1️⃣ Gerar as chaves criptográficas

Antes de mais, é obrigatório gerar as chaves públicas e privadas (serão guardadas na pasta chaves_publicas/):
Bash

python3 gerar_chaves.py

2️⃣ Iniciar o servidor

No mesmo terminal, inicie o processo do servidor para que este fique à escuta de novas ligações:
Bash

python3 server.py

3️⃣ Iniciar o cliente

Abre um novo terminal, navega novamente para a pasta trabalho-pratico e inicia a interface do cliente:
Bash

cd trabalho-pratico
python3 client.py
