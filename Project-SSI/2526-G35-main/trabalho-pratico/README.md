# Repositório SSI 25/26

- A106900 - João Tomás Maciel Sousa
- A106926 - José Dinis Guimarães Machado
- A107332 - Pedro Afonso Quesado Pacheco Pereira

### Guiões Práticos

Estes devem ser colocados na diretoria `guioes`, dentro da semana correspondente (`S3`, `S4`, etc.).

### Trabalho Prático

Este deverá ser depositado dentro da diretoria `trabalho-pratico`.


# Chat Seguro E2EE — Projeto de Segurança de Sistemas Informáticos

Sistema de conversação com cifragem End-to-End (E2EE) implementado em Python, utilizando a biblioteca `cryptography`.

## Funcionalidades

### Chat em Tempo Real
- Mensagens 1-para-1 cifradas com Forward Secrecy
- Grupos de chat com chave AES partilhada
- Notificações de mensagens não lidas
- Lista de utilizadores online

### Modo PGP-like (sem servidor)
- Exportar mensagens cifradas para ficheiro `.pgp`
- Importar e decifrar ficheiros `.pgp` recebidos
- Comunicação sem dependência do servidor

## Instalação

```bash
# Clonar o repositório
git clone <url-do-repositorio>
cd trabalho-pratico

# Instalar dependências
pip install cryptography

# Gerar identidades dos utilizadores
python3 gerar_chaves.py
```

## Como Correr

**Terminal 1 — Servidor:**
```bash
python3 server.py
```

**Terminal 2 — Cliente Alice:**
```bash
python3 client.py
# Introduz o ID: alice
```

**Terminal 3 — Cliente Bob:**
```bash
python3 client.py
# Introduz o ID: bob
```

## Comandos Disponíveis

| Comando | Descrição |
|---|---|
| `/conectar <nome>` | Abre chat seguro com outro utilizador |
| `/lista` | Mostra utilizadores online |
| `/grupo criar <nome>` | Cria um grupo de chat |
| `/grupo add <nome> <membro>` | Adiciona membro ao grupo |
| `/grupo entrar <nome>` | Entra no chat de grupo |
| `/grupo sair` | Sai do chat de grupo atual |
| `/grupo lista` | Lista grupos a que pertences |
| `/exportar <nome> <msg>` | Cria ficheiro .pgp (sem servidor) |
| `/importar <ficheiro.pgp>` | Lê e decifra ficheiro .pgp |
| `/sair` | Fecha a aplicação |

## Arquitetura de Segurança

### Primitivas Criptográficas
- **AES-256-GCM** — Cifragem das mensagens (confidencialidade + integridade)
- **RSA-2048 + OAEP** — Encapsulamento de chaves simétricas
- **RSA-PSS + SHA-256** — Assinaturas digitais (autenticidade)
- **ECDH X25519** — Troca de chaves efémeras (Forward Secrecy)
- **HKDF-SHA256** — Derivação de chaves de sessão

### Modelo de Segurança
- **Servidor honesto mas curioso** — nunca consegue ler o conteúdo das mensagens
- **Autenticação mútua** — protocolo Challenge-Response entre cliente e servidor
- **Anti-replay** — nonces únicos por mensagem, janela de 5 minutos
- **Forward Secrecy** — chaves ECDH efémeras destruídas após cada sessão

## Valorizações Implementadas

### 1. Mensagens Offline
O servidor armazena mensagens cifradas em `mensagens_offline.json` quando o destinatário está desligado. As mensagens são entregues automaticamente quando o utilizador se liga.

### 2. PKI / Entidade de Certificação
O servidor age como CA self-signed. Cada utilizador recebe um certificado digital assinado pelo servidor no momento do registo. Validade: 1 ano.

### 3. Forward Secrecy
Protocolo ECDH X25519 efémero entre clientes. As chaves são destruídas após o cálculo do segredo partilhado — comunicações passadas ficam protegidas mesmo se a chave RSA for comprometida.

### 4. Mensagens de Grupo
Chave AES de grupo gerada pelo criador e distribuída a cada membro individualmente, cifrada com a sua chave RSA pública. O servidor nunca tem acesso à chave do grupo.

### 5. Modo PGP-like (Descentralizado)
Comunicação sem servidor através de ficheiros `.pgp`. O envelope contém a mensagem cifrada, a chave AES cifrada com RSA do destinatário e a assinatura do remetente.

## Estrutura do Projeto

```
trabalho-pratico/
├── client.py          # Interface do utilizador
├── server.py          # Servidor central
├── seguranca.py       # Primitivas criptográficas
├── utils.py           # Utilitários de rede
├── gerar_chaves.py    # Gerador de identidades RSA
├── chaves_publicas/   # Chaves públicas dos utilizadores
└── README.md
```

## Ficheiros Gerados Automaticamente

Os seguintes ficheiros são criados automaticamente e **não devem ser submetidos** no repositório:

- `chaves_privadas/` — Chaves privadas (segredos)
- `mensagens_offline.json` — Mensagens pendentes
- `certificados.json` — Certificados PKI emitidos
- `grupos.json` — Estado dos grupos

## Dependências

```
cryptography>=41.0.0
```