import os
import time
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================================
# 1. GESTÃO DE CHAVES RSA (Identidades)
# ==========================================
def gerar_chaves_rsa(nome_utilizador, password=None):
    """
    Gera um novo par de chaves RSA e guarda nos ficheiros PEM.
    Se password for fornecida, a chave privada é protegida com AES-256-CBC.
    """
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    chave_publica = chave_privada.public_key()

    os.makedirs("chaves_privadas", exist_ok=True)
    os.makedirs("chaves_publicas", exist_ok=True)

    # Proteger chave privada com password se fornecida
    if password:
        if isinstance(password, str):
            password = password.encode('utf-8')
        algoritmo_cifra = serialization.BestAvailableEncryption(password)
    else:
        algoritmo_cifra = serialization.NoEncryption()

    pem_privada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algoritmo_cifra
    )
    with open(f"chaves_privadas/{nome_utilizador}_privada.pem", "wb") as f:
        f.write(pem_privada)

    pem_publica = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"chaves_publicas/{nome_utilizador}_publica.pem", "wb") as f:
        f.write(pem_publica)


def carregar_chave_privada(nome_utilizador, password=None):
    """
    Carrega a chave privada do disco.
    Se a chave foi gerada com password, deve ser fornecida aqui.
    """
    if password and isinstance(password, str):
        password = password.encode('utf-8')
    with open(f"chaves_privadas/{nome_utilizador}_privada.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def carregar_chave_publica(nome_utilizador):
    with open(f"chaves_publicas/{nome_utilizador}_publica.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


def chave_publica_para_bytes(chave_publica):
    """Serializa uma chave pública para bytes PEM (para enviar pela rede)."""
    return chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def bytes_para_chave_publica(pem_bytes):
    """Desserializa bytes PEM para objeto de chave pública."""
    return serialization.load_pem_public_key(pem_bytes)


# ==========================================
# 2. ASSINATURAS DIGITAIS (Autenticidade)
# ==========================================
def assinar_dados(chave_privada_rsa, dados_bytes):
    """Assina os dados para provar quem enviou."""
    return chave_privada_rsa.sign(
        dados_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def verificar_assinatura(chave_publica_rsa, assinatura, dados_bytes):
    """Verifica se quem enviou foi mesmo o dono da chave pública."""
    try:
        chave_publica_rsa.verify(
            assinatura,
            dados_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ==========================================
# 3. ENCAPSULAMENTO DE CHAVE (O "Envelope" RSA)
# ==========================================
def cifrar_chave_aes_com_rsa(chave_publica_destino, chave_aes):
    """Cifra a chave simétrica com a chave pública do destinatário usando OAEP."""
    return chave_publica_destino.encrypt(
        chave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decifrar_chave_aes_com_rsa(chave_privada_minha, chave_aes_cifrada):
    """Usa a tua chave privada para abrir o envelope e tirar a chave AES."""
    return chave_privada_minha.decrypt(
        chave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ==========================================
# 4. CIFRAGEM DAS MENSAGENS (AES-GCM)
# ==========================================
def gerar_chave_aes_aleatoria():
    """Gera uma chave AES de 256-bits (32 bytes) para UMA única mensagem."""
    return os.urandom(32)


def cifrar_mensagem(chave_aes, mensagem_bytes):
    """
    Cifra os dados com AES-GCM.
    Aceita bytes diretamente (funciona para texto E ficheiros).
    """
    aesgcm = AESGCM(chave_aes)
    nonce = os.urandom(12)
    if isinstance(mensagem_bytes, str):
        mensagem_bytes = mensagem_bytes.encode('utf-8')
    dados_cifrados = aesgcm.encrypt(nonce, mensagem_bytes, None)
    return nonce + dados_cifrados


def decifrar_mensagem(chave_aes, pacote_cifrado):
    """Decifra o texto da mensagem e devolve string."""
    aesgcm = AESGCM(chave_aes)
    nonce = pacote_cifrado[:12]
    dados_cifrados = pacote_cifrado[12:]
    return aesgcm.decrypt(nonce, dados_cifrados, None).decode('utf-8')


def decifrar_bytes(chave_aes, pacote_cifrado):
    """Decifra e devolve bytes puros (para ficheiros)."""
    aesgcm = AESGCM(chave_aes)
    nonce = pacote_cifrado[:12]
    dados_cifrados = pacote_cifrado[12:]
    return aesgcm.decrypt(nonce, dados_cifrados, None)


# ==========================================
# 5. AUTENTICAÇÃO MÚTUA CLIENTE-SERVIDOR
#    Protocolo Challenge-Response com Timestamp
# ==========================================
def gerar_desafio():
    """
    Gera um desafio aleatório com timestamp embutido.
    Formato: 28 bytes aleatórios + 4 bytes timestamp (big-endian).
    """
    nonce = os.urandom(28)
    ts = int(time.time()).to_bytes(4, 'big')
    return nonce + ts  # 32 bytes total


def assinar_desafio(chave_privada, desafio_bytes):
    """Assina o desafio recebido para provar posse da chave privada."""
    return assinar_dados(chave_privada, desafio_bytes)


def verificar_resposta_desafio(chave_publica, desafio_bytes, assinatura, janela_segundos=30):
    """
    Verifica a autenticidade e frescura da resposta ao desafio.
    Retorna (True, "OK") ou (False, "motivo do erro").
    """
    ts_bytes = desafio_bytes[-4:]
    ts = int.from_bytes(ts_bytes, 'big')
    agora = int(time.time())

    if abs(agora - ts) > janela_segundos:
        return False, "Desafio expirado (possível replay attack)"

    if not verificar_assinatura(chave_publica, assinatura, desafio_bytes):
        return False, "Assinatura inválida — servidor/cliente não autenticado"

    return True, "OK"


# ==========================================
# 6. PROTEÇÃO ANTI-REPLAY DAS MENSAGENS
# ==========================================
class AntiReplay:
    """
    Guarda registo dos nonces de mensagens já processadas.
    Previne que um atacante reenvie um pacote cifrado capturado.
    """
    def __init__(self):
        self._vistos = {}  # nonce_hex -> timestamp_de_receção

    def verificar_e_registar(self, nonce_bytes):
        """
        Retorna True se o nonce é NOVO (mensagem legítima).
        Retorna False se já foi visto (replay attack detectado).
        """
        agora = time.time()
        self._limpar(agora)
        chave = nonce_bytes.hex()
        if chave in self._vistos:
            return False  # REPLAY DETECTADO
        self._vistos[chave] = agora
        return True

    def _limpar(self, agora):
        """Remove nonces com mais de 5 minutos."""
        expirados = [k for k, t in self._vistos.items() if agora - t > 300]
        for k in expirados:
            del self._vistos[k]


# ==========================================
# 7. PKI — CERTIFICADOS DIGITAIS
#
#  O servidor age como CA (Autoridade de Certificação) self-signed.
#  Quando um utilizador se regista, o servidor emite um certificado
#  que associa o seu ID à sua chave pública, assinado pela CA.
#
#  Estrutura do certificado (JSON):
#  {
#    "id":         "alice",
#    "chave_pub":  "<PEM em base64>",
#    "emitido_em": 1234567890,
#    "valido_ate": 1234567890,
#    "versao":     1
#  }
#  + assinatura da CA sobre o JSON acima (bytes separados)
#
#  VANTAGEM sobre pré-partilha manual:
#  Antes: cada cliente precisava ter os ficheiros .pem de todos.
#  Agora: cada cliente só precisa da chave pública do servidor (CA).
#         Pede certificados ao servidor conforme necessário.
# ==========================================

VALIDADE_CERTIFICADO_DIAS = 365


def criar_certificado(id_utilizador, chave_publica, chave_privada_ca):
    """
    O servidor (CA) emite um certificado para um utilizador.
    Retorna (corpo_json_bytes, assinatura_bytes).

    Parâmetros:
      id_utilizador   - nome do utilizador (ex: "alice")
      chave_publica   - objeto de chave pública RSA do utilizador
      chave_privada_ca - chave privada do servidor (CA) para assinar
    """
    agora = int(time.time())
    valido_ate = agora + (VALIDADE_CERTIFICADO_DIAS * 24 * 3600)

    # Serializar a chave pública para string PEM (para guardar em JSON)
    pem_bytes = chave_publica_para_bytes(chave_publica)
    pem_str = pem_bytes.decode('utf-8')

    corpo = {
        "id": id_utilizador,
        "chave_pub": pem_str,
        "emitido_em": agora,
        "valido_ate": valido_ate,
        "versao": 1
    }

    # Serializar o corpo de forma determinística para assinar
    corpo_bytes = json.dumps(corpo, sort_keys=True).encode('utf-8')

    # CA assina o corpo do certificado
    assinatura = assinar_dados(chave_privada_ca, corpo_bytes)

    return corpo_bytes, assinatura


def verificar_certificado(corpo_bytes, assinatura, chave_publica_ca):
    """
    Verifica se um certificado foi emitido pela CA e se ainda é válido.
    Retorna (chave_publica_utilizador, id_utilizador) em caso de sucesso.
    Lança exceção se inválido.

    Parâmetros:
      corpo_bytes      - bytes JSON do certificado
      assinatura       - assinatura da CA
      chave_publica_ca - chave pública do servidor (CA) para verificar
    """
    # 1. Verificar assinatura da CA
    if not verificar_assinatura(chave_publica_ca, assinatura, corpo_bytes):
        raise ValueError("Certificado com assinatura inválida — não emitido pela CA!")

    # 2. Desserializar e verificar validade temporal
    corpo = json.loads(corpo_bytes.decode('utf-8'))
    agora = int(time.time())

    if agora > corpo["valido_ate"]:
        raise ValueError(f"Certificado de '{corpo['id']}' expirado!")

    if agora < corpo["emitido_em"]:
        raise ValueError(f"Certificado de '{corpo['id']}' com data futura — suspeito!")

    # 3. Extrair e devolver a chave pública do utilizador
    chave_pub = bytes_para_chave_publica(corpo["chave_pub"].encode('utf-8'))
    return chave_pub, corpo["id"]


def serializar_certificado_completo(corpo_bytes, assinatura):
    """
    Junta corpo + assinatura num único bloco de bytes para enviar pela rede.
    Formato: 4 bytes (tamanho do corpo) + corpo + assinatura
    """
    tamanho = len(corpo_bytes).to_bytes(4, 'big')
    return tamanho + corpo_bytes + assinatura


def desserializar_certificado_completo(dados):
    """
    Separa corpo e assinatura de um bloco serializado.
    Inverso de serializar_certificado_completo.
    """
    tamanho = int.from_bytes(dados[:4], 'big')
    corpo_bytes = dados[4:4 + tamanho]
    assinatura = dados[4 + tamanho:]
    return corpo_bytes, assinatura

# ==========================================
# 8. FORWARD SECRECY — ECDH X25519 EFÉMERO
#
#  Problema sem Forward Secrecy:
#    Se um atacante gravar mensagens cifradas hoje e descobrir
#    a chave RSA privada no futuro, consegue decifrar tudo.
#
#  Solução — ECDH Efémero (X25519):
#    Cada sessão gera um par de chaves X25519 temporário.
#    A chave AES é derivada via ECDH entre os dois pares.
#    No fim da sessão as chaves efémeras são destruídas.
#    Mesmo com a chave RSA, mensagens passadas ficam inacessíveis.
#
#  Protocolo entre Alice e Bob (servidor como relay):
#
#    Alice                 Servidor                 Bob
#      |                      |                      |
#      |-- FS_HELLO:pub_ecdh->|-- FS_HELLO:pub_ecdh->|
#      |                      |                      |
#      |<-FS_HELLO:pub_ecdh --|<-FS_HELLO:pub_ecdh --|
#      |                      |                      |
#    Ambos calculam segredo ECDH e derivam chave AES
#    Chaves efémeras destruídas após cálculo
# ==========================================
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def gerar_par_ecdh_efemero():
    """
    Gera um par de chaves X25519 efémero para uma sessão.
    Retorna (chave_privada, chave_publica_bytes).
    A chave privada NUNCA sai deste processo.
    """
    chave_privada = X25519PrivateKey.generate()
    chave_publica_bytes = chave_privada.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    return chave_privada, chave_publica_bytes  # 32 bytes cada


def calcular_segredo_ecdh(minha_chave_privada_efemera, pub_bytes_outro):
    """
    Calcula o segredo partilhado ECDH.
    O segredo é igual para ambos os lados sem nunca ser transmitido.
    """
    chave_pub_outro = X25519PublicKey.from_public_bytes(pub_bytes_outro)
    return minha_chave_privada_efemera.exchange(chave_pub_outro)


def derivar_chave_sessao(segredo_ecdh, info=b"chat-e2ee-sessao-v1"):
    """
    Deriva uma chave AES-256 a partir do segredo ECDH usando HKDF-SHA256.
    HKDF garante propriedades criptográficas fortes mesmo com bias no segredo.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    ).derive(segredo_ecdh)


def assinar_chave_ecdh(chave_privada_rsa, pub_ecdh_bytes, meu_id, id_destino):
    """
    Assina a chave pública ECDH com RSA para garantir autenticidade.
    Sem esta assinatura, um atacante podia substituir a chave ECDH (MITM).
    O que é assinado: pub_ecdh + id_remetente + id_destinatario
    """
    dados = pub_ecdh_bytes + meu_id.encode() + id_destino.encode()
    return assinar_dados(chave_privada_rsa, dados)


def verificar_chave_ecdh(chave_publica_rsa, pub_ecdh_bytes, id_remetente, id_destinatario, assinatura):
    """
    Verifica que a chave ECDH recebida foi gerada pelo remetente esperado.
    Retorna True se válida, False se suspeita de MITM.
    """
    dados = pub_ecdh_bytes + id_remetente.encode() + id_destinatario.encode()
    return verificar_assinatura(chave_publica_rsa, assinatura, dados)

# ==========================================
# 9. MODO PGP-LIKE — COMUNICAÇÃO SEM SERVIDOR
#
#  O modo PGP-like permite que dois utilizadores troquem
#  mensagens cifradas SEM precisar que o servidor esteja
#  a correr — ou seja, sem dependência absoluta do servidor.
#
#  Como funciona:
#  1. Alice cifra uma mensagem para Bob usando a chave pública
#     do Bob (que já tem no disco).
#  2. O resultado é um ficheiro .pgp que contém:
#     - A mensagem cifrada com AES-GCM
#     - A chave AES cifrada com RSA-OAEP da chave pública do Bob
#     - A assinatura RSA-PSS de Alice sobre tudo
#     - Metadados: remetente, destinatário, timestamp
#  3. Alice pode enviar este ficheiro por QUALQUER meio
#     (email, USB, Bluetooth, etc.) sem precisar do servidor.
#  4. Bob abre o ficheiro com o comando /importar e decifra
#     com a sua chave privada.
#
#  Garantias de segurança:
#  - Confidencialidade: só o Bob pode decifrar (RSA-OAEP)
#  - Autenticidade: assinatura de Alice garante origem
#  - Integridade: AES-GCM deteta qualquer alteração
#  - Não-repúdio: assinatura prova que foi Alice
# ==========================================

def cifrar_para_ficheiro_pgp(minha_chave_privada, meu_id,
                              chave_publica_destino, id_destino,
                              mensagem_texto):
    """
    Cria um envelope PGP-like para envio sem servidor.
    Retorna bytes prontos para guardar em ficheiro .pgp

    Estrutura do ficheiro:
    {
      "versao": 1,
      "remetente": "alice",
      "destinatario": "bob",
      "timestamp": 1234567890,
      "chave_aes_cifrada": "<hex>",
      "mensagem_cifrada": "<hex>",
      "assinatura": "<hex>"
    }
    """
    import json as _json

    # 1. Gerar chave AES efémera para esta mensagem
    chave_aes = gerar_chave_aes_aleatoria()

    # 2. Cifrar a mensagem com AES-GCM
    mensagem_cifrada = cifrar_mensagem(chave_aes, mensagem_texto)

    # 3. Cifrar a chave AES com RSA-OAEP do destinatário
    chave_aes_cifrada = cifrar_chave_aes_com_rsa(chave_publica_destino, chave_aes)

    # 4. Assinar: chave_aes_cifrada + mensagem_cifrada (garante integridade de tudo)
    dados_para_assinar = chave_aes_cifrada + mensagem_cifrada
    assinatura = assinar_dados(minha_chave_privada, dados_para_assinar)

    # 5. Montar o envelope JSON
    envelope = {
        "versao": 1,
        "remetente": meu_id,
        "destinatario": id_destino,
        "timestamp": int(time.time()),
        "chave_aes_cifrada": chave_aes_cifrada.hex(),
        "mensagem_cifrada": mensagem_cifrada.hex(),
        "assinatura": assinatura.hex()
    }

    return _json.dumps(envelope, indent=2).encode('utf-8')


def decifrar_ficheiro_pgp(minha_chave_privada, meu_id,
                           chave_publica_remetente, dados_ficheiro):
    """
    Decifra e verifica um ficheiro PGP-like recebido.
    Retorna (mensagem_texto, remetente, timestamp) em caso de sucesso.
    Lança exceção se inválido, adulterado ou não destinado a nós.

    Parâmetros:
      minha_chave_privada    - chave privada RSA do destinatário
      meu_id                 - ID do destinatário (para verificar)
      chave_publica_remetente - chave pública RSA do remetente
      dados_ficheiro         - bytes do ficheiro .pgp
    """
    import json as _json

    # 1. Ler e validar estrutura
    try:
        envelope = _json.loads(dados_ficheiro.decode('utf-8'))
    except Exception:
        raise ValueError("Ficheiro PGP inválido ou corrompido")

    if envelope.get("versao") != 1:
        raise ValueError("Versão de ficheiro PGP não suportada")

    # 2. Verificar que somos o destinatário correto
    if envelope.get("destinatario") != meu_id:
        raise ValueError(
            f"Este ficheiro é para '{envelope.get('destinatario')}', não para '{meu_id}'"
        )

    remetente = envelope.get("remetente", "desconhecido")
    timestamp = envelope.get("timestamp", 0)

    # 3. Desserializar campos
    try:
        chave_aes_cifrada = bytes.fromhex(envelope["chave_aes_cifrada"])
        mensagem_cifrada  = bytes.fromhex(envelope["mensagem_cifrada"])
        assinatura        = bytes.fromhex(envelope["assinatura"])
    except Exception:
        raise ValueError("Ficheiro PGP com campos inválidos")

    # 4. Verificar assinatura do remetente (autenticidade + integridade)
    dados_assinados = chave_aes_cifrada + mensagem_cifrada
    if not verificar_assinatura(chave_publica_remetente, assinatura, dados_assinados):
        raise ValueError(
            f"⚠️  Assinatura inválida! Ficheiro pode ter sido adulterado ou não é de '{remetente}'"
        )

    # 5. Decifrar a chave AES com a nossa chave privada
    try:
        chave_aes = decifrar_chave_aes_com_rsa(minha_chave_privada, chave_aes_cifrada)
    except Exception:
        raise ValueError("Não foi possível decifrar — este ficheiro não é para ti")

    # 6. Decifrar a mensagem
    try:
        mensagem_texto = decifrar_mensagem(chave_aes, mensagem_cifrada)
    except Exception:
        raise ValueError("Mensagem corrompida ou adulterada (falha AES-GCM)")

    return mensagem_texto, remetente, timestamp