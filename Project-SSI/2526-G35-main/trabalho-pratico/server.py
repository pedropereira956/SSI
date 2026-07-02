import socket
import threading
import json
import os
import utils
import seguranca

HOST = '127.0.0.1'
PORT = 65432
ARQUIVO_BD = 'mensagens_offline.json'
ARQUIVO_CERTIFICADOS = 'certificados.json'
ARQUIVO_GRUPOS = 'grupos.json'

# Nome reservado para a identidade do servidor (CA)
SERVIDOR_ID = "servidor"


# ==========================================
# GESTÃO DA BASE DE DADOS DE MENSAGENS (JSON)
# ==========================================
def carregar_base_dados():
    """Lê o ficheiro JSON ao arrancar e converte as mensagens (Hex) de volta para Bytes."""
    if not os.path.exists(ARQUIVO_BD):
        return {}
    try:
        with open(ARQUIVO_BD, 'r') as f:
            db_hex = json.load(f)
            db_bytes = {}
            for utilizador, msgs in db_hex.items():
                db_bytes[utilizador] = [bytes.fromhex(msg) for msg in msgs]
            return db_bytes
    except Exception as e:
        print(f"[AVISO] Erro ao carregar base de dados: {e}")
        return {}


def guardar_base_dados(dicionario_mensagens):
    """Grava as mensagens pendentes no ficheiro JSON (convertendo Bytes para Hex)."""
    db_hex = {}
    for utilizador, msgs in dicionario_mensagens.items():
        db_hex[utilizador] = [msg.hex() for msg in msgs]
    with open(ARQUIVO_BD, 'w') as f:
        json.dump(db_hex, f, indent=4)


# ==========================================
# GESTÃO DA BASE DE DADOS DE CERTIFICADOS PKI
# ==========================================
def carregar_certificados():
    """
    Carrega os certificados emitidos pela CA do disco.
    Formato: { "alice": { "corpo": "<hex>", "assinatura": "<hex>" }, ... }
    """
    if not os.path.exists(ARQUIVO_CERTIFICADOS):
        return {}
    try:
        with open(ARQUIVO_CERTIFICADOS, 'r') as f:
            dados = json.load(f)
            # Converter de hex para bytes
            certs = {}
            for uid, cert in dados.items():
                certs[uid] = {
                    'corpo': bytes.fromhex(cert['corpo']),
                    'assinatura': bytes.fromhex(cert['assinatura'])
                }
            return certs
    except Exception as e:
        print(f"[AVISO] Erro ao carregar certificados: {e}")
        return {}


def guardar_certificados(certs):
    """Grava os certificados no disco (convertendo bytes para hex)."""
    dados = {}
    for uid, cert in certs.items():
        dados[uid] = {
            'corpo': cert['corpo'].hex(),
            'assinatura': cert['assinatura'].hex()
        }
    with open(ARQUIVO_CERTIFICADOS, 'w') as f:
        json.dump(dados, f, indent=4)


# ==========================================
# GESTÃO DA BASE DE DADOS DE GRUPOS
# ==========================================
def carregar_grupos():
    """
    Carrega os grupos existentes do disco.
    Formato: { "nome_grupo": { "criador": "alice", "membros": ["alice","bob"] } }
    """
    if not os.path.exists(ARQUIVO_GRUPOS):
        return {}
    try:
        with open(ARQUIVO_GRUPOS, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[AVISO] Erro ao carregar grupos: {e}")
        return {}


def guardar_grupos(grupos):
    """Grava os grupos no disco."""
    with open(ARQUIVO_GRUPOS, 'w') as f:
        json.dump(grupos, f, indent=4)


# ==========================================
# ESTADO GLOBAL (thread-safe com Lock)
# ==========================================
clientes_ligados = {}
lock_clientes = threading.Lock()
mensagens_offline = carregar_base_dados()
lock_offline = threading.Lock()
certificados = carregar_certificados()
lock_certs = threading.Lock()
grupos = carregar_grupos()
lock_grupos = threading.Lock()


# ==========================================
# IDENTIDADE E PKI DO SERVIDOR (CA)
# ==========================================
def inicializar_identidade_servidor():
    """
    Garante que o servidor tem um par de chaves RSA próprio.
    Esta chave é usada tanto para autenticar o servidor (handshake)
    como para assinar certificados (função CA).
    """
    chave_priv_path = f"chaves_privadas/{SERVIDOR_ID}_privada.pem"
    chave_pub_path = f"chaves_publicas/{SERVIDOR_ID}_publica.pem"

    if not os.path.exists(chave_priv_path):
        print(f"[CA] A gerar identidade criptográfica do servidor (CA)...")
        seguranca.gerar_chaves_rsa(SERVIDOR_ID)
        print(f"[CA] Chave da CA criada em '{chave_pub_path}'")
        print(f"[CA] Esta chave é o 'root of trust' — distribui-a a todos os clientes!")

    return seguranca.carregar_chave_privada(SERVIDOR_ID)


def emitir_certificado(id_utilizador, chave_publica, chave_privada_ca):
    """
    A CA emite e assina um certificado para o utilizador.
    Guarda na base de dados e devolve o certificado serializado.
    """
    corpo_bytes, assinatura = seguranca.criar_certificado(
        id_utilizador, chave_publica, chave_privada_ca
    )

    with lock_certs:
        certificados[id_utilizador] = {
            'corpo': corpo_bytes,
            'assinatura': assinatura
        }
        guardar_certificados(certificados)

    print(f"[CA] Certificado emitido para '{id_utilizador}' ✓")
    return seguranca.serializar_certificado_completo(corpo_bytes, assinatura)


# ==========================================
# HANDSHAKE DE AUTENTICAÇÃO MÚTUA + REGISTO PKI
#
#  Servidor (CA)                        Cliente
#    |                                     |
#    |--- DESAFIO (32 bytes) ------------->|  (1) Servidor desafia cliente
#    |<-- ID_AUTH: id | assinatura --------|  (2) Cliente prova identidade
#    |<-- CHAVE_PUB: pem_bytes ------------|  (3) Cliente envia chave pública
#    |--- CERT: certificado_assinado ----->|  (4) CA emite e envia certificado
#    |<-- DESAFIO_CLI: desafio ------------|  (5) Cliente desafia servidor
#    |--- RESP_SERVIDOR: assinatura ------>|  (6) Servidor prova identidade
#    |<-- AUTH_OK ------------------------ |  (7) Confirmação
#    |                                     |
#    |====== LIGAÇÃO SEGURA + PKI OK ======|
# ==========================================
def handshake_autenticacao(conn, chave_privada_servidor):
    """
    Executa autenticação mútua E registo/renovação PKI.
    Retorna (id_utilizador, True) ou (None, False).
    """
    try:
        # --- PASSO 1: Servidor envia desafio ---
        desafio_servidor = seguranca.gerar_desafio()
        utils.send_msg(conn, b"DESAFIO:" + desafio_servidor)

        # --- PASSO 2: Cliente responde com ID + assinatura ---
        resposta = utils.recv_msg(conn)
        if not resposta or not resposta.startswith(b"ID_AUTH:"):
            print("[AUTH] Protocolo inválido — cliente não enviou ID_AUTH")
            return None, False

        conteudo = resposta[8:]
        id_cliente, assinatura_cliente = utils.unpair(conteudo)
        id_cliente = id_cliente.decode('utf-8')

        # Carregar chave pública — do certificado existente ou do ficheiro
        chave_pub_cliente = None
        with lock_certs:
            cert_existente = certificados.get(id_cliente)

        if cert_existente:
            # Utilizador conhecido — verificar via certificado existente
            try:
                chave_pub_ca = seguranca.carregar_chave_publica(SERVIDOR_ID)
                chave_pub_cliente, _ = seguranca.verificar_certificado(
                    cert_existente['corpo'],
                    cert_existente['assinatura'],
                    chave_pub_ca
                )
            except Exception as e:
                print(f"[CA] Certificado de '{id_cliente}' inválido: {e}")
                # Tentar fallback para ficheiro
                chave_pub_cliente = None

        if chave_pub_cliente is None:
            # Utilizador novo ou certificado inválido — usar ficheiro .pem
            try:
                chave_pub_cliente = seguranca.carregar_chave_publica(id_cliente)
            except FileNotFoundError:
                print(f"[AUTH] Identidade '{id_cliente}' desconhecida — acesso negado")
                utils.send_msg(conn, b"AUTH_FALHOU:Identidade desconhecida")
                return None, False

        # Verificar assinatura do cliente sobre o nosso desafio
        valido, motivo = seguranca.verificar_resposta_desafio(
            chave_pub_cliente, desafio_servidor, assinatura_cliente
        )
        if not valido:
            print(f"[AUTH] FALHA na autenticação de '{id_cliente}': {motivo}")
            utils.send_msg(conn, b"AUTH_FALHOU:" + motivo.encode())
            return None, False

        print(f"[AUTH] Cliente '{id_cliente}' autenticado com sucesso ✓")

        # --- PASSO 3: Receber chave pública do cliente para emitir/renovar certificado ---
        pacote_pub = utils.recv_msg(conn)
        if not pacote_pub or not pacote_pub.startswith(b"CHAVE_PUB:"):
            utils.send_msg(conn, b"AUTH_FALHOU:Protocolo PKI incompleto")
            return None, False

        pem_bytes = pacote_pub[10:]
        chave_pub_para_cert = seguranca.bytes_para_chave_publica(pem_bytes)

        # --- PASSO 4: CA emite certificado e envia ao cliente ---
        cert_serializado = emitir_certificado(id_cliente, chave_pub_para_cert, chave_privada_servidor)
        utils.send_msg(conn, b"CERT:" + cert_serializado)

        # --- PASSO 5: Cliente desafia o servidor ---
        desafio_cliente = utils.recv_msg(conn)
        if not desafio_cliente or not desafio_cliente.startswith(b"DESAFIO_CLI:"):
            utils.send_msg(conn, b"AUTH_FALHOU:Protocolo incompleto")
            return None, False

        desafio_bytes = desafio_cliente[12:]

        # --- PASSO 6: Servidor assina o desafio do cliente ---
        assinatura_servidor = seguranca.assinar_desafio(chave_privada_servidor, desafio_bytes)
        utils.send_msg(conn, b"RESP_SERVIDOR:" + assinatura_servidor)

        # --- PASSO 7: Aguardar confirmação ---
        confirmacao = utils.recv_msg(conn)
        if confirmacao != b"AUTH_OK":
            print(f"[AUTH] Cliente '{id_cliente}' rejeitou autenticação do servidor")
            return None, False

        print(f"[AUTH] Autenticação mútua com '{id_cliente}' concluída ✓")
        return id_cliente, True

    except Exception as e:
        print(f"[AUTH] Erro durante handshake: {e}")
        return None, False


# ==========================================
# GESTÃO DE CADA CLIENTE (Thread)
# ==========================================
def handle_client(conn, addr, chave_privada_servidor):
    print(f"[NOVA LIGAÇÃO] Cliente de {addr}")
    meu_id = None

    try:
        # Autenticação mútua + PKI obrigatórios
        meu_id, autenticado = handshake_autenticacao(conn, chave_privada_servidor)

        if not autenticado:
            print(f"[SEGURANÇA] Ligação de {addr} rejeitada — autenticação falhou")
            conn.close()
            return

        # Registar cliente (thread-safe)
        with lock_clientes:
            if meu_id in clientes_ligados:
                print(f"[*] '{meu_id}' já estava ligado — a fechar sessão antiga")
                try:
                    clientes_ligados[meu_id].close()
                except Exception:
                    pass
            clientes_ligados[meu_id] = conn

        print(f"[*] '{meu_id}' registado no servidor.")

        # Entregar mensagens offline pendentes
        with lock_offline:
            if meu_id in mensagens_offline and len(mensagens_offline[meu_id]) > 0:
                n = len(mensagens_offline[meu_id])
                print(f"[*] A entregar {n} mensagens offline a '{meu_id}'...")
                for pacote_pendente in mensagens_offline[meu_id]:
                    utils.send_msg(conn, pacote_pendente)
                mensagens_offline[meu_id] = []
                guardar_base_dados(mensagens_offline)

        # Loop principal
        while True:
            pacote = utils.recv_msg(conn)
            if not pacote:
                break

            # Comando: lista de utilizadores online
            if pacote == b"CMD:LISTA":
                with lock_clientes:
                    online = [uid for uid in clientes_ligados if uid != meu_id]
                resposta = "ONLINE:" + ",".join(online) if online else "ONLINE:"
                utils.send_msg(conn, resposta.encode('utf-8'))
                continue

            # Comando PKI: pedir certificado de outro utilizador
            if pacote.startswith(b"CMD:CERT:"):
                id_pedido = pacote[9:].decode('utf-8')
                with lock_certs:
                    cert = certificados.get(id_pedido)
                if cert:
                    cert_serializado = seguranca.serializar_certificado_completo(
                        cert['corpo'], cert['assinatura']
                    )
                    utils.send_msg(conn, b"CERT_RESP:" + cert_serializado)
                    print(f"[CA] Certificado de '{id_pedido}' enviado a '{meu_id}'")
                else:
                    utils.send_msg(conn, b"CERT_NAO_ENCONTRADO:" + id_pedido.encode())
                continue

            # Comando: criar grupo
            if pacote.startswith(b"CMD:GRUPO:CRIAR:"):
                nome_grupo = pacote[16:].decode('utf-8').strip()
                with lock_grupos:
                    if nome_grupo in grupos:
                        utils.send_msg(conn, b"GRUPO_ERRO:Grupo ja existe")
                    else:
                        grupos[nome_grupo] = {
                            'criador': meu_id,
                            'membros': [meu_id]
                        }
                        guardar_grupos(grupos)
                        utils.send_msg(conn, b"GRUPO_OK:Grupo criado")
                        print(f"[GRUPO] '{meu_id}' criou o grupo '{nome_grupo}'")
                continue

            # Comando: adicionar membro ao grupo
            if pacote.startswith(b"CMD:GRUPO:ADD:"):
                partes = pacote[14:].decode('utf-8').split(':', 1)
                if len(partes) == 2:
                    nome_grupo, novo_membro = partes
                    with lock_grupos:
                        if nome_grupo not in grupos:
                            utils.send_msg(conn, b"GRUPO_ERRO:Grupo nao existe")
                        elif meu_id != grupos[nome_grupo]['criador']:
                            utils.send_msg(conn, b"GRUPO_ERRO:Apenas o criador pode adicionar membros")
                        elif novo_membro in grupos[nome_grupo]['membros']:
                            utils.send_msg(conn, b"GRUPO_ERRO:Membro ja esta no grupo")
                        else:
                            grupos[nome_grupo]['membros'].append(novo_membro)
                            guardar_grupos(grupos)
                            membros_str = ','.join(grupos[nome_grupo]['membros'])
                            utils.send_msg(conn, f"GRUPO_OK:{membros_str}".encode())
                            print(f"[GRUPO] '{novo_membro}' adicionado a '{nome_grupo}' por '{meu_id}'")
                continue

            # Comando: listar membros de um grupo
            if pacote.startswith(b"CMD:GRUPO:INFO:"):
                nome_grupo = pacote[15:].decode('utf-8').strip()
                with lock_grupos:
                    grupo = grupos.get(nome_grupo)
                if grupo:
                    membros_str = ','.join(grupo['membros'])
                    criador = grupo['criador']
                    utils.send_msg(conn, f"GRUPO_INFO:{criador}:{membros_str}".encode())
                else:
                    utils.send_msg(conn, b"GRUPO_ERRO:Grupo nao existe")
                continue

            # Encaminhamento de mensagem de grupo (para todos os membros)
            if pacote.startswith(b"GRUPO_MSG:"):
                partes = pacote.split(b"|", 1)
                if len(partes) == 2:
                    nome_grupo = partes[0][10:].decode('utf-8')
                    pacote_real = partes[1]
                    pacote_final = f"GRUPO_FROM:{meu_id}:{nome_grupo}|".encode() + pacote_real

                    with lock_grupos:
                        grupo = grupos.get(nome_grupo)

                    if not grupo:
                        utils.send_msg(conn, b"GRUPO_ERRO:Grupo nao existe")
                        continue

                    if meu_id not in grupo['membros']:
                        utils.send_msg(conn, b"GRUPO_ERRO:Nao es membro deste grupo")
                        continue

                    # Enviar para todos os membros (exceto o remetente)
                    for membro in grupo['membros']:
                        if membro == meu_id:
                            continue
                        with lock_clientes:
                            membro_conn = clientes_ligados.get(membro)
                        if membro_conn:
                            try:
                                utils.send_msg(membro_conn, pacote_final)
                            except Exception:
                                with lock_offline:
                                    mensagens_offline.setdefault(membro, []).append(pacote_final)
                                    guardar_base_dados(mensagens_offline)
                        else:
                            with lock_offline:
                                mensagens_offline.setdefault(membro, []).append(pacote_final)
                                guardar_base_dados(mensagens_offline)
                    print(f"[GRUPO] Mensagem de '{meu_id}' no grupo '{nome_grupo}'")
                continue

            # Encaminhamento de mensagem
            if pacote.startswith(b"DEST:"):
                partes = pacote.split(b"|", 1)
                if len(partes) == 2:
                    destinatario = partes[0][5:].decode('utf-8')
                    pacote_real = partes[1]
                    pacote_final = f"FROM:{meu_id}|".encode('utf-8') + pacote_real

                    with lock_clientes:
                        destino_conn = clientes_ligados.get(destinatario)

                    if destino_conn:
                        try:
                            utils.send_msg(destino_conn, pacote_final)
                        except Exception:
                            with lock_offline:
                                mensagens_offline.setdefault(destinatario, []).append(pacote_final)
                                guardar_base_dados(mensagens_offline)
                    else:
                        with lock_offline:
                            mensagens_offline.setdefault(destinatario, []).append(pacote_final)
                            guardar_base_dados(mensagens_offline)
                        print(f"[*] Mensagem para '{destinatario}' guardada (offline).")

    except Exception as e:
        print(f"[ERRO] Exceção no cliente {addr}: {e}")

    finally:
        if meu_id:
            with lock_clientes:
                if clientes_ligados.get(meu_id) == conn:
                    del clientes_ligados[meu_id]
        print(f"[DESCONECTADO] '{meu_id or addr}' desligou-se.")
        conn.close()


# ==========================================
# ARRANQUE DO SERVIDOR
# ==========================================
def start_server():
    chave_privada_servidor = inicializar_identidade_servidor()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    total_offline = sum(len(m) for m in mensagens_offline.values())
    total_certs = len(certificados)

    print(f"\n[A INICIAR] Servidor à escuta em {HOST}:{PORT}...")
    print(f"[*] Mensagens offline armazenadas: {total_offline}")
    print(f"[*] Certificados PKI emitidos: {total_certs}")
    print(f"[*] Autenticação mútua: ATIVA")
    print(f"[*] Proteção anti-replay: ATIVA")
    total_grupos = len(grupos)
    print(f"[*] PKI / CA: ATIVA")
    print(f"[*] Grupos criados: {total_grupos}\n")

    while True:
        conn, addr = server.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr, chave_privada_servidor),
            daemon=True
        ).start()


if __name__ == "__main__":
    start_server()