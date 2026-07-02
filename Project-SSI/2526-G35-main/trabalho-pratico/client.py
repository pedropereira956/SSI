import socket
import threading
import sys
import os
import utils
import seguranca

HOST = '127.0.0.1'
PORT = 65432
SERVIDOR_ID = "servidor"


class ClienteE2EE:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.meu_id = ""
        self.chat_ativo = ""
        self.sessoes = {}
        self.minha_rsa_priv = None
        # Proteção anti-replay: regista nonces de mensagens já processadas
        self.anti_replay = seguranca.AntiReplay()
        # Cache local de certificados PKI verificados
        self.cache_certificados = {}
        # Forward Secrecy: chaves ECDH efémeras por sessão
        # { 'bob': {'priv': X25519PrivateKey, 'chave_sessao': bytes} }
        self.sessoes_fs = {}
        # Grupos: chaves AES partilhadas por grupo
        # { 'nome_grupo': chave_aes_bytes }
        self.chaves_grupo = {}
        # Chat de grupo ativo (None = chat privado)
        self.grupo_ativo = None

    def iniciar(self):
        print("==================================")
        print("🛡️  BEM-VINDO AO CHAT SEGURO (E2EE)")
        print("==================================")

        self.meu_id = input("Qual é o teu ID de utilizador?: ").strip().lower()
        if not self.meu_id:
            print("[ERRO] ID não pode ser vazio.")
            return

        # Carregar ou criar identidade
        try:
            self.minha_rsa_priv = seguranca.carregar_chave_privada(self.meu_id)
            print(f"[*] Identidade '{self.meu_id}' carregada.")
        except FileNotFoundError:
            resposta = input(f"[*] A identidade '{self.meu_id}' não existe. Criar agora? (s/n): ")
            if resposta.lower() == 's':
                print(f"[*] A gerar par de chaves RSA para '{self.meu_id}'...")
                seguranca.gerar_chaves_rsa(self.meu_id)
                self.minha_rsa_priv = seguranca.carregar_chave_privada(self.meu_id)
                print("[+] Identidade criada com sucesso!")
            else:
                print("[ERRO] A sair...")
                return

        # Ligar ao servidor (opcional — modo offline disponível sem servidor)
        self.modo_offline = False
        try:
            self.sock.connect((HOST, PORT))
            print("[*] Ligado ao servidor. A autenticar e registar certificado...")

            # Handshake com PKI
            if not self._handshake_autenticacao():
                print("[ERRO FATAL] Autenticação falhou. A sair.")
                self.sock.close()
                return

            print(f"[✓] Autenticação mútua + PKI concluídas — ligação segura estabelecida!\n")
            threading.Thread(target=self.receber_mensagens, daemon=True).start()

        except ConnectionRefusedError:
            print("[!] Servidor não está disponível — a entrar em MODO OFFLINE.")
            print("[!] Funcionalidades disponíveis: /exportar e /importar (PGP-like)")
            print("[!] Para chat em tempo real, arranca o server.py primeiro.\n")
            self.modo_offline = True

        self.menu_comandos()

    # ==========================================
    # HANDSHAKE DE AUTENTICAÇÃO MÚTUA + PKI
    #
    #  Cliente                          Servidor (CA)
    #    |                                  |
    #    |<-- DESAFIO (32 bytes) -----------|  (1) Receber desafio
    #    |--- ID_AUTH: id | assinatura ---->|  (2) Provar identidade
    #    |--- CHAVE_PUB: pem_bytes -------->|  (3) Enviar chave pública para certificado
    #    |<-- CERT: certificado_assinado ---|  (4) Receber certificado da CA
    #    |--- DESAFIO_CLI: desafio -------->|  (5) Desafiar o servidor
    #    |<-- RESP_SERVIDOR: assinatura ----|  (6) Verificar servidor
    #    |--- AUTH_OK --------------------> |  (7) Confirmar
    # ==========================================
    def _handshake_autenticacao(self):
        try:
            # PASSO 1: Receber desafio do servidor
            pacote = utils.recv_msg(self.sock)
            if not pacote or not pacote.startswith(b"DESAFIO:"):
                print("[AUTH] Resposta inesperada do servidor.")
                return False
            desafio_servidor = pacote[8:]

            # PASSO 2: Assinar o desafio e enviar com o nosso ID
            assinatura = seguranca.assinar_desafio(self.minha_rsa_priv, desafio_servidor)
            id_bytes = self.meu_id.encode('utf-8')
            payload = utils.mkpair(id_bytes, assinatura)
            utils.send_msg(self.sock, b"ID_AUTH:" + payload)

            # PASSO 3: Enviar a nossa chave pública para a CA emitir certificado
            minha_chave_pub = seguranca.carregar_chave_publica(self.meu_id)
            pem_bytes = seguranca.chave_publica_para_bytes(minha_chave_pub)
            utils.send_msg(self.sock, b"CHAVE_PUB:" + pem_bytes)

            # PASSO 4: Receber o nosso certificado assinado pela CA
            resp_cert = utils.recv_msg(self.sock)

            if resp_cert and resp_cert.startswith(b"AUTH_FALHOU:"):
                motivo = resp_cert[12:].decode('utf-8')
                print(f"[AUTH] Servidor rejeitou-nos: {motivo}")
                return False

            if not resp_cert or not resp_cert.startswith(b"CERT:"):
                print("[AUTH] Servidor não enviou certificado.")
                return False

            cert_data = resp_cert[5:]
            corpo_bytes, assinatura_ca = seguranca.desserializar_certificado_completo(cert_data)

            # Verificar o nosso próprio certificado com a chave pública da CA
            try:
                chave_pub_ca = seguranca.carregar_chave_publica(SERVIDOR_ID)
                chave_pub_verificada, id_verificado = seguranca.verificar_certificado(
                    corpo_bytes, assinatura_ca, chave_pub_ca
                )
                print(f"[PKI] Certificado próprio recebido e verificado ✓ (válido 1 ano)")
                self.cache_certificados[self.meu_id] = (corpo_bytes, assinatura_ca)
            except Exception as e:
                print(f"[PKI] Aviso: não foi possível verificar o certificado: {e}")

            # PASSO 5: Desafiar o servidor
            nosso_desafio = seguranca.gerar_desafio()
            utils.send_msg(self.sock, b"DESAFIO_CLI:" + nosso_desafio)

            # PASSO 6: Verificar resposta do servidor
            resp_servidor = utils.recv_msg(self.sock)

            if resp_servidor and resp_servidor.startswith(b"AUTH_FALHOU:"):
                motivo = resp_servidor[12:].decode('utf-8')
                print(f"[AUTH] Servidor rejeitou: {motivo}")
                return False

            if not resp_servidor or not resp_servidor.startswith(b"RESP_SERVIDOR:"):
                print("[AUTH] Servidor não respondeu ao nosso desafio.")
                return False

            assinatura_servidor = resp_servidor[14:]

            try:
                chave_pub_servidor = seguranca.carregar_chave_publica(SERVIDOR_ID)
            except FileNotFoundError:
                print(f"[AUTH] Chave pública do servidor não encontrada.")
                return False

            valido, motivo = seguranca.verificar_resposta_desafio(
                chave_pub_servidor, nosso_desafio, assinatura_servidor
            )
            if not valido:
                print(f"[SEGURANÇA] ⚠️  SERVIDOR NÃO AUTENTICADO: {motivo}")
                print("[SEGURANÇA] Possível ataque Man-in-the-Middle! A terminar.")
                return False

            print(f"[AUTH] Servidor autenticado com sucesso ✓")

            # PASSO 7: Confirmar
            utils.send_msg(self.sock, b"AUTH_OK")
            return True

        except Exception as e:
            print(f"[AUTH] Erro no handshake: {e}")
            return False

    # ==========================================
    # PKI — OBTER CHAVE PÚBLICA VIA CERTIFICADO
    # ==========================================
    def _obter_chave_publica_via_pki(self, nome):
        """Pede certificado ao servidor e verifica-o. Retorna chave pública ou None."""
        if nome in self.cache_certificados:
            try:
                corpo_bytes, assinatura = self.cache_certificados[nome]
                chave_pub_ca = seguranca.carregar_chave_publica(SERVIDOR_ID)
                chave_pub, _ = seguranca.verificar_certificado(corpo_bytes, assinatura, chave_pub_ca)
                return chave_pub
            except Exception:
                del self.cache_certificados[nome]
        try:
            utils.send_msg(self.sock, b"CMD:CERT:" + nome.encode('utf-8'))
        except Exception as e:
            print(f"[PKI] Erro ao pedir certificado: {e}")
        return None

    # ==========================================
    # COMANDOS DO UTILIZADOR
    # ==========================================
    def menu_comandos(self):
        print("--- COMANDOS DISPONÍVEIS ---")
        print(" /conectar <nome>  - Abre conversa com <nome>")
        print(" /lista            - Mostra quem está online")
        print(" /grupo criar <nome>         - Cria um grupo")
        print(" /grupo add <nome> <membro>  - Adiciona membro")
        print(" /grupo entrar <nome>        - Entra no grupo")
        print(" /grupo sair                 - Sai do chat de grupo")
        print(" /grupo lista                - Ver grupos a que pertences")
        print(" /exportar               - Exportar mas apenas offline (PGP-like)")
        print(" /importar               - Importar mas apenas offline (PGP-like)")
        print(" /sair             - Fecha a aplicação")
        print(" <texto>           - Envia mensagem cifrada")
        print("----------------------------\n")
 
        while True:
            try:
                msg = input("")
            except EOFError:
                break
 
            if not msg.strip():
                continue
 
            if msg.lower() == '/sair':
                self.sock.close()
                sys.exit(0)
 
            elif msg.lower().startswith('/conectar '):
                partes = msg.split(' ', 1)
                if len(partes) < 2 or not partes[1].strip():
                    print("[ERRO] Uso: /conectar <nome>")
                    continue
                self.iniciar_conversa(partes[1].strip().lower())
 
            elif msg.lower() == '/lista':
                self._pedir_lista_online()
 
            elif msg.lower().startswith('/grupo '):
                self._comando_grupo(msg[7:].strip())
 
            elif msg.lower().startswith('/exportar '):
                partes = msg.split(' ', 2)
                if len(partes) < 3:
                    print("[ERRO] Uso: /exportar <nome> <mensagem>")
                else:
                    self._exportar_pgp(partes[1].strip().lower(), partes[2].strip())
 
            elif msg.lower().startswith('/importar '):
                partes = msg.split(' ', 1)
                if len(partes) < 2:
                    print("[ERRO] Uso: /importar <ficheiro.pgp>")
                else:
                    self._importar_pgp(partes[1].strip())
 
            elif msg.startswith('/'):
                print("[ERRO] Comando desconhecido. Usa /conectar, /lista, /grupo ou /sair")
 
            else:
                self.enviar_mensagem(msg)
 
    def _pedir_lista_online(self):
        """Pede ao servidor a lista de utilizadores online."""
        try:
            utils.send_msg(self.sock, b"CMD:LISTA")
        except Exception as e:
            print(f"[ERRO] Falha ao pedir lista: {e}")


    # ==========================================
    # GESTÃO DE SESSÕES (com suporte PKI)
    # ==========================================
    def obter_sessao(self, nome):
        """
        Devolve (ou cria) a sessão de um contacto.
        Tenta obter a chave pública via certificado PKI primeiro,
        com fallback para o ficheiro .pem local.
        """
        if nome not in self.sessoes:
            chave_pub = None

            # Tentar via certificado em cache
            if nome in self.cache_certificados:
                try:
                    corpo_bytes, assinatura = self.cache_certificados[nome]
                    chave_pub_ca = seguranca.carregar_chave_publica(SERVIDOR_ID)
                    chave_pub, _ = seguranca.verificar_certificado(
                        corpo_bytes, assinatura, chave_pub_ca
                    )
                    print(f"[PKI] Chave de '{nome}' obtida via certificado verificado ✓")
                except Exception as e:
                    print(f"[PKI] Certificado de '{nome}' inválido: {e}")
                    chave_pub = None

            # Fallback: ficheiro .pem local
            if chave_pub is None:
                try:
                    chave_pub = seguranca.carregar_chave_publica(nome)
                    print(f"[*] Chave de '{nome}' carregada do ficheiro local.")
                except FileNotFoundError:
                    return None

            self.sessoes[nome] = {
                'rsa_pub': chave_pub,
                'nao_lidas': []
            }

        return self.sessoes[nome]

    def iniciar_conversa(self, novo_contacto):
        """Muda para o chat com o contacto e inicia handshake Forward Secrecy."""
        if novo_contacto == self.meu_id:
            print("[ERRO] Não podes conversar contigo mesmo.")
            return

        sessao = self.obter_sessao(novo_contacto)
        if not sessao:
            print(f"[ERRO] Identidade pública de '{novo_contacto}' não encontrada.")
            print(f"       O '{novo_contacto}' já se ligou ao servidor alguma vez?")
            return

        self.chat_ativo = novo_contacto
        print(f"\n[+] Chat seguro com {novo_contacto.upper()} — podes escrever!")

        # Iniciar handshake Forward Secrecy
        self._iniciar_handshake_fs(novo_contacto)

        if sessao['nao_lidas']:
            print(f"--- 📥 {len(sessao['nao_lidas'])} MENSAGENS NÃO LIDAS ---")
            for msg in sessao['nao_lidas']:
                print(f"  [{novo_contacto.capitalize()}] {msg}")
            print("---------------------------------")
            sessao['nao_lidas'] = []

    # ==========================================
    # FORWARD SECRECY — HANDSHAKE ECDH EFÉMERO
    #
    #  Quando Alice faz /conectar bob:
    #  1. Gera par X25519 efémero
    #  2. Envia chave pública ECDH assinada com RSA (anti-MITM)
    #  3. Bob recebe, gera o seu par, calcula segredo, responde
    #  4. Alice recebe, calcula segredo, destrói chave efémera
    #  5. Ambos têm a mesma chave AES de sessão
    #  6. Chaves efémeras destruídas — não podem recuperar mensagens passadas
    #
    #  Funciona em QUALQUER ordem de /conectar:
    #  Se Bob ainda não fez /conectar alice, quando recebe o FS_HELLO
    #  responde automaticamente sem precisar de interação do utilizador.
    # ==========================================
    def _iniciar_handshake_fs(self, contacto):
        """
        Inicia o handshake ECDH efémero para Forward Secrecy.
        Gera par X25519 e envia chave pública assinada com RSA.
        """
        try:
            priv_efemero, pub_efemero_bytes = seguranca.gerar_par_ecdh_efemero()
            self.sessoes_fs[contacto] = {
                'priv': priv_efemero,
                'chave_sessao': None
            }
            assinatura = seguranca.assinar_chave_ecdh(
                self.minha_rsa_priv, pub_efemero_bytes, self.meu_id, contacto
            )
            payload = utils.mkpair(pub_efemero_bytes, assinatura)
            cabecalho = f"DEST:{contacto}|".encode('utf-8')
            utils.send_msg(self.sock, cabecalho + b"FS_HELLO:" + payload)
            print(f"[FS] Handshake iniciado com {contacto} — a aguardar resposta...")
        except Exception as e:
            print(f"[FS] Erro ao iniciar handshake: {e}")

    # ==========================================
    # ENVIO DE MENSAGEM
    #
    # Usa Forward Secrecy se disponível (preferido),
    # caso contrário usa o modo clássico RSA (fallback).
    # ==========================================
    def enviar_mensagem(self, texto):
        # Verificar se estamos num chat de grupo
        if self.grupo_ativo:
            self._enviar_mensagem_grupo(texto)
            return

        if not self.chat_ativo:
            print("[ERRO] Não tens conversa aberta. Usa /conectar <nome> ou /grupo entrar <nome>")
            return

        sessao = self.sessoes.get(self.chat_ativo)
        if not sessao:
            print(f"[ERRO] Sessão com '{self.chat_ativo}' perdida. Usa /conectar novamente.")
            return

        try:
            fs = self.sessoes_fs.get(self.chat_ativo)

            if fs and fs.get('chave_sessao'):
                # ==========================================
                # MODO FORWARD SECRECY (preferido)
                # Chave AES derivada via ECDH efémero.
                # Mesmo que RSA seja comprometido no futuro,
                # esta mensagem fica protegida — chave efémera
                # já foi destruída.
                # ==========================================
                chave_aes = fs['chave_sessao']
                pacote_cifrado = seguranca.cifrar_mensagem(chave_aes, texto)
                assinatura = seguranca.assinar_dados(self.minha_rsa_priv, pacote_cifrado)
                envelope_final = utils.mkpair(assinatura, pacote_cifrado)
                cabecalho = f"DEST:{self.chat_ativo}|".encode('utf-8')
                utils.send_msg(self.sock, cabecalho + b"MSG_FS:" + envelope_final)
            else:
                # ==========================================
                # MODO CLÁSSICO (fallback)
                # Usado quando handshake FS ainda não completou.
                # ==========================================
                rsa_pub_dest = sessao['rsa_pub']
                chave_aes = seguranca.gerar_chave_aes_aleatoria()
                pacote_cifrado = seguranca.cifrar_mensagem(chave_aes, texto)
                chave_aes_cifrada = seguranca.cifrar_chave_aes_com_rsa(rsa_pub_dest, chave_aes)
                envelope_interno = utils.mkpair(chave_aes_cifrada, pacote_cifrado)
                assinatura = seguranca.assinar_dados(self.minha_rsa_priv, envelope_interno)
                envelope_final = utils.mkpair(assinatura, envelope_interno)
                cabecalho = f"DEST:{self.chat_ativo}|".encode('utf-8')
                utils.send_msg(self.sock, cabecalho + b"MSG:" + envelope_final)

        except Exception as e:
            print(f"[ERRO] Falha ao enviar mensagem: {e}")

    # ==========================================
    # RECEÇÃO DE MENSAGENS (Thread de background)
    # ==========================================
    def receber_mensagens(self):
        while True:
            try:
                pacote = utils.recv_msg(self.sock)

                if not pacote:
                    print("\n[ERRO FATAL] Servidor encerrou a ligação.", flush=True)
                    os._exit(1)

                # Resposta ao /lista
                if pacote.startswith(b"ONLINE:"):
                    lista_str = pacote[7:].decode('utf-8')
                    if lista_str:
                        print(f"\n[🟢 Online agora]: {', '.join(lista_str.split(','))}", flush=True)
                    else:
                        print("\n[🟢 Online agora]: Ninguém mais online.", flush=True)
                    continue

                # Resposta PKI: certificado de outro utilizador
                if pacote.startswith(b"CERT_RESP:"):
                    cert_data = pacote[10:]
                    try:
                        corpo_bytes, assinatura = seguranca.desserializar_certificado_completo(cert_data)
                        chave_pub_ca = seguranca.carregar_chave_publica(SERVIDOR_ID)
                        chave_pub, id_util = seguranca.verificar_certificado(
                            corpo_bytes, assinatura, chave_pub_ca
                        )
                        self.cache_certificados[id_util] = (corpo_bytes, assinatura)
                        if id_util in self.sessoes:
                            self.sessoes[id_util]['rsa_pub'] = chave_pub
                        print(f"\n[PKI] Certificado de '{id_util}' verificado e guardado ✓", flush=True)
                    except Exception as e:
                        print(f"\n[PKI] Certificado inválido recebido: {e}", flush=True)
                    continue

                # Respostas de comandos de grupo
                if pacote.startswith(b"GRUPO_OK:") or pacote.startswith(b"GRUPO_ERRO:") or pacote.startswith(b"GRUPO_INFO:"):
                    self._processar_resposta_grupo(pacote)
                    continue

                if pacote.startswith(b"CERT_NAO_ENCONTRADO:"):
                    nome = pacote[20:].decode('utf-8')
                    print(f"\n[PKI] Certificado de '{nome}' não encontrado no servidor.", flush=True)
                    continue

                # Mensagem de grupo (encaminhada pelo servidor)
                if pacote.startswith(b"GRUPO_FROM:"):
                    self._processar_grupo_from(pacote)
                    continue

                # Mensagem de outro utilizador
                if pacote.startswith(b"FROM:"):
                    partes = pacote.split(b"|", 1)
                    if len(partes) < 2:
                        continue

                    remetente = partes[0][5:].decode('utf-8')
                    dados_reais = partes[1]

                    sessao = self.obter_sessao(remetente)
                    if not sessao:
                        print(f"\n[⚠️] Mensagem de '{remetente}' desconhecido — ignorada.", flush=True)
                        continue

                    # Mensagem de grupo recebida
                    if dados_reais.startswith(b"GRUPO_MSG_CIFRADA:"):
                        self._processar_mensagem_grupo_recebida(remetente, dados_reais[18:], partes[0])
                        continue

                    # Handshake Forward Secrecy — funciona em qualquer ordem
                    if dados_reais.startswith(b"GRUPO_CHAVE:"):
                        self._processar_chave_grupo(dados_reais)
                        continue

                    if dados_reais.startswith(b"FS_HELLO:"):
                        self._processar_fs_hello(remetente, dados_reais[9:], sessao)
                        continue

                    # Mensagem com Forward Secrecy ativa
                    if dados_reais.startswith(b"MSG_FS:"):
                        self._processar_mensagem_fs(remetente, dados_reais[7:], sessao)
                        continue

                    # Mensagem clássica (sem FS)
                    if dados_reais.startswith(b"MSG:"):
                        self._processar_mensagem(remetente, dados_reais[4:], sessao)

            except OSError:
                print("\n[ERRO FATAL] Ligação cortada.", flush=True)
                os._exit(1)
            except Exception as e:
                print(f"\n[AVISO] Erro ao processar pacote: {e}", flush=True)

    def _processar_mensagem(self, remetente, envelope_final, sessao):
        """Abre o envelope clássico, verifica assinatura e decifra."""
        try:
            assinatura, envelope_interno = utils.unpair(envelope_final)

            if not seguranca.verificar_assinatura(sessao['rsa_pub'], assinatura, envelope_interno):
                print(f"\n[⚠️  SEGURANÇA] Assinatura inválida de '{remetente}'! Mensagem REJEITADA.", flush=True)
                return

            chave_aes_cifrada, pacote_cifrado = utils.unpair(envelope_interno)

            nonce = pacote_cifrado[:12]
            if not self.anti_replay.verificar_e_registar(nonce):
                print(f"\n[⚠️  SEGURANÇA] Replay detectado de '{remetente}'! Mensagem REJEITADA.", flush=True)
                return

            chave_aes = seguranca.decifrar_chave_aes_com_rsa(self.minha_rsa_priv, chave_aes_cifrada)
            msg_limpa = seguranca.decifrar_mensagem(chave_aes, pacote_cifrado)

            if remetente == self.chat_ativo:
                print(f"\n[{remetente.capitalize()}] {msg_limpa}", flush=True)
            else:
                sessao['nao_lidas'].append(msg_limpa)
                print(f"\n[🔔] Mensagem de {remetente.capitalize()}! Usa /conectar {remetente}", flush=True)

        except Exception as e:
            print(f"\n[ERRO] Falha ao processar mensagem de '{remetente}': {e}", flush=True)

    def _processar_fs_hello(self, remetente, payload, sessao):
        """
        Processa handshake ECDH recebido — funciona em qualquer ordem.
        Se já iniciámos: calcula segredo e finaliza.
        Se não iniciámos: gera par, calcula segredo e responde automaticamente.
        Chave privada efémera é destruída após cálculo.
        """
        try:
            pub_ecdh_bytes, assinatura = utils.unpair(payload)

            # Verificar assinatura RSA — confirma autenticidade (anti-MITM)
            if not seguranca.verificar_chave_ecdh(
                sessao['rsa_pub'], pub_ecdh_bytes, remetente, self.meu_id, assinatura
            ):
                print(f"\n[⚠️ FS] Chave ECDH de '{remetente}' inválida — possível MITM!", flush=True)
                return

            fs = self.sessoes_fs.get(remetente)

            if fs and fs.get('priv'):
                # Já iniciámos — calcular segredo e finalizar
                segredo = seguranca.calcular_segredo_ecdh(fs['priv'], pub_ecdh_bytes)
                chave_sessao = seguranca.derivar_chave_sessao(segredo)
                self.sessoes_fs[remetente]['chave_sessao'] = chave_sessao
                self.sessoes_fs[remetente]['priv'] = None  # destruir chave efémera
                print(f"\n[🔒 FS] Forward Secrecy estabelecido com {remetente.capitalize()}! Chave efémera destruída.", flush=True)
            else:
                # Não iniciámos — gerar par, calcular segredo e responder automaticamente
                priv_efemero, pub_efemero_bytes = seguranca.gerar_par_ecdh_efemero()
                segredo = seguranca.calcular_segredo_ecdh(priv_efemero, pub_ecdh_bytes)
                chave_sessao = seguranca.derivar_chave_sessao(segredo)
                self.sessoes_fs[remetente] = {
                    'priv': None,  # destruir imediatamente após cálculo
                    'chave_sessao': chave_sessao
                }
                # Responder com a nossa chave ECDH pública assinada
                assin_resp = seguranca.assinar_chave_ecdh(
                    self.minha_rsa_priv, pub_efemero_bytes, self.meu_id, remetente
                )
                payload_resp = utils.mkpair(pub_efemero_bytes, assin_resp)
                cabecalho = f"DEST:{remetente}|".encode('utf-8')
                utils.send_msg(self.sock, cabecalho + b"FS_HELLO:" + payload_resp)
                print(f"\n[🔒 FS] Forward Secrecy estabelecido com {remetente.capitalize()}! Chave efémera destruída.", flush=True)
                if remetente != self.chat_ativo:
                    print(f"[FS] Sessão segura pronta — usa /conectar {remetente} para conversar.", flush=True)

        except Exception as e:
            print(f"\n[FS] Erro ao processar handshake: {e}", flush=True)

    def _processar_mensagem_fs(self, remetente, envelope_final, sessao):
        """
        Decifra mensagem com Forward Secrecy usando chave de sessão ECDH.
        """
        try:
            fs = self.sessoes_fs.get(remetente)
            if not fs or not fs.get('chave_sessao'):
                print(f"\n[⚠️ FS] Mensagem FS de '{remetente}' sem sessão FS — ignorada.", flush=True)
                return

            assinatura, pacote_cifrado = utils.unpair(envelope_final)

            # Verificar assinatura RSA (autenticidade)
            if not seguranca.verificar_assinatura(sessao['rsa_pub'], assinatura, pacote_cifrado):
                print(f"\n[⚠️ SEGURANÇA] Assinatura FS inválida de '{remetente}'! Rejeitada.", flush=True)
                return

            # Anti-replay
            nonce = pacote_cifrado[:12]
            if not self.anti_replay.verificar_e_registar(nonce):
                print(f"\n[⚠️ SEGURANÇA] Replay FS detectado de '{remetente}'!", flush=True)
                return

            # Decifrar com chave de sessão ECDH
            msg_limpa = seguranca.decifrar_mensagem(fs['chave_sessao'], pacote_cifrado)

            if remetente == self.chat_ativo:
                print(f"\n[{remetente.capitalize()}] {msg_limpa}", flush=True)
            else:
                sessao['nao_lidas'].append(msg_limpa)
                print(f"\n[🔔] Mensagem de {remetente.capitalize()}! Usa /conectar {remetente}", flush=True)

        except Exception as e:
            print(f"\n[ERRO FS] Falha ao processar mensagem: {e}", flush=True)


    # ==========================================
    # MENSAGENS DE GRUPO
    #
    # Modelo de segurança:
    # 1. Criador gera chave AES de grupo aleatória
    # 2. Chave é cifrada com RSA de cada membro individualmente
    # 3. Cada membro recebe a sua cópia cifrada e decifra
    # 4. Mensagens de grupo cifradas com chave AES partilhada
    # 5. Servidor gere membros mas NUNCA vê a chave do grupo
    #
    # Comandos:
    #   /grupo criar <nome>         - Cria grupo e gera chave
    #   /grupo add <nome> <membro>  - Adiciona membro e envia-lhe a chave
    #   /grupo entrar <nome>        - Muda para chat de grupo
    # ==========================================
    def _comando_grupo(self, args):
        """Processa comandos de grupo."""
        partes = args.split(' ', 2)
        subcomando = partes[0].lower() if partes else ''

        if subcomando == 'criar' and len(partes) >= 2:
            self._criar_grupo(partes[1])

        elif subcomando == 'add' and len(partes) >= 3:
            self._adicionar_membro_grupo(partes[1], partes[2])

        elif subcomando == 'entrar' and len(partes) >= 2:
            self._entrar_grupo(partes[1])

        elif subcomando == 'sair':
            self._sair_grupo()

        elif subcomando == 'lista':
            self._listar_grupos()

        else:
            print("[GRUPO] Comandos disponíveis:")
            print("  /grupo criar <nome>         - Cria um grupo")
            print("  /grupo add <nome> <membro>  - Adiciona membro ao grupo")
            print("  /grupo entrar <nome>        - Entra na conversa de grupo")

    def _criar_grupo(self, nome_grupo):
        """Cria um novo grupo e gera a chave AES partilhada."""
        try:
            # Pedir ao servidor para criar o grupo
            utils.send_msg(self.sock, f"CMD:GRUPO:CRIAR:{nome_grupo}".encode())
            # Gerar chave AES de grupo (será confirmado na resposta)
            chave_grupo = seguranca.gerar_chave_aes_aleatoria()
            self.chaves_grupo[nome_grupo] = chave_grupo
            print(f"[GRUPO] A criar grupo '{nome_grupo}'...")
        except Exception as e:
            print(f"[GRUPO] Erro ao criar grupo: {e}")

    def _adicionar_membro_grupo(self, nome_grupo, novo_membro):
        """
        Adiciona um membro ao grupo e envia-lhe a chave AES do grupo,
        cifrada com a chave pública RSA do novo membro.
        """
        if nome_grupo not in self.chaves_grupo:
            print(f"[GRUPO] Não tens a chave do grupo '{nome_grupo}'.")
            print(f"        Só o criador pode adicionar membros.")
            return

        try:
            # Obter chave pública do novo membro
            sessao = self.obter_sessao(novo_membro)
            if not sessao:
                print(f"[GRUPO] Identidade de '{novo_membro}' não encontrada.")
                return

            # Cifrar a chave de grupo com RSA do novo membro
            chave_grupo = self.chaves_grupo[nome_grupo]
            chave_cifrada = seguranca.cifrar_chave_aes_com_rsa(sessao['rsa_pub'], chave_grupo)

            # Assinar para autenticidade
            assinatura = seguranca.assinar_dados(self.minha_rsa_priv, chave_cifrada)
            payload = seguranca.serializar_certificado_completo(chave_cifrada, assinatura)

            # Pedir ao servidor para adicionar o membro
            utils.send_msg(self.sock, f"CMD:GRUPO:ADD:{nome_grupo}:{novo_membro}".encode())

            # Enviar a chave de grupo cifrada ao novo membro via servidor
            cabecalho = f"DEST:{novo_membro}|".encode()
            msg_chave = f"GRUPO_CHAVE:{nome_grupo}:".encode() + payload
            utils.send_msg(self.sock, cabecalho + msg_chave)
            print(f"[GRUPO] A adicionar '{novo_membro}' ao grupo '{nome_grupo}'...")

        except Exception as e:
            print(f"[GRUPO] Erro ao adicionar membro: {e}")

    def _entrar_grupo(self, nome_grupo):
        """Muda para o chat de grupo."""
        if nome_grupo not in self.chaves_grupo:
            print(f"[GRUPO] Não tens a chave do grupo '{nome_grupo}'.")
            print(f"        Pede ao criador para te adicionar com /grupo add.")
            return

        self.grupo_ativo = nome_grupo
        self.chat_ativo = ""  # desativar chat privado
        print(f"\n[+] Chat de grupo '{nome_grupo.upper()}' — podes escrever!")
        print(f"[GRUPO] Mensagens cifradas com chave AES partilhada do grupo.")



    def _sair_grupo(self):
        if not self.grupo_ativo:
            print("[GRUPO] Não estás em nenhum grupo.")
            return
        nome = self.grupo_ativo
        self.grupo_ativo = None
        self.chat_ativo = ""
        print(f"[GRUPO] Saíste do chat '{nome}'.")
        print("[*] Modo normal — usa /conectar <nome> ou /grupo entrar <nome>.")

    def _listar_grupos(self):
        if not self.chaves_grupo:
            print("[GRUPO] Não pertences a nenhum grupo.")
            return
        print("\n[GRUPO] Os teus grupos:")
        for nome in self.chaves_grupo:
            ativo = " ← ativo agora" if nome == self.grupo_ativo else ""
            print(f"  • {nome}{ativo}")

    

    def _enviar_mensagem_grupo(self, texto):
        """
        Envia mensagem ao grupo, cifrada com a chave AES do grupo.
        O servidor encaminha para todos os membros.
        """
        if self.grupo_ativo not in self.chaves_grupo:
            print(f"[GRUPO] Sem chave para o grupo '{self.grupo_ativo}'.")
            return

        try:
            chave_grupo = self.chaves_grupo[self.grupo_ativo]
            pacote_cifrado = seguranca.cifrar_mensagem(chave_grupo, texto)
            assinatura = seguranca.assinar_dados(self.minha_rsa_priv, pacote_cifrado)
            envelope = seguranca.serializar_certificado_completo(pacote_cifrado, assinatura)

            cabecalho = f"GRUPO_MSG:{self.grupo_ativo}|".encode()
            utils.send_msg(self.sock, cabecalho + envelope)
        except Exception as e:
            print(f"[GRUPO] Erro ao enviar mensagem: {e}")

    def _processar_grupo_from(self, pacote):
        """
        Processa mensagem de grupo recebida do servidor.
        Formato: GRUPO_FROM:<remetente>:<grupo>|<envelope>
        """
        try:
            # Separar cabeçalho do payload
            partes = pacote.split(b"|", 1)
            if len(partes) < 2:
                return

            cabecalho = partes[0][11:].decode('utf-8')  # Remove "GRUPO_FROM:"
            partes_cab = cabecalho.split(':', 1)
            if len(partes_cab) < 2:
                return

            remetente = partes_cab[0]
            nome_grupo = partes_cab[1]
            envelope = partes[1]

            if nome_grupo not in self.chaves_grupo:
                print(f"\n[GRUPO] Mensagem do grupo '{nome_grupo}' — sem chave!", flush=True)
                return

            # Desserializar envelope
            chave_grupo = self.chaves_grupo[nome_grupo]
            pacote_cifrado, assinatura = seguranca.desserializar_certificado_completo(envelope)

            # Verificar assinatura do remetente
            sessao = self.obter_sessao(remetente)
            if sessao and not seguranca.verificar_assinatura(sessao['rsa_pub'], assinatura, pacote_cifrado):
                print(f"\n[⚠️ GRUPO] Assinatura inválida de '{remetente}'! Rejeitada.", flush=True)
                return

            # Anti-replay
            nonce = pacote_cifrado[:12]
            if not self.anti_replay.verificar_e_registar(nonce):
                print(f"\n[⚠️ GRUPO] Replay detectado de '{remetente}'!", flush=True)
                return

            # Decifrar com chave de grupo
            msg_limpa = seguranca.decifrar_mensagem(chave_grupo, pacote_cifrado)

            if self.grupo_ativo == nome_grupo:
                print(f"\n[{remetente.capitalize()} → {nome_grupo}] {msg_limpa}", flush=True)
            else:
                print(f"\n[🔔 Grupo '{nome_grupo}'] Mensagem de {remetente.capitalize()}! Usa /grupo entrar {nome_grupo}", flush=True)

        except Exception as e:
            print(f"\n[GRUPO] Erro ao processar mensagem: {e}", flush=True)

    def _processar_chave_grupo(self, pacote):
        """
        Recebe e processa a chave AES do grupo cifrada com a nossa RSA.
        Enviada pelo criador quando nos adiciona ao grupo.
        """
        try:
            # Formato: GRUPO_CHAVE:<nome_grupo>:<payload>
            conteudo = pacote[12:]  # Remove "GRUPO_CHAVE:"
            idx = conteudo.index(b':')
            nome_grupo = conteudo[:idx].decode('utf-8')
            payload = conteudo[idx+1:]

            chave_cifrada, assinatura = seguranca.desserializar_certificado_completo(payload)

            # Decifrar a chave de grupo com a nossa chave privada RSA
            chave_grupo = seguranca.decifrar_chave_aes_com_rsa(self.minha_rsa_priv, chave_cifrada)
            self.chaves_grupo[nome_grupo] = chave_grupo
            print(f"\n[🔑 GRUPO] Recebeste acesso ao grupo '{nome_grupo}'!", flush=True)
            print(f"[GRUPO] Usa /grupo entrar {nome_grupo} para participar.", flush=True)

        except Exception as e:
            print(f"\n[GRUPO] Erro ao processar chave de grupo: {e}", flush=True)

    def _processar_resposta_grupo(self, pacote):
        """Processa respostas do servidor a comandos de grupo."""
        if pacote.startswith(b"GRUPO_OK:"):
            msg = pacote[9:].decode('utf-8')
            print(f"\n[GRUPO ✓] {msg}", flush=True)
        elif pacote.startswith(b"GRUPO_ERRO:"):
            msg = pacote[11:].decode('utf-8')
            print(f"\n[GRUPO ✗] {msg}", flush=True)
        elif pacote.startswith(b"GRUPO_INFO:"):
            info = pacote[11:].decode('utf-8')
            partes = info.split(':', 1)
            if len(partes) == 2:
                criador, membros_str = partes
                membros = membros_str.split(',')
                print(f"\n[GRUPO] Criador: {criador} | Membros: {', '.join(membros)}", flush=True)

    def _processar_mensagem_grupo_recebida(self, remetente, dados, cabecalho_bytes):
        """Fallback para mensagens de grupo recebidas via FROM: (compatibilidade)."""
        pass


    # ==========================================
    # MODO PGP-LIKE — COMUNICAÇÃO SEM SERVIDOR
    #
    #  Permite trocar mensagens cifradas sem o servidor estar a correr.
    #  Útil para comunicação assíncrona via email, USB, etc.
    #
    #  /exportar <nome> <mensagem>
    #    → Cria ficheiro <nome>_<timestamp>.pgp no diretório atual
    #    → Ficheiro contém mensagem cifrada + chave AES + assinatura
    #    → Pode ser enviado por qualquer meio sem o servidor
    #
    #  /importar <ficheiro.pgp>
    #    → Lê, verifica e decifra um ficheiro .pgp recebido
    #    → Verifica assinatura do remetente automaticamente
    # ==========================================
    def _exportar_pgp(self, destinatario, mensagem):
        """
        Cria um ficheiro .pgp cifrado para o destinatário.
        Não precisa do servidor — basta ter a chave pública do destinatário.
        """
        try:
            # Obter chave pública do destinatário
            sessao = self.obter_sessao(destinatario)
            if not sessao:
                print(f"[PGP] Identidade de '{destinatario}' não encontrada.")
                print(f"      Garante que '{destinatario}_publica.pem' está em chaves_publicas/")
                return

            # Criar envelope PGP
            dados_pgp = seguranca.cifrar_para_ficheiro_pgp(
                self.minha_rsa_priv,
                self.meu_id,
                sessao['rsa_pub'],
                destinatario,
                mensagem
            )

            # Guardar ficheiro
            import time as _time
            nome_ficheiro = f"{self.meu_id}_para_{destinatario}_{int(_time.time())}.pgp"
            with open(nome_ficheiro, 'wb') as f:
                f.write(dados_pgp)

            print(f"[📦 PGP] Ficheiro criado: '{nome_ficheiro}'")
            print(f"[PGP] Envia este ficheiro ao {destinatario} por qualquer meio.")
            print(f"[PGP] Ele decifra com: /importar {nome_ficheiro}")

        except Exception as e:
            print(f"[PGP] Erro ao exportar: {e}")

    def _importar_pgp(self, caminho_ficheiro):
        """
        Lê, verifica e decifra um ficheiro .pgp recebido.
        Verifica automaticamente a assinatura do remetente.
        """
        try:
            # Ler o ficheiro
            with open(caminho_ficheiro, 'rb') as f:
                dados_pgp = f.read()

            # Precisamos saber quem é o remetente para verificar assinatura
            # Primeiro fazer parse rápido para saber o remetente
            import json as _json
            envelope = _json.loads(dados_pgp.decode('utf-8'))
            remetente = envelope.get("remetente", "")
            destinatario = envelope.get("destinatario", "")

            # Verificar que somos o destinatário
            if destinatario != self.meu_id:
                print(f"[PGP] ⚠️  Este ficheiro é para '{destinatario}', não para ti ('{self.meu_id}')!")
                return

            # Obter chave pública do remetente para verificar assinatura
            sessao = self.obter_sessao(remetente)
            if not sessao:
                print(f"[PGP] Identidade do remetente '{remetente}' não encontrada.")
                print(f"      Garante que '{remetente}_publica.pem' está em chaves_publicas/")
                return

            # Decifrar e verificar
            msg, remetente_verificado, timestamp = seguranca.decifrar_ficheiro_pgp(
                self.minha_rsa_priv,
                self.meu_id,
                sessao['rsa_pub'],
                dados_pgp
            )

            from datetime import datetime as _dt
            data_hora = _dt.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            print(f"\n[📨 PGP] Mensagem recebida de {remetente_verificado.capitalize()}")
            print(f"[PGP] Enviada em: {data_hora}")
            print(f"[PGP] Assinatura verificada ✓")
            print(f"[PGP] Conteúdo: {msg}")

        except FileNotFoundError:
            print(f"[PGP] Ficheiro '{caminho_ficheiro}' não encontrado.")
        except ValueError as e:
            print(f"[PGP] ⚠️  {e}")
        except Exception as e:
            print(f"[PGP] Erro ao importar: {e}")


if __name__ == "__main__":
    app = ClienteE2EE()
    app.iniciar()