def mkpair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)""" # [cite: 140]
    len_x = len(x) # [cite: 141]
    len_x_bytes = len_x.to_bytes(2, "little") # [cite: 143]
    return len_x_bytes + x + y # [cite: 144]


def unpair(xy):
    """extrai componentes de um par codificado com 'mkpair'""" # [cite: 146]
    len_x = int.from_bytes(xy[:2], "little") # [cite: 147]
    x = xy[2:len_x+2] # [cite: 148]
    y = xy[len_x+2:] # [cite: 149]
    return x, y # [cite: 150]

def send_msg(sock, msg_bytes):
    """Envia uma mensagem garantindo que o tamanho vai primeiro."""
    # Prefixamos a mensagem com 4 bytes que indicam o tamanho total
    msg_length = len(msg_bytes).to_bytes(4, 'big')
    sock.sendall(msg_length + msg_bytes)

def recvall(sock, n):
    """Função auxiliar para garantir que recebe exatamente n bytes (evita pacotes partidos)."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    """Recebe uma mensagem lendo primeiro o seu tamanho."""
    # Lê os primeiros 4 bytes para saber o tamanho da mensagem que aí vem
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = int.from_bytes(raw_msglen, 'big')
    # Lê exatamente o número de bytes que formam a mensagem
    return recvall(sock, msglen)