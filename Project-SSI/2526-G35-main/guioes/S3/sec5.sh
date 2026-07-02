#!/bin/bash

# Exercício 1
capsh --print
# Exercício 2
cat > webserver.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error when creating socket");
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error on bind");
        close(sockfd);
        return 1;
    }
    printf("Success: binded to port %d\n", port);
    close(sockfd);
    return 0;
}
EOF

# Compilar
gcc webserver.c -o webserver
ls -l webserver
# Exercício 3
./webserver 80
# Resultado: "Error on bind: Permission denied"
# Portas abaixo de 1024 são privilegiadas em Linux.
# Um utilizador comum não pode fazer bind a estas portas.
# Seria necessário ser root OU ter a capability CAP_NET_BIND_SERVICE.
sudo setcap cap_net_bind_service=ep webserver
getcap webserver
./webserver 80
# Resultado: "Success: binded to port 80"
# Atribuindo apenas CAP_NET_BIND_SERVICE ao executável, o programa
# consegue fazer bind à porta 80 sem precisar de privilégios root.
# Isto demonstra o princípio do menor privilégio — em vez de dar
# acesso root completo, atribuímos apenas a capability necessária.
# Comparando com setuid root: setuid daria TODOS os privilégios root
# ao processo, enquanto capabilities permitem uma granularidade muito
# maior e muito mais segura.
