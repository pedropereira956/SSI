#!/bin/bash

# Exercício 0
cat /etc/passwd
cat /etc/group

# Exercício 1
sudo adduser alice --disabled-password --gecos ""
sudo adduser bob --disabled-password --gecos ""
sudo adduser carlos --disabled-password --gecos ""

# Exercício 2
sudo groupadd grupo-ssi
sudo groupadd par-ssi
sudo gpasswd -a alice grupo-ssi
sudo gpasswd -a bob grupo-ssi
sudo gpasswd -a carlos grupo-ssi
sudo gpasswd -a alice par-ssi
sudo gpasswd -a bob par-ssi

# Exercício 3
cat /etc/passwd
cat /etc/group
# Diferenças face ao Exercício 0:
# - /etc/passwd tem 3 novas entradas: alice, bob e carlos
# - /etc/group tem os novos grupos grupo-ssi e par-ssi com os respetivos membros

# Exercício 4
sudo chown alice braga.txt
ls -l braga.txt

# Exercício 5
cat braga.txt
# Resultado: Permission denied - ubuntu não é dono nem tem permissões no ficheiro

# Exercício 6
su - alice

# Exercício 7
id
groups
# uid=1001(alice) gid=1001(alice) groups=1001(alice),100(users),1004(grupo-ssi),1005(par-ssi)
# id mostra o UID, GID principal e grupos secundários de alice.
# groups confirma os mesmos grupos de forma resumida.

# Exercício 8
cat /home/ubuntu/braga.txt
# Resultado: Permission denied
# Apesar de alice ser dona do ficheiro, não tem permissão x
# na diretoria /home/ubuntu (drwxr-x---), sendo tratada como "outros".

# Exercício 9
cd /home/ubuntu/dir2
# Resultado: Permission denied
# dir2 tem permissões drwx------ logo apenas ubuntu pode entrar.
