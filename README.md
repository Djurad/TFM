# Diseño, Implementación y Evaluación de un Sistema de Apoyo al Pentesting Web Automatizado y de Asistencia mediante IA

## Descripción

Este proyecto forma parte del Trabajo Fin de Máster desarrollado por **Diego Ramiro Jurado Reyna** y **José Antonio Montes Solano**.

El objetivo es el desarrollo de un sistema de apoyo al pentesting web automatizado mediante inteligencia artificial, orientado a mejorar la fase de reconocimiento en auditorías de seguridad. El sistema permite estructurar la superficie de ataque, priorizar riesgos y generar respuestas que faciliten el análisis por parte del pentester.

---

## Arquitectura del sistema

El sistema sigue una arquitectura distribuida:

- **Windows (host):** ejecuta Ollama (modelo de IA)  
- **VM Ubuntu:** ejecuta backend y frontend  

La comunicación con la IA se realiza mediante HTTP en red local (modo Bridge).

---

## Requisitos previos

### 1. Ollama (en Windows)

Descargar e instalar Ollama desde:  
https://ollama.com/

Ejecutar Ollama en modo servidor accesible desde la red:

```
OLLAMA_HOST=0.0.0.0 ollama serve
```

El valor `0.0.0.0` permite que Ollama escuche peticiones desde cualquier IP, no solo desde `localhost`.

Cargar el modelo:

```
ollama run llama3
```

---

### 2. Configuración de Firewall (Windows)

Permitir conexiones al puerto **11434**:

- Crear regla de entrada en el Firewall de Windows  
- Puerto: **11434**  
- Protocolo: TCP  
- Acción: Permitir  

---

### 3. Máquina Virtual

Descargar la máquina virtual desde:

https://mega.nz/file/qg5lyLSJ#GnHkTm_CB2LKYAp0zaberoXwaJgXXLv96XaFEvUU7Kk

#### Configuración recomendada

- Memoria RAM: **8 GB**
- La máquina debe estar encendida antes de ejecutar el sistema

#### Configuración de red (IMPORTANTE)

Configurar la VM en **modo Bridge (Adaptador Puente)**:

1. Configuración de la VM  
2. Red → Adaptador 1  
3. Tipo: Adaptador puente  
4. Seleccionar interfaz de red del host  

---

## Configuración del backend

Dentro de la **VM Ubuntu**, crear un archivo `.env` en la carpeta `backend/`:

```
OLLAMA_HOST=IP_DEL_HOST_WINDOWS
```

Ejemplo:

```
OLLAMA_HOST=192.168.1.100
```

---

## Ejecución del proyecto

Dentro de la VM Ubuntu:

```
cd backend
npm install
node server.js
```

Abrir en el navegador:

```
http://localhost:3000
```

---

## Estructura del proyecto

### backend/

- `server.js` → rutas principales y servidor  
- `.env` → configuración del entorno  

#### modules/
- `ia.js` → comunicación con Ollama  
- `procesamiento.js` → tratamiento de datos  
- `reconocimiento.js` → análisis de superficie de ataque  
- `scoring.js` → priorización de riesgos  

#### utils/
- `pdf.js` → generación de informes en PDF  

- `node_modules/` → dependencias  
- `package.json` / `package-lock.json` → configuración  

---

### frontend/

- `index.html` → interfaz principal  
- `app.js` → lógica de interacción con backend  

---

## Funcionamiento

1. El usuario introduce un prompt  
2. El frontend envía la petición al backend  
3. El backend consulta el modelo de IA (Ollama en Windows)  
4. Se obtiene la respuesta  
5. Se muestra o se descarga en PDF  

---

## Pruebas manuales de herramientas

Estos comandos permiten validar el pipeline por separado antes de ejecutar el analisis completo desde la interfaz:

```bash
subfinder -d demo.owasp-juice.shop
echo demo.owasp-juice.shop | httpx -title -tech-detect -status-code
katana -u https://demo.owasp-juice.shop
sqlmap -u "https://testphp.vulnweb.com/listproducts.php?cat=1" --batch
nuclei -u https://demo.owasp-juice.shop -severity low,medium,high,critical
gau demo.owasp-juice.shop
gf xss urls.txt
feroxbuster -u https://demo.owasp-juice.shop --depth 2 --silent --json
trufflehog filesystem ./tmp_scan --json
```

Por defecto, Nuclei excluye resultados informativos y tags ruidosos como `dns`, `tech`, `waf`, `cdn` y `favicon`. Para incluir severidad `info` en modo avanzado sin tratarla como vulnerabilidad:

```bash
NUCLEI_INCLUDE_INFO=true node server.js
```

Sqlmap solo se ejecuta automaticamente sobre URLs con parametros. Si no se encuentran parametros, el backend devuelve el aviso `sqlmap no se ejecuto porque no se encontraron parametros`. Para permitir un crawl ligero de sqlmap cuando no haya parametros:

```bash
SQLMAP_CRAWL_IF_NO_PARAMS=true node server.js
```

Limites configurables para mantener el analisis acotado:

```bash
MAX_GAU_URLS=500
MAX_FEROX_URLS=100
MAX_DALFOX_URLS=50
MAX_SQLMAP_URLS=10
MAX_JS_SECRET_SCAN=20
TOOL_TIMEOUT_SECONDS=120
```

---

## Tecnologías utilizadas

- Node.js + Express  
- Ollama (modelo de lenguaje local en Windows)  
- PDFKit  
- HTML / JavaScript  

---

## Notas

- Ollama se ejecuta en el host Windows  
- La VM Ubuntu ejecuta backend y frontend  
- Requisitos imprescindibles:
  - Ejecutar `OLLAMA_HOST=0.0.0.0 ollama serve`
  - VM en modo Bridge  
  - Puerto 11434 permitido en firewall  

---

## Copyright

© 2026 Diego Ramiro Jurado Reyna y José Antonio Montes Solano.  
Todos los derechos reservados.
