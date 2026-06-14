# Diseño, Implementación y Evaluación de un Sistema de Apoyo al Pentesting Web Automatizado y de Asistencia mediante IA

## Descripción

Este proyecto forma parte del Trabajo Fin de Máster desarrollado por **Diego Ramiro Jurado Reyna** y **José Antonio Montes Solano**.

El objetivo es el desarrollo de un sistema de apoyo al pentesting web automatizado mediante inteligencia artificial, orientado a mejorar la fase de reconocimiento en auditorías de seguridad. El sistema permite estructurar la superficie de ataque, priorizar riesgos y generar respuestas que faciliten el análisis por parte del pentester.

---

## Arquitectura del sistema

El sistema sigue una arquitectura distribuida:

- **Windows (host):** ejecuta Ollama (modelo de IA)  
- **WSL Ubuntu:** ejecuta backend, frontend y herramientas de reconocimiento  

La comunicación con la IA se realiza mediante HTTP desde WSL hacia el servicio de Ollama en Windows.

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

### 3. WSL Ubuntu

Instalar y usar una distribución Ubuntu en WSL para ejecutar el backend, el frontend y las herramientas externas del pipeline.

Desde PowerShell:

```powershell
wsl --install -d Ubuntu
```

Una vez instalado WSL, abrir Ubuntu y situarse en la carpeta del proyecto. Si el repositorio está en Windows, se puede acceder desde WSL mediante `/mnt/c/...`.

Ejemplo:

```bash
cd /mnt/c/Users/Diego/Documents/workspaceTFM/TFM
```

---

## Configuración del backend

Dentro de **WSL Ubuntu**, crear un archivo `.env` en la carpeta `backend/`:

```
OLLAMA_HOST=IP_DEL_HOST_WINDOWS
```

Ejemplo:

```
OLLAMA_HOST=192.168.1.100
```

---

## Ejecución del proyecto

Dentro de WSL Ubuntu:

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

```text
TFM/
├── backend/                  # API, orquestación del pipeline y generación de informes
│   ├── server.js             # servidor Express y rutas principales
│   ├── modules/
│   │   ├── ia/               # comunicación con Ollama
│   │   ├── reconocimiento/   # ejecución y parseo de herramientas de reconocimiento
│   │   │   ├── analizadores/ # comprobaciones pasivas y análisis auxiliares
│   │   │   └── herramientas/ # wrappers de subfinder, httpx, gau, nuclei, etc.
│   │   ├── procesamiento/    # normalización, extracción y clasificación de hallazgos
│   │   ├── priorizacion/     # scoring, correlación y agrupación de findings
│   │   └── pdf/              # plantillas, estilos, gráficas y generación de PDF
│   ├── tests/                # pruebas del backend y del pipeline
│   └── tools/                # herramientas locales usadas por el backend
├── frontend/
│   ├── index.html            # interfaz principal
│   └── app.js                # lógica de interacción con el backend
├── logs/                     # salidas y evidencias de ejecuciones
├── tools/                    # herramientas externas incluidas en el proyecto
├── setup.sh                  # instalación base de dependencias
├── herramientas.sh           # instalación/verificación de herramientas de pentesting
├── package.json              # scripts y dependencias del proyecto
└── .env.example              # ejemplo de configuración de entorno
```

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
feroxbuster -u https://demo.owasp-juice.shop --depth 1 --silent --json --time-limit 60s
echo https://demo.owasp-juice.shop | katana -silent -depth 3 -jc -kf all
gau demo.owasp-juice.shop
gf xss urls.txt
nuclei -u https://demo.owasp-juice.shop -severity low,medium,high,critical
dalfox pipe --silence --format json < urls.txt
sqlmap -u "https://testphp.vulnweb.com/listproducts.php?cat=1" --batch
trufflehog filesystem ./tmp_scan --json
```

El orden del pipeline principal es: `subfinder`, `httpx`, `headers`, `cookies`, `httpsRedirect`, `tls`, `robotsSitemap`, `ports`, `feroxbuster`, `katana`, `gau`, `gf`, `nuclei`, `dalfox`, `sqlmap`, `trufflehog`.

Los modulos `headers`, `cookies`, `httpsRedirect`, `tls` y `robotsSitemap` son pasivos/defensivos y usan APIs nativas de Node.js. `ports` usa `nmap` si esta instalado; si no, aplica un fallback TCP ligero sobre puertos comunes. Estos hallazgos se muestran como hardening, superficie o reconocimiento salvo evidencias de riesgo claro, por ejemplo certificados expirados o puertos de bases de datos/cache accesibles.

Dependencias externas recomendadas en Linux/WSL:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/gf@latest
cargo install feroxbuster
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh
sudo apt install -y nmap
```

`gf` necesita patterns en `~/.gf`; los scripts `setup.sh` y `herramientas.sh` instalan un conjunto base. En Windows nativo varias herramientas Go/Rust funcionan si estan en `PATH`, pero para TFM/demo se recomienda WSL/Linux por compatibilidad con `feroxbuster`, `gf`, `gau` y `trufflehog`.

GF solo prioriza candidatos por patron; no confirma vulnerabilidades. Del mismo modo, la ausencia de cabeceras HTTP o flags de cookies se reporta como hardening/configuracion y no debe interpretarse como XSS/SQLi confirmado.

Por defecto, Nuclei se ejecuta sobre activos HTTP vivos, usando las templates oficiales instaladas localmente. La configuracion es conservadora para TFM: severidades `critical,high,medium,low`, salida JSONL, sin color, y exclusion de tags ruidosos como `dns`, `tech`, `waf`, `cdn` y `favicon`. Esto evita que `tech-detect`, `waf-detect`, favicon o CDN se cuenten como vulnerabilidades. Nuclei complementa a Dalfox, SQLMap y TruffleHog; un resultado 0 significa que no hubo matches en las templates ejecutadas, no ausencia total de vulnerabilidades.

Para incluir severidad `info` en modo avanzado sin tratarla como vulnerabilidad:

```bash
NUCLEI_INCLUDE_INFO=true node server.js
```

Sqlmap solo se ejecuta automaticamente sobre URLs con parametros. Si no se encuentran parametros, el backend devuelve el aviso `sqlmap no se ejecuto porque no se encontraron parametros`. Para permitir un crawl ligero de sqlmap cuando no haya parametros:

```bash
SQLMAP_CRAWL_IF_NO_PARAMS=true node server.js
```

Limites configurables para mantener el analisis acotado:

```bash
NUCLEI_TEMPLATES_PATH=
NUCLEI_SEVERITIES=critical,high,medium,low
NUCLEI_INCLUDE_INFO=false
NUCLEI_TAGS=
NUCLEI_RATE_LIMIT=
NUCLEI_TIMEOUT_SECONDS=
FEROX_WORDLIST=
FEROX_DEPTH=1
FEROX_TIME_LIMIT_SECONDS=60
FEROX_THREADS=10
MAX_FEROX_TARGETS=5
MAX_FEROX_URLS=100
MAX_GAU_PARAM_URLS=100
MAX_GAU_SURFACE_URLS=100
MAX_GAU_TOTAL_AFTER_FILTER=300
MAX_GAU_PER_PATTERN=3
GAU_FILTER_EXTERNAL=true
MAX_DALFOX_URLS=50
MAX_SQLMAP_URLS=10
MAX_JS_SECRET_SCAN=20
TOOL_TIMEOUT_SECONDS=120
PASSIVE_TIMEOUT_SECONDS=8
MAX_PASSIVE_TARGETS=20
PASSIVE_PORTS=80,443,8080,8443,8000,3000,5000,5432,3306,6379,9200,27017,22,21,25
PORT_SCAN_TIMEOUT_MS=800
```

GAU ya no aplica un corte bruto temprano. Primero parsea todas las URLs historicas devueltas, descarta ruido externo/assets/trackers, deduplica por `origin + path + nombres de parametros + extension`, puntua endpoints utiles y solo despues limita por categoria. Las metricas distinguen URLs raw, validas, externas descartadas, assets descartados, duplicados/patrones descartados, URLs con parametros y seleccion final enviada a GF.

Feroxbuster registra binario, argumentos reales, wordlist usada, existencia de la wordlist, activos enviados, lineas raw, parseados JSONL y descartes por assets o status. Si no hay wordlist configurada intenta usar `common.txt` de SecLists/dirb cuando exista; si no, continua con warning claro. Una ruta interesante se reporta como superficie; exposiciones sensibles con HTTP 200, como `/.env`, `/.git`, backups o dumps SQL, se tratan como posibles vulnerabilidades para validacion.

---

## Tecnologías utilizadas

- Node.js + Express  
- Ollama (modelo de lenguaje local en Windows)  
- PDFKit  
- HTML / JavaScript  

---

## Notas

- Ollama se ejecuta en el host Windows  
- WSL Ubuntu ejecuta backend, frontend y herramientas de reconocimiento  
- Requisitos imprescindibles:
  - Ejecutar `OLLAMA_HOST=0.0.0.0 ollama serve`
  - Tener WSL Ubuntu instalado y las herramientas del pipeline disponibles en `PATH`  
  - Puerto 11434 permitido en firewall  

---

## Copyright

© 2026 Diego Ramiro Jurado Reyna y José Antonio Montes Solano.  
Todos los derechos reservados.
