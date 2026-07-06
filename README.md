# Diseño, Implementación y Evaluación de un Sistema de Apoyo al Pentesting Web Automatizado y de Asistencia mediante IA

## Descripción

Este proyecto forma parte del Trabajo Fin de Máster desarrollado por **Diego Ramiro Jurado Reyna** y **José Antonio Montes Solano**.

La herramienta implementa una plataforma de apoyo al pentesting web que automatiza tareas de reconocimiento, clasificación de hallazgos, priorización de riesgos, enriquecimiento mediante inteligencia artificial local y generación de informes técnicos en PDF.

El objetivo no es sustituir al pentester, sino acelerar la fase de descubrimiento y análisis inicial: la herramienta recopila evidencias, separa vulnerabilidades confirmadas de candidatos o elementos de superficie, estima criticidad y probabilidad, y presenta la información de forma trazable para facilitar la validación manual y la remediación.

---

## Qué realiza la herramienta

La aplicación ejecuta un pipeline completo de auditoría web defensiva sobre un dominio o URL autorizado. A alto nivel:

1. Normaliza el objetivo introducido por el usuario.
2. Descubre subdominios y activos HTTP/HTTPS vivos.
3. Ejecuta comprobaciones pasivas de configuración.
4. Descubre rutas, endpoints y URLs históricas.
5. Prioriza candidatos mediante patrones de seguridad.
6. Ejecuta herramientas de validación como Dalfox, SQLMap, Nuclei y TruffleHog cuando aplica.
7. Normaliza y deduplica todos los hallazgos.
8. Clasifica cada hallazgo por estado: confirmado, posible, candidato, hardening, superficie, informativo o descartado.
9. Enriquece individualmente con IA todos los hallazgos reportables.
10. Calcula una puntuación global final mediante una revisión IA sobre todos los hallazgos enriquecidos.
11. Muestra los resultados en la interfaz web.
12. Genera un informe PDF solo si la cobertura de IA es completa.

La herramienta distingue expresamente entre:

- **Vulnerabilidades confirmadas:** evidencias reproducibles o de alta confianza.
- **Vulnerabilidades posibles:** indicios relevantes que requieren validación adicional.
- **Candidatos GF:** URLs o parámetros priorizados por patrones, pero no confirmados.
- **Hardening:** mejoras defensivas de configuración.
- **Superficie:** recursos o servicios expuestos que amplían el reconocimiento.
- **Informativos:** datos útiles de inventario o contexto.
- **Descartados:** ruido, duplicados o elementos no reportables.

---

## Filosofía de análisis

El sistema está diseñado para evitar dos errores habituales en informes automatizados:

- Inflar candidatos o superficie como si fueran vulnerabilidades confirmadas.
- Ocultar carencias del análisis mediante textos genéricos o plantillas.

Por ello, la herramienta separa:

- **criticidad potencial**, es decir, el impacto si el hallazgo se confirma;
- **probabilidad real**, basada en la evidencia disponible;
- **estado del hallazgo**, por ejemplo confirmado, posible, candidato o hardening;
- **evidencia técnica**, herramienta, endpoint, parámetro, payload y observaciones;
- **confianza**, según la calidad de la señal;
- **riesgo global**, calculado después de revisar todos los hallazgos enriquecidos.

Los candidatos críticos de GF, por ejemplo un posible RCE, se muestran como criticidad potencial alta o crítica, pero con probabilidad baja si no existe ejecución confirmada. Del mismo modo, un hallazgo de superficie como Swagger/OpenAPI público no se presenta como vulnerabilidad confirmada, sino como exposición útil para reconocimiento.

---

## Enriquecimiento obligatorio mediante IA

La IA es una parte central del sistema. Todos los hallazgos reportables deben pasar por una llamada individual al modelo local.

Son reportables:

- confirmados;
- posibles;
- candidatos GF;
- hardening;
- superficie;
- informativos si aparecen en el informe.

No se enriquecen:

- descartados;
- duplicados internos;
- ruido no mostrado;
- assets descartados.

Cada hallazgo reportable recibe una petición IA individual con un JSON compacto del hallazgo. La IA debe devolver, como mínimo:

```json
{
  "impact": "Impacto concreto del hallazgo.",
  "recommendation": "Recomendación técnica concreta.",
  "severity": "critical|high|medium|low|info",
  "probability": 0,
  "confidence": "high|medium|low",
  "status": "confirmed|possible|candidate|hardening|surface|informational"
}
```

Los campos realmente imprescindibles para aceptar un enriquecimiento son `impact` y `recommendation`. Los campos cortos, como estado, severidad, probabilidad y confianza, pueden completarse o corregirse mediante guardrails deterministas si la respuesta IA es útil pero incompleta.

La salida final visible del hallazgo debe venir de IA o de una reparación de texto devuelto por IA. No se usan plantillas como impacto o recomendación final.

---

## Control de cobertura IA

Antes de generar el PDF se valida la cobertura de enriquecimiento.

Para cada hallazgo reportable se exige:

- `aiProcessed = true`;
- impacto procedente de IA o texto IA reparado;
- recomendación procedente de IA o texto IA reparado;
- ausencia de templates finales;
- ausencia de fallback genérico final.

Si la cobertura no es del 100 %, el informe queda bloqueado cuando `AI_REQUIRE_ALL_FINDINGS=true`.

Ejemplo de estado correcto:

```text
[SUCCESS] analisis ia - 35/35 hallazgos enriquecidos por IA, templates finales usados: 0
[SUCCESS] score global ia - 78/100 Riesgo high
```

---

## Scoring global

La herramienta calcula primero un score determinista interno y, después, si todos los hallazgos reportables han sido enriquecidos correctamente, solicita a la IA una revisión global.

La revisión global recibe un resumen compacto de todos los hallazgos enriquecidos:

- identificador;
- herramienta;
- familia;
- estado;
- criticidad;
- probabilidad;
- confianza;
- endpoint;
- resumen de impacto.

La IA devuelve una puntuación final sobre 100:

```json
{
  "score": 0,
  "riskLevel": "critical|high|medium|low|info",
  "reason": "",
  "mainDrivers": [],
  "whyNotHigher": "",
  "whyNotLower": ""
}
```

El score final mostrado en la interfaz y el PDF procede de esta revisión global IA cuando la cobertura es completa.

Existen guardrails para evitar resultados incoherentes:

- un candidato crítico con probabilidad baja no convierte por sí solo el sitio en crítico
- el riesgo crítico global requiere evidencia crítica confirmada
- un XSS confirmado de severidad alta no debe quedar hundido en un score bajo
- hardening y superficie no pesan como vulnerabilidades confirmadas
- los posibles pesan menos que los confirmados
- los candidatos pesan menos que los posibles

---

## Pipeline de herramientas

El orden principal del pipeline es:

```text
subfinder
httpx
headers
cookies
httpsRedirect
tls
robotsSitemap
ports
feroxbuster
katana
gau
gf
nuclei
dalfox
sqlmap
trufflehog
IA individual
score global IA
PDF
```

### Herramientas y módulos usados

| Componente | Función |
| --- | --- |
| `subfinder` | Descubrimiento de subdominios. |
| `httpx` | Identificación de activos vivos, códigos HTTP, títulos y tecnologías. |
| `headers` | Revisión pasiva de cabeceras de seguridad y banners. |
| `cookies` | Revisión de flags como `Secure`, `HttpOnly` y `SameSite`. |
| `httpsRedirect` | Comprobación de redirección HTTP a HTTPS. |
| `tls` | Análisis de certificado, expiración y metadatos TLS. |
| `robotsSitemap` | Revisión de `robots.txt` y `sitemap.xml`. |
| `ports` | Detección de puertos comunes abiertos con `nmap` o fallback TCP. |
| `feroxbuster` | Descubrimiento de rutas y recursos ocultos o sensibles. |
| `katana` | Crawling de endpoints modernos. |
| `gau` | Recuperación de URLs históricas desde fuentes públicas. |
| `gf` | Priorización de candidatos por patrones de XSS, SQLi, SSRF, LFI, RCE u Open Redirect. |
| `nuclei` | Detección basada en plantillas de vulnerabilidades conocidas, con configuración conservadora. |
| `dalfox` | Validación automatizada de XSS. |
| `sqlmap` | Validación automatizada de SQL Injection sobre URLs parametrizadas. |
| `trufflehog` | Búsqueda de secretos en recursos JavaScript o ficheros relevantes. |
| `Ollama` | Modelo de IA local usado para enriquecer hallazgos y revisar el score global. |

---

## Arquitectura

La arquitectura recomendada para la demo y el desarrollo es:

- **Windows host:** ejecuta Ollama y el modelo de lenguaje local.
- **WSL Ubuntu:** ejecuta backend, frontend y herramientas de pentesting.
- **Frontend web:** interfaz HTML/JavaScript servida por Express.
- **Backend Node.js:** orquesta herramientas, procesamiento, IA, scoring y PDF.

La comunicación con Ollama se realiza mediante HTTP hacia el puerto `11434`.

```text
Usuario
  │
  ▼
Frontend web
  │
  ▼
Backend Node.js / Express
  │
  ├─ Herramientas externas: subfinder, httpx, katana, gau, gf, nuclei, dalfox, sqlmap...
  ├─ Analizadores pasivos: headers, cookies, TLS, redirects, ports...
  ├─ Procesamiento: normalización, deduplicación, clasificación y correlación
  ├─ IA individual: enriquecimiento por hallazgo reportable
  ├─ IA global: score final sobre 100
  └─ PDFKit: generación de informe
```

---

## Estructura del proyecto

```text
TFM/
├── backend/
│   ├── server.js                         # servidor Express y endpoints principales
│   ├── scanLogger.js                     # logging detallado de ejecuciones
│   ├── modules/
│   │   ├── ia/                           # conexión con Ollama, prompts, cobertura y score global
│   │   ├── reconocimiento/               # ejecución del pipeline de herramientas
│   │   │   ├── analizadores/             # módulos pasivos: headers, cookies, TLS, puertos...
│   │   │   └── herramientas/             # wrappers de subfinder, httpx, katana, gau, etc.
│   │   ├── procesamiento/                # extractores, normalización y clasificación de findings
│   │   ├── priorizacion/                 # scoring, grupos, correlaciones y reconciliación
│   │   ├── pipeline/                     # estados auxiliares de herramientas
│   │   └── pdf/                          # PDFKit, estilos, utilidades y plantilla de informe
│   ├── tests/                            # pruebas automatizadas del backend
│   └── package.json
├── frontend/
│   ├── index.html                        # interfaz principal
│   └── app.js                            # lógica de UI, streaming y renderizado de resultados
├── logs/                                 # logs de análisis y depuración
├── tools/                                # herramientas externas incluidas, como sqlmap
├── setup.sh                              # instalación completa recomendada
├── herramientas.sh                       # instalación/verificación alternativa de herramientas
├── .env.example                          # ejemplo de configuración
└── README.md
```

---

## Requisitos previos

### Sistema recomendado

- Windows 10/11.
- WSL2 con Ubuntu.
- Node.js 20 o superior en WSL.
- Go, Cargo/Rust y herramientas de pentesting disponibles en `PATH`.
- Ollama instalado en Windows.
- Modelo compatible cargado en Ollama, por defecto `llama3`.

### Dependencias principales del backend

- `express`
- `cors`
- `dotenv`
- `pdfkit`

---

## Instalación

### 1. Instalar Ollama en Windows

Descargar Ollama desde:

```text
https://ollama.com/
```

Iniciar Ollama escuchando en todas las interfaces:

```powershell
$env:OLLAMA_HOST="0.0.0.0"
ollama serve
```

Cargar el modelo:

```powershell
ollama run llama3
```

Si se usa otro modelo, puede configurarse con `OLLAMA_MODEL` en `backend/.env`.

### 2. Permitir el puerto de Ollama

En el Firewall de Windows, permitir conexiones TCP entrantes al puerto:

```text
11434
```

Esto permite que el backend ejecutado en WSL consulte el servicio Ollama del host Windows.

### 3. Instalar WSL Ubuntu

Desde PowerShell:

```powershell
wsl --install -d Ubuntu
```

Abrir Ubuntu y situarse en la carpeta del proyecto. Si el repositorio está en Windows:

```bash
cd /mnt/c/Users/Asus/Desktop/TFM
```

### 4. Instalar dependencias y herramientas

Ejecutar el script de instalación:

```bash
chmod +x setup.sh
./setup.sh
```

También existe un script alternativo centrado en herramientas:

```bash
chmod +x herramientas.sh
./herramientas.sh
```

Los scripts instalan o verifican herramientas como:

- subfinder;
- httpx;
- katana;
- nuclei;
- dalfox;
- gau;
- gf;
- feroxbuster;
- trufflehog;
- nmap;
- sqlmap en `tools/sqlmap`.

---

## Configuración

Crear el archivo `backend/.env` a partir de `.env.example`:

```bash
cp .env.example backend/.env
```

Configurar como mínimo la dirección del host Windows donde escucha Ollama:

```env
OLLAMA_HOST=192.168.1.100
OLLAMA_MODEL=llama3
```

También se puede usar una URL completa:

```env
OLLAMA_HOST=http://192.168.1.100:11434
```

### Configuración IA recomendada

```env
AI_MODE=complete
AI_REQUIRE_ALL_FINDINGS=true
AI_DISABLE_TEMPLATES=true
AI_MAX_FINDINGS=0
AI_MAX_INDIVIDUAL_FINDINGS=0
AI_ENABLED_FOR_GF=true
AI_ENABLED_FOR_SURFACE=true
AI_ENABLED_FOR_LOW_HARDENING=true
AI_DISABLE_TIMEOUTS=true
AI_TIMEOUT_MS=0
AI_SINGLE_FINDING_TIMEOUT_MS=0
OLLAMA_REQUEST_TIMEOUT_MS=0
AI_WAIT_LOG_INTERVAL_MS=60000
```

Interpretación:

- `AI_MODE=complete`: todos los hallazgos reportables pasan por IA.
- `AI_REQUIRE_ALL_FINDINGS=true`: el PDF se bloquea si falta cobertura IA.
- `AI_DISABLE_TEMPLATES=true`: las plantillas no pueden ser salida final.
- `AI_MAX_FINDINGS=0` y `AI_MAX_INDIVIDUAL_FINDINGS=0`: sin límite de hallazgos.
- `AI_DISABLE_TIMEOUTS=true`: no se cancela una llamada IA por timeout artificial.
- `AI_TIMEOUT_MS=0`: sin límite de espera para IA.

### Límites del pipeline

Variables útiles incluidas en `.env.example`:

```env
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

ENABLE_GAU=true
GAU_PROVIDERS=otx
GAU_TIMEOUT_SECONDS=10
GAU_FALLBACK_PROVIDERS=wayback,commoncrawl,urlscan
GAU_ENABLE_PROVIDER_FALLBACK=true
GAU_ENABLE_WAYBACKURLS_FALLBACK=true
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

---

## Ejecución

Instalar dependencias del backend:

```bash
cd backend
npm install
```

Arrancar el servidor:

```bash
npm start
```

O directamente:

```bash
node server.js
```

Abrir la interfaz:

```text
http://localhost:3000
```

Desde la interfaz se introduce el dominio o URL objetivo y se inicia el análisis. El endpoint de streaming muestra el progreso de cada herramienta y devuelve los resultados al finalizar.

---

## Interfaz web

La interfaz muestra:

- estado de ejecución de cada herramienta;
- métricas de superficie, vulnerabilidades, candidatos y hardening;
- score global final;
- grupos de hallazgos;
- tarjetas individuales;
- impacto y recomendación enriquecidos por IA;
- criticidad potencial;
- probabilidad real;
- estado del hallazgo;
- herramienta que originó el resultado;
- indicador de verificación para hardening, superficie e informativos;
- botón de generación de PDF.

Para hallazgos confirmados, posibles y candidatos se muestra porcentaje de probabilidad real. Para hardening, superficie e informativos se muestra como observado o no aplicable, evitando aparentar que falta un dato.

---

## Informe PDF

El PDF incluye:

- portada ejecutiva
- resumen de riesgo
- métricas del análisis
- timeline del pipeline
- hallazgos confirmados y posibles
- candidatos GF
- hardening
- superficie de ataque
- correlaciones relevantes
- recomendaciones
- anexo técnico
- métricas de cobertura IA
- estado del score global IA

El PDF se bloquea si:

- no hay cobertura IA completa
- algún hallazgo reportable sigue pendiente
- el score global IA no se ha calculado correctamente
- se detectan plantillas o fallbacks finales como impacto/recomendación

---

## Logs y trazabilidad

Cada análisis genera trazas detalladas en consola y en la carpeta `logs/`.

Los logs registran, entre otros:

- objetivo analizado;
- herramientas ejecutadas;
- argumentos usados;
- métricas por herramienta;
- findings deterministas;
- findings normalizados;
- correlaciones;
- llamadas IA por hallazgo;
- respuestas IA;
- validación de idioma;
- reparación de respuestas no JSON;
- guardrails aplicados;
- cobertura IA;
- score determinista previo;
- score final IA;
- motivo de bloqueo del PDF si aplica.

Ejemplos de eventos IA:

```text
[AI-COVERAGE-PLAN]
[AI-FINDING-START]
[AI-FINDING-REQUEST]
[AI-FINDING-RAW-RESPONSE]
[AI-NORMALIZE]
[AI-VALIDATION]
[AI-RETRY]
[AI-FINDING-END]
[AI-COVERAGE-STATS]
[AI-FINAL-SCORE-VALIDATED]
```

---

## Pruebas

Las pruebas del backend se ejecutan desde `backend/`:

```bash
cd backend
npm test
```

La suite valida, entre otros aspectos:

- selección completa de hallazgos reportables para IA;
- contrato mínimo de IA;
- reparación de respuestas no JSON;
- bloqueo del PDF si falta cobertura;
- ausencia de templates finales;
- guardrails de probabilidad y severidad;
- candidatos GF;
- hardening y superficie;
- presentación de probabilidad u observado;
- score conservador;
- parsing de herramientas;
- calidad del pipeline.

---

## Consideraciones sobre herramientas

### GF

GF no confirma vulnerabilidades. Solo prioriza URLs o parámetros que coinciden con patrones conocidos. Sus resultados se clasifican como candidatos y requieren validación manual o confirmación mediante herramientas específicas.

Ejemplos:

- GF RCE: criticidad potencial crítica, probabilidad baja si no hay ejecución.
- GF SQLi: criticidad potencial alta, probabilidad baja/media hasta validar.
- GF SSRF: criticidad potencial alta, sin afirmar acceso interno si no hay callback o evidencia.
- GF LFI: criticidad potencial alta, sin afirmar lectura de archivos si no hay prueba.
- GF Open Redirect: criticidad potencial media, pendiente de confirmación.

### Nuclei

Nuclei se ejecuta con una configuración conservadora. Por defecto se usan severidades `critical,high,medium,low` y se evitan tags ruidosos como tecnología, CDN, WAF o favicon para no convertir fingerprinting en vulnerabilidad.

Un resultado vacío de Nuclei no significa que no existan vulnerabilidades; solo significa que no hubo coincidencias en las plantillas ejecutadas.

### Dalfox

Dalfox se usa para validar XSS. Un XSS confirmado por Dalfox con payload reproducible se mantiene como confirmado y con probabilidad alta. No se eleva automáticamente a crítico salvo evidencia adicional, como robo de sesión, acciones privilegiadas o datos sensibles.

### SQLMap

SQLMap se ejecuta automáticamente sobre URLs con parámetros. Si no se descubren parámetros, el backend devuelve un aviso y no fuerza la ejecución.

### Feroxbuster

Feroxbuster descubre rutas y recursos. Las rutas interesantes se reportan como superficie. Recursos sensibles como `.env`, `.git`, backups o dumps pueden clasificarse como posibles vulnerabilidades si hay evidencia suficiente.

### GAU y Katana

GAU recupera URLs históricas y Katana descubre endpoints mediante crawling. El sistema filtra ruido, assets estáticos, duplicados y rutas externas antes de enviar resultados a GF o IA.

### TruffleHog

TruffleHog revisa recursos JavaScript o ficheros descargables seleccionados para detectar secretos. Los secretos verificados tienen mayor prioridad que los posibles.

---

## Limitaciones

- La herramienta no sustituye la validación manual de un pentester.
- Los candidatos GF deben confirmarse antes de reportarlos como vulnerabilidades reales.
- La ausencia de hallazgos no garantiza ausencia de vulnerabilidades.
- El resultado depende de la disponibilidad de herramientas externas y del modelo IA local.
- Las pruebas activas pueden generar tráfico y deben ejecutarse solo con autorización.
- El enriquecimiento IA puede tardar si hay muchos hallazgos reportables y el modelo local es lento.

---

## Uso ético y legal

Este proyecto debe utilizarse exclusivamente sobre sistemas propios, entornos de laboratorio o activos para los que exista autorización expresa. El objetivo es defensivo, académico y orientado a la mejora de seguridad.

No debe emplearse para analizar, explotar, degradar o recopilar información de sistemas de terceros sin permiso.

---

## Tecnologías utilizadas

- Node.js
- Express
- JavaScript
- HTML/CSS
- PDFKit
- Ollama
- subfinder
- httpx
- katana
- gau
- gf
- nuclei
- dalfox
- sqlmap
- feroxbuster
- trufflehog
- nmap

---

## Autores

Trabajo Fin de Máster desarrollado por:

- **Diego Ramiro Jurado Reyna**
- **José Antonio Montes Solano**

---

## Copyright

© 2026 Diego Ramiro Jurado Reyna y José Antonio Montes Solano.  
Todos los derechos reservados.
