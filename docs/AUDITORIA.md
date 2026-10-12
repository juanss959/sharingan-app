# Auditoría técnica de Sharingan — Diagnóstico para evolución a plataforma de Web Pentesting

**Fecha:** 2026-10-12
**Alcance:** revisión de solo lectura de todo el backend (`app.py`, ~2996 líneas) y el frontend (`templates/index.html`, ~1645 líneas).
**Método:** inspección módulo por módulo (8 inspectores en paralelo) + verificación cruzada. Cada afirmación está anclada a `archivo:línea`.
**Estado de implementación:**
- ✅ **P0 (lote de seguridad) — IMPLEMENTADO Y VERIFICADO** (2026-10-12). Ver §10.
- ✅ **P1 #5 (motor de validación central) + #6 (http_probe compartido) — IMPLEMENTADO Y VERIFICADO** (2026-10-12). Ver §10.
- ✅ **P1 #7 (wildcard DNS + resolución + scope anclado + gate SSRF en FASE 3/4) + #8 (cancelación real de subprocesos + estado de error visible + reconciliación de scans) — IMPLEMENTADO Y VERIFICADO** (2026-10-12). Ver §10.
- ✅ **P1 #9 (dedup de nuclei) — IMPLEMENTADO Y VERIFICADO** (2026-10-12): dedup de filas existentes + índice único `(scan_id, template, host, matched_at)` + `INSERT OR IGNORE`. **Con esto P1 queda 100% completo.** Verificado: dup exacto borrado, `matched_at` distinto conservado (sin sobre-dedup), reinserción ignorada.
- Pendiente de aprobación: todo **P2** (assets↔findings, proyectos/alcance, workflows, reportes, fix cross-client) y **P3** (IA, feroxbuster/katana).
- También se corrigieron 2 defectos del refactor de fuzzing de esta sesión (§10).

---

## 1. Estado actual de Sharingan

Sharingan es una **app web local de recon/pentesting** en **Flask + Flask-SocketIO** (un único `app.py` monolítico + un `index.html` SPA en vanilla JS). Persiste en **SQLite** (WAL). Orquesta herramientas CLI externas (subfinder, sublist3r, assetfinder, httpx, nmap, nuclei, ffuf, waybackurls, gau, curl, gh) y hace algunas comprobaciones nativas en Python (WHOIS por socket, SSL, OSINT).

Tiene dos "mundos" que **comparten muy poco**:

1. **Scan por fases** (`start_scan` → `run_scan`, `app.py:2574-2868`): pipeline fijo de 7 fases (recon pasivo → subdominios → hosts vivos → puertos → vulns → directorios → URLs históricas) que escribe en las 8 tablas y se consulta por `/api/scans/<id>`.
2. **Herramientas standalone** por socket: Fuzzing, 403 Bypass, OSINT (dominio), User OSINT (usuario/email) y verificación httpx. Estas emiten resultados por socket; **casi ninguna persiste** (excepción: el fuzzing, tras el refactor de esta sesión).

**Lo que realmente funciona** (27 módulos "works" de 48 aspectos auditados): el scan completo corre de punta a punta, los renderers del frontend muestran los resultados, el módulo de **Fuzzing es el más maduro** (tras el refactor: ejecución sin shell, gate SSRF, baseline soft-404, concurrencia, clasificación de interés, WAF/stack, recursión, persistencia).

**Lo que NO existe** (la brecha vs. "plataforma profesional"): gestión de **proyectos y alcance autorizado**, un **motor central de validación** con taxonomía verificado/probable/falso-positivo/no-concluyente, **orquestación/workflows** configurables, un **modelo de datos correlacionado** (assets/findings), **gestión de hallazgos y reportes** profesionales, y **copiloto de IA**.

**Veredicto global:** Sharingan hoy es un **ejecutor de herramientas con buena UI**, no una plataforma de validación. La calidad del motor de fuzzing demuestra que el patrón correcto ya está en el código; el problema es que **ese patrón no se aplicó al resto**.

---

## 2. Inventario de módulos

| Módulo | Estado | Herramientas | Problemas principales | Mejora recomendada | Prio |
|---|---|---|---|---|---|
| **WHOIS** (`215-257`,`293-314`) | works | socket puerto 43 | Mapa TLD→servidor hardcodeado (8 entradas) falla en ccTLDs/multinivel; scrape por regex sin normalizar; GDPR deja campos vacíos | RDAP (JSON) como primario + referral IANA; normalizar fechas | P2 |
| **DNS records** (`317-334`,`199-212`) | works | PowerShell `Resolve-DnsName` vía `.ps1` temporal | **Inyección PowerShell** por `$d='{domain}'`; Windows-only; sin DNSSEC/CAA/DMARC/SPF; usa resolver local (split-horizon) | **dnspython** (quita inyección, temp-file y dependencia Windows); añadir CAA/DMARC/SPF | **P1** |
| **Tecnologías** (`346-465`) | works | `curl` (shell=True) + regex | FP alto: substrings (`cloudflare`,`gtag`) casan en comentarios; cookies mal atribuidas; **inyección por `domain`** | Fingerprinter real (webanalyze/nuclei-tech); fetch con `requests`; separar authoritative vs inferido | P2 |
| **Security Headers** (`366-410`) | works | `curl -sI -L` + regex | Lee cabeceras de un hop intermedio por `-L`; "MISSING" puede ser falso | Evaluar solo la respuesta final; vía `requests` | P2 |
| **SSL/TLS** (`260-288`) | partial | `ssl`,`socket` | Usa contexto **verificado** → cert expirado/self-signed/mismatch **no se parsea** (justo los casos interesantes) | Contexto sin verificar para recolectar + **reportar** el resultado de validación | P2 |
| **Subdominios** (`2588`,`2611-2653`) | works | crt.sh, subfinder, sublist3r, assetfinder | Filtro de scope por **substring** (`domain in s`) → acepta out-of-scope; sin resolución DNS; **sin wildcard DNS**; **inyección por `domain`** | Scope por sufijo (`==domain or endswith('.'+domain)`); resolver y descartar NXDOMAIN; detectar wildcard | **P1** |
| **Hosts Vivos** (`2660-2695`) | works | httpx | "Vivo" = devolvió JSON (400/403/500 cuentan igual); **sin wildcard/soft-404**; **sin gate SSRF** (FASE 3) | Baseline wildcard por zona; reusar `get_baseline`; aplicar `_assert_public_target`; guardar IP | **P1** |
| **Puertos** (`2701-2735`) | works | nmap `-sV -T4 --top-ports 100` | Guarda `filtered` como accionable; parse por regex de stdout frágil; **código muerto** de IP (`2718-2723`); **sin gate SSRF** | Dedup por IP; parsear `-oX` XML; solo `open`; `run_argv` | **P1** |
| **OSINT dominio** (`590-810`) | works | requests, GitHub API, Wayback | **Sin gate SSRF** + `verify=False`; emails/secretos GitHub sin validar (son counts); **no persiste** | Gatear target; quitar `verify=False`; URL-encode; persistir con `scan_id` | **P1** |
| **User OSINT** (`1399-...`) | works | ~60 endpoints 3rd-party | Username/email **interpolado crudo** en URLs (query tampering, 1 GraphQL inj.); 35 requests sin pool/backoff; no persiste | Validar/encodear; pool + backoff; persistir | P2 |
| **Vulns (nuclei)** (`2746-2771`) | works | nuclei | Dump crudo sin dedup ni verificación; descarta evidencia (matcher/cvss/req-resp); cancel solo tras terminar | Guardar evidencia completa; stream + cancel; dedup | **P1** |
| **Vulns (nikto)** | **stub** | — | Nombrado en el scope pero **no implementado** | Añadir vía `run_argv` + parse JSON, o quitarlo del producto | P2 |
| **Directorios (FASE 6)** (`2782-2806`) | works | `run_fuzzing` (ffuf/nativo) | Cap arbitrario `alive[:5]` silencioso; `likely_real` NULL; `except:pass` por host | Cap configurable; poblar `likely_real`; dedup DB | **P1** |
| **Fuzzing (ffuf)** (`1877-1958`) | works* | ffuf + baseline | *Bug `-e` multi-ext (corregido §10); sin stream live en ffuf | Ya sólido; falta clasif. verificado/probable | P2 |
| **Fuzzing (nativo+recursión)** (`1960-2070`) | works | requests+ThreadPool | Falta exponer conteo de errores por request | Distinguir host muerto de "sin hits" | P2 |
| **403 Bypass** (`2135-2294`) | partial | requests | No persiste; sin diff de baseline | Persistir (`source='bypass'`); diff vs baseline | P2 |
| **httpx-verify** (`2438-2559`) | partial | httpx/requests | Fallback Python sigue redirects → **bypassa el gate SSRF**; `likely_real` solo estructural; **no persiste** | `allow_redirects=False`/re-gate; persistir en `directories`; taxonomía con evidencia | **P1** |
| **Frontend SPA** (`index.html`) | works | socket.io, vanilla JS | 19 `onclick` inline + renderers por `innerHTML`; estado global mutable; **cross-client bleed** (eventos sin `scan_id`) | Scoping por room/run id; capa de componentes | P2 |
| **/api routes** (`2873-2958`) | works | Flask | Sin auth ni CSRF en `DELETE`; OK mientras sea `127.0.0.1` | Auth + CSRF antes de permitir `0.0.0.0` | P2 |

(*) Detalle de GAPs y transversales en §3, §7 y §8.

---

## 3. Auditoría de arquitectura

**Fortalezas**
- Persistencia por `scan_id` **correcta y correlacionada** para el scan por fases: `recon_info`, `subdomains`, `alive_hosts`, `ports`, `vulns`, `directories`, `urls` se devuelven juntas en `/api/scans/<id>` (`2915-2948`). No hay orfandad.
- El **refactor de fuzzing** estableció el patrón correcto: `run_argv` (shell=False, `176-192`), `_assert_public_target` (gate SSRF, `1541-1578`), baseline soft-404 (`get_baseline`/`is_baseline`). **Ese patrón es la plantilla para arreglar el resto.**
- SocketIO ya atado a `127.0.0.1` por defecto con CORS allowlist (`25-28`).

**Debilidades / deuda técnica**
- **Monolito**: `app.py` de ~3000 líneas mezcla DB, ejecución de procesos, parsing, lógica de negocio y rutas. Sin capa de adaptadores por herramienta, sin tests.
- **Dos ejecutores divergentes**: `run_cmd` (shell=True, inseguro) y `run_argv` (shell=False). El refactor migró fuzzing/bypass/httpx a `run_argv` pero **dejó TODO el scan por fases en `run_cmd`** → superficie de inyección (§7, P0).
- **Sin modelo de assets/findings**: 8 tablas planas por scan, correlacionadas solo por `scan_id` y por **strings de hostname re-derivados** (`2664-2665`, `2707-2709`), nunca por IP. Un hallazgo no se puede unir a sus puertos abiertos.
- **Manejo de errores por `except: pass`** sistemático (`2601`,`2689`,`2769`,`2801`): un fallo de herramienta es indistinguible de "target limpio".
- **Cancelación coarse**: `active_scans` se chequea solo entre fases; un `run_cmd` de hasta 600s no se puede interrumpir y el subproceso sigue vivo.

**Riesgos**
- **P0 — RCE local** por inyección de comandos (§7) y PowerShell (DNS).
- **P1 — SSRF/recon interno**: el scan principal no gatea el target; `localhost`/`169.254.169.254`/RFC1918 se escanean.
- **Scans "running" eternos**: hilos daemon mueren con el proceso dejando `status='running'` (sin reconciliación al arrancar).

---

## 4. Auditoría de automatización

**Bien automatizado:** el pipeline de recon de extremo a extremo (dar un dominio → subdominios → vivos → puertos → vulns → dirs → URLs), con progreso en vivo por socket. El fuzzing automatiza bien la calibración soft-404 y la priorización.

**Trabajo manual que la herramienta aún obliga / debería automatizar:**
- **Validación de hallazgos**: hoy el analista debe verificar a mano si un 200 de ffuf, un hit de nuclei o un "secreto" de JS es real. No hay verificación automática (salvo httpx en fuzzing).
- **Correlación**: unir "vuln X en host Y" con "puerto Z abierto en Y" y "dir W en Y" es 100% manual (tablas no se cruzan).
- **De-duplicación entre fuentes**: subdominios se deduplican por string exacto; no hay dedup semántica de URLs ni de findings.
- **Reanudación**: un scan cancelado/caído no se retoma; hay que relanzar todo.
- **Reporte**: no hay exportación; el analista copia manualmente.

**Automatización frágil (falsos "listo"):** una fase emite `done` tanto si el target está limpio como si la herramienta falló o fue truncada por timeout.

---

## 5. Evaluación de fuzzing

**Cómo se ejecuta hoy** (`run_fuzzing`, `1807+`): detecta ffuf; si está, ejecuta vía **`run_argv` (sin shell)** con wordlist (auto-detectada o del usuario), extensiones, recursión y headers; si no, usa un **fuzzer nativo concurrente** (ThreadPoolExecutor + sesión por worker, BFS con recursión). La **Fase 6** del scan reusa este mismo motor en modo silencioso (`emit_live=False`) y persiste en `directories`.

**Verificación / anti-FP (lo bueno):** es el **único módulo con verificación real**:
- Baseline soft-404 por `(profundidad, extensión)` con firma `status + tamaño + md5(body[:512])` (`get_baseline`/`is_baseline`, `1702-1770`), filtrado **por status** (un target que hace 403 a todo colapsa correctamente; validado en pruebas).
- Botón "Verificar con httpx" que marca `likely_real` por unicidad de tamaño.
- `classify_interest` prioriza `.env`/`.git/config`/actuator sin filtrar.

**Lo que falta para "grado plataforma":**
- Clasificación de 4 estados (verificado/probable/FP/no-concluyente) **con evidencia por hit** (hoy es binario keep/filter + etiqueta de interés advisory).
- `likely_real` de httpx **no se persiste** (se guarda NULL, `2080` — ver §10 recién corregido parcialmente) ni se escribe de vuelta a `directories`.
- Sin **feroxbuster** ni **katana/gau** sembrando bases de recursión.
- `classify_interest` usa substring, no límites de palabra (`.git` casa dentro de rutas no relacionadas).

**Defecto hallado y corregido (§10):** el flag `-e` de ffuf generaba `.php,bak,env,json` (solo la 1ra extensión con punto) → el descubrimiento multi-extensión por ffuf estaba roto.

---

## 6. Evaluación de httpx

**Integración:** httpx se usa en **dos sitios desconectados**:
1. **FASE 3** (hosts vivos, `2672`): vía `run_cmd` **shell=True**, sin gate SSRF. "Vivo" = devolvió una línea JSON — **sin filtrado de status ni wildcard**.
2. **httpx-verify standalone** (`2438-2559`): vía `run_argv` (sin shell), con gate SSRF por URL y fallback Python. Enriquece con status/size/title/server/tech + `likely_real`.

**Como servicio de validación compartido (la visión correcta):** httpx **debería ser un servicio central** que toda fase use para confirmar existencia, pero hoy:
- FASE 7 (URLs) guarda URLs **sin probar jamás** su liveness.
- FASE 3 lo usa pero sin baseline wildcard → inflado por wildcard DNS.
- El fallback Python de verify **sigue redirects** (`allow_redirects=True`, `2406`) → un 302 a `169.254.169.254` **bypassa el gate SSRF**.
- `likely_real` es puramente estructural y **no se persiste**.

**Recomendación:** extraer un `http_probe(urls, …) -> [{status,len,title,hash,verdict,evidence}]` reutilizable, con gate SSRF re-aplicado tras redirects, usado por FASE 3, FASE 6, FASE 7 y verify. Es el pilar del motor anti-FP.

---

## 7. Análisis de falsos positivos

**Fuentes de FP / resultados no verificados (de mayor a menor impacto):**

1. **nuclei (FASE 5)**: dump crudo sin post-filtrado ni dedup; expuesto 100% a los FP de templates (`2759-2768`).
2. **JS Secrets** (`479-583`): 28 regex incluyendo claves **públicas por diseño** (`pk_live`, `AIza`, MapBox) y un matcher "Internal Endpoint" que casa `api.stripe.com`/`api.github.com` — ruido en casi todo bundle. Sin validación contra el servicio emisor.
3. **OSINT GitHub** (`696+`): los "secretos" son `total_count>0` del search API (= "una query casó"), mostrados bajo un header rojo "Secretos Encontrados".
4. **Subdominios/Hosts vivos**: filtro de scope por **substring** + **sin wildcard DNS** → `alive_hosts` se inunda de hosts inexistentes si la zona tiene wildcard.
5. **Categorización de URLs (FASE 7)** (`2834-2842`): tagging por substring (`id=` casa `uuid=`; `.git` casa `.github.io`; `.php` casa `graph.php.bak`).
6. **Security Headers / Tech**: lectura de hop intermedio por `-L`; substrings en HTML.
7. **UI**: **todo se muestra como hecho sin chip de validación** salvo el fuzzing. nuclei, JS-secrets y "MISSING headers" se presentan como factual.

**Patrón raíz:** no existe un **motor central de validación** ni una **taxonomía de verdicto con evidencia**. El fuzzing lo tiene a medias; el resto, nada.

---

## 8. Arquitectura objetivo (propuesta)

Sin reescribir desde cero. Evolución en capas sobre lo existente:

```
┌─ Frontend (incremental: + chips de validación, + vista Proyecto/Assets/Findings/Report)
│
├─ API Flask (+ auth cuando se exponga)
│
├─ CAPA DE SERVICIOS (nueva, extraída del monolito)
│   ├─ exec/            run_argv único (matar run_cmd); Popen killable + timeouts por fase
│   ├─ scope/           Proyecto + alcance autorizado + _assert_public_target en TODO target
│   ├─ probe/           http_probe(httpx) como servicio compartido (FASE 3/6/7/verify)
│   ├─ validate/        motor anti-FP: classify(finding)->{verdict, evidence}
│   │                    estados: verificado | probable | falso_positivo | no_concluyente
│   ├─ adapters/        un adaptador por herramienta (in estructurado → out estructurado)
│   └─ orchestrator/    workflows = phase-sets con deps/condiciones/reintentos/checkpoints
│
└─ DATOS (SQLite → modelo correlacionado)
    projects → scans → assets(host/ip/service) ← findings(asset_id, source, verdict, evidence)
```

**Decisiones clave:**
- **Un solo ejecutor** (`run_argv`) y validación estricta de `domain`/`url`/`username` en el borde (allowlist de hostname). Elimina P0 de raíz.
- **`_assert_public_target` en el target del scan** (`handle_start`), no solo en herramientas standalone.
- **Modelo assets/findings**: `host`/`ip`/`service` como entidades de primera clase; findings con FK a asset → correlación real (vuln ↔ puerto ↔ dir).
- **Motor de validación** envolviendo la lógica httpx/baseline ya existente, aplicado a cada fuente; verdicto + evidencia persistidos y mostrados como chip.
- **Workflows** reusando que `start_scan` ya acepta un array `phases` (`2961`): primero checkboxes de fases + plantillas guardadas; luego grafo con dependencias.

---

## 9. Roadmap priorizado

Formato: **[Prio] Tarea — archivos — dependencias — complejidad — riesgo — criterio de aceptación.**

### P0 — CRÍTICO (seguridad del propio tool)
1. **Matar inyección de comandos en el scan** — `handle_start:2963-2967` (allowlist hostname `^[a-z0-9.-]+$`) + migrar `curl/subfinder/sublist3r/assetfinder/waybackurls/gau/nmap/nuclei/httpx` de `run_cmd`→`run_argv` — sin deps — media — bajo (patrón ya probado en fuzzing) — *AC: un `domain` con `& | " $()` es rechazado y ninguna fase usa `shell=True`.*
2. **Matar inyección PowerShell (DNS)** — reemplazar `run_ps`+`Resolve-DnsName` por **dnspython** en `run_fingerprint:317-334` — `pip install dnspython` — baja — bajo — *AC: `domain="x';calc;'"` no ejecuta nada; A/AAAA/MX/NS/TXT/CNAME/SOA siguen poblándose.*
3. **Gate SSRF en el target del scan** — `_assert_public_target(domain)` en `handle_start` antes de `run_scan` — depende de nada — baja — bajo — *AC: scan de `127.0.0.1`/`169.254.169.254`/RFC1918 se bloquea con mensaje claro (salvo `SHARINGAN_ALLOW_PRIVATE`).*
4. **SSRF en sink de JS Secrets** — `_assert_public_target(js_url)` + `run_argv` en `app.py:563` — baja — bajo — *AC: un `<script src>` hacia IP interna no se descarga.*

### P1 — ALTO (fiabilidad + anti-FP)
5. **Motor de validación central** — nuevo `validate/classify()` + columnas `validation_status`+`evidence(JSON)` en `vulns` y `directories` (migración idempotente, ya hay patrón en `init_db`) — dep: #6 — media — medio — *AC: cada hit de dirs/vulns lleva verdicto + evidencia persistida y chip en UI.*
6. **http_probe como servicio compartido** — extraer de httpx-verify; re-gatear tras redirect (`allow_redirects=False`); usar en FASE 3/6/7 — baja/media — bajo — *AC: FASE 7 marca liveness real; verify no sigue redirects a internos.*
7. **Wildcard DNS + resolución en subdominios/hosts vivos** — baseline por zona + resolver antes de persistir — dep: #6 — media — medio — *AC: zona wildcard no inunda `alive_hosts`.*
8. **Cancelación real + estado de error** — `Popen` killable, poll de `active_scans` durante herramientas, reconciliar scans "running" al arrancar, distinguir "0 hallazgos" de "herramienta falló" — media — medio — *AC: cancelar mata el subproceso; una herramienta ausente muestra error, no "done".*
9. **Evidencia de nuclei + dedup** — ampliar schema `vulns` (matcher/cvss/req-resp/cve) + unique `(scan_id,template,host,matched_at)` + `ORDER BY` por rango de severidad (`2930`) — baja — bajo — *AC: findings con evidencia y orden por riesgo real.*

### P2 — MEDIO (plataforma)
10. **Modelo assets/findings correlacionado** — tablas `projects`, `assets`, `findings` + migración/backfill — dep: #5 — alta — medio.
11. **Proyectos + alcance autorizado** — `projects` + `project_id` en `scans` + selector + validación de scope cliente y servidor — dep: #10 — media — medio.
12. **Workflows/plantillas** — checkboxes de fases (ya soportado por `phases`) → phase-sets guardados — baja→media — bajo.
13. **Reportes** — botón "Exportar informe" → vista HTML imprimible + `window.print()`/JSON/CSV — baja — bajo.
14. **UI: chips de validación en toda tabla** + fix cross-client bleed (scoping por room) — media — bajo.

### P3 — EVOLUTIVO
15. Copiloto IA read-only ("Explicar hallazgo") con guardrails (scoped, sin acciones autónomas, anti prompt-injection).
16. feroxbuster + katana sembrando recursión; analítica histórica entre scans; plugins.

---

## 10. Primera mejora recomendada + defectos ya corregidos

### Defectos del refactor de esta sesión (ya corregidos)
Durante la auditoría se hallaron 2 regresiones introducidas en el refactor de fuzzing previo. Al ser trabajo ya aprobado y entregado, se corrigieron de inmediato:
- **Bug `-e` multi-extensión de ffuf** (`app.py:1900`): generaba `.php,bak,env,json` (solo la 1ra con punto) → descubrimiento multi-ext por ffuf roto. Corregido a `"." + ",.".join(extensions)`.
- **Fila `scans` del fuzz "running" eterna** (`app.py:2360`): el fuzz standalone creaba la fila pero nunca la cerraba. Corregido: se marca `done`+`finished_at` al terminar (solo si `phase is None`).

### ✅ P0 — IMPLEMENTADO Y VERIFICADO (2026-10-12)
Se cerró el lote completo de seguridad del camino principal:

1. **Allowlist estricta de hostname** en `handle_start` (`^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,}`): rechaza espacios, comillas, `& | ; $ ()`, backticks. Neutraliza en origen la inyección de comandos **y** de PowerShell para todo el scan.
2. **`run_cmd(shell=True)` ELIMINADO por completo** — `run_argv` (shell=False) es el único ejecutor. Las 15 llamadas (curl, crt.sh, subfinder, sublist3r, assetfinder, httpx, nmap, nuclei, waybackurls, gau) y `/api/tools` se migraron. **Cero `shell=True` en todo `app.py`.**
3. **DNS sin inyección**: `run_ps` ahora pasa el dominio como parámetro vinculado (`param([string]$d)` + `-File script.ps1 -d <valor>`), no por interpolación. Probado: `a$(7*7)b` llega como literal de 8 chars (no evalúa a `a49b`).
4. **Gate SSRF en el target del scan**: `_assert_public_target(domain)` en `handle_start` + en el sink de JS Secrets (`js_url` del HTML del target).

**Verificación:** payloads de inyección (`x.com & calc`, `x"&whoami&"`, `x';calc;'`, `ejemplo.com; rm -rf`) → RECHAZADO; `localhost`/`127.0.0.1`/`169.254.169.254`/`10.0.0.5` → bloqueado; herramientas siguen funcionando por el camino seguro (curl→200, DNS→registros A/NS/MX reales).

### ✅ P1 #5 + #6 — IMPLEMENTADO Y VERIFICADO (2026-10-12)
Motor de validación central con taxonomía **verificado / probable / falso-positivo / no-concluyente** + evidencia:

1. **`classify_discovery` / `classify_vuln`** (`app.py`): veredicto por hallazgo con razón explicable. Nativo 200 con cuerpo distinto del baseline → `verified`; ffuf 200 → `probable` (confirmar con httpx); 401/403/redirect distintos → `probable`; httpx `likely_real` → `verified` / dup → `false_positive`; nuclei → `probable` (reportado, sin re-confirmar); info/timeout → `inconclusive`.
2. **Persistencia**: columnas `validation_status` + `evidence(JSON)` en `directories` y `vulns` (migración idempotente). El fuzzing y nuclei guardan veredicto + evidencia; nuclei ahora conserva matcher/CVE/CWE/CVSS/referencia/curl (antes se descartaban).
3. **#6 http_probe compartido**: `_verify_url_python` ahora con `allow_redirects=False` (**cierra el hueco SSRF de redirects** — un 302 a interno ya no se sigue) + hash de cuerpo; httpx-verify asigna el veredicto central.
4. **UI**: chip de validación en las tablas de Fuzzing (vivo + final), Directorios, Vulnerabilidades y httpx-verify; evidencia (CVE/CVSS/matcher) en las tarjetas de vuln; conteo de verificados. Fix del `ORDER BY severity` alfabético → por rango real de riesgo.

**Verificación:** server local soft-404 + reales → hits reales `verified`, soft-404 descartado; los 6 casos de `classify_discovery` correctos; migración añade columnas; UI renderiza los 4 chips + CVE/CVSS (probado en navegador).

### ✅ P1 #7 + #8 — IMPLEMENTADO Y VERIFICADO (2026-10-12)

**#7 — Wildcard DNS + resolución + scope:**
- **Scope anclado por sufijo** (`_in_scope`): reemplaza el `domain in name` (substring) que aceptaba `notexample.com` / `example.com.evil.net`. Aplicado en crt.sh y las 3 fuentes de FASE 2.
- **Detección de wildcard DNS** (`detect_wildcard_dns`): resuelve 3 etiquetas aleatorias; si resuelven, la zona es wildcard → sus IPs se guardan para marcar fantasmas.
- **Resolución concurrente** (ThreadPoolExecutor×40) de cada subdominio: guarda IP, `resolved`, `is_wildcard`, `is_internal` (migración de la tabla `subdomains`). NXDOMAIN y wildcard/fantasma quedan marcados.
- **FASE 3 (hosts vivos)** solo prueba hosts que resuelven, NO wildcard y NO internos → mata el flooding por wildcard DNS y cierra el **SSRF que faltaba en FASE 3**. **FASE 4 (nmap)** también gatea cada host con `_assert_public_target`.
- UI: vista Subdominios ahora muestra IP + chip RESUELVE/INTERNO/WILDCARD/NXDOMAIN y el conteo resueltos/wildcard.

**#8 — Cancelación real + estado de error:**
- **`run_argv_cancel`**: runner interrumpible (Popen + sondeo de `active_scans` cada 1s) que **mata el árbol de procesos** (taskkill /T en Windows) al cancelar o al vencer el timeout. Salida a archivo temporal (no pipe) para que waybackurls/gau no bloqueen por buffer. Usado en FASE 1/2/3/4/5/7.
- **Estado de error visible**: distingue "0 resultados" de "herramienta falló/timeout"; emite `phase_status` con `note` (⚠ naranja en el log) por subfinder/httpx/nmap/nuclei que fallan o expiran.
- **Reconciliación**: al arrancar, los scans colgados en `status='running'` (hilo daemon muerto con el proceso) pasan a `interrupted`. `active_scans` se limpia al terminar.

**Verificación:** `_in_scope` (5/5 casos), resolución/NXDOMAIN, `_ips_internal` (loopback/privadas→True), wildcard (sin wildcard→vacío) ✓; `run_argv_cancel` probado en los 4 estados — **ok**, **error** (binario inexistente), **timeout** (ping 15s/to=2 → matado en 2.2s), **cancelled** (cancel a los 2s → matado en 2.1s) ✓; UI subs renderiza los 4 flags ✓.

### Siguiente paso recomendado (pendiente de aprobación)
Con P0 + el núcleo de P1 cerrados, lo natural es **P2**: modelo **assets↔findings** correlacionado (unir vuln ↔ puerto ↔ dir por IP) + **proyectos/alcance autorizado**, o bien **#9 (dedup de nuclei)** si preferís cerrar P1 del todo primero.
