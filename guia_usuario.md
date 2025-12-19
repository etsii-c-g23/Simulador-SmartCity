# Guía de Usuario - Simulador de Seguridad IoT para Smart Cities

## Tabla de Contenidos
1. [Introducción](#1-introducción)
2. [Requisitos del Sistema](#2-requisitos-del-sistema)
3. [Instalación y Ejecución](#3-instalación-y-ejecución)
4. [Descripción de la Interfaz](#4-descripción-de-la-interfaz)
5. [Modos de Demostración](#5-modos-de-demostración)
   - [5.1 DoS Attack (Vulnerable)](#51-dos-attack-vulnerable)
   - [5.2 DoS Protection (Paper)](#52-dos-protection-paper)
   - [5.3 MitM Attack (Vulnerable)](#53-mitm-attack-vulnerable)
   - [5.4 MitM Protection (Paper)](#54-mitm-protection-paper)

---

## 1. Introducción

### ¿Qué es este simulador?
Esta aplicación es una **demostración interactiva** de los protocolos de seguridad propuestos en el artículo de investigación *"Comunicaciones seguras en el internet de las cosas en redes 5G"* del Grupo G-23. El simulador permite visualizar y comprender:

- **Ataques de Denegación de Servicio (DoS)** contra dispositivos IoT
- **Ataques Man-in-the-Middle (MitM)** en comunicaciones WiFi Direct
- **Soluciones de protección** basadas en el protocolo MAKE (Mutual Authentication and Key Establishment)

### Dispositivos Simulados
La aplicación simula tres actores:

| Actor | Nombre | Descripción |
|---------|--------|-------------|
| 🚦 **Alice** | Semáforo 5G | Dispositivo IoT legítimo que inicia la comunicación |
| 📷 **Bob** | Cámara IoT | Dispositivo IoT receptor |
| 🦹 **Hugo** | Atacante | Adversario malicioso que intenta comprometer la comunicación |

---

## 2. Requisitos del Sistema

### Software Necesario
- **Python 3.8+** (recomendado Python 3.10 o superior)
- **Navegador web moderno** (Chrome, Firefox, Edge, Safari)
- **Conexión a Internet** (para cargar librerías e imágenes)

### Dependencias Python
Las siguientes librerías son necesarias:
```
fastapi
uvicorn
```

### Hardware Recomendado
- Procesador: Cualquier CPU moderna
- Memoria RAM: 2 GB mínimo
- Resolución de pantalla: 1366x768 o superior (recomendado 1920x1080)

---

## 3. Instalación y Ejecución

### Paso 1: Instalar Dependencias
Abre una terminal en la carpeta del proyecto y ejecuta:
```bash
pip install -r requirements.txt
```
O manualmente:
```bash
pip install fastapi uvicorn
```

### Paso 2: Iniciar el Servidor

#### Opción A: Usando el script (Windows)
Haz doble clic en el archivo `start.bat`:
```batch
start.bat
```
Este script:
1. Abre automáticamente el navegador en `http://127.0.0.1:8000`
2. Inicia el servidor backend FastAPI

#### Opción B: Desde la terminal
```bash
uvicorn backend:app --reload
```
O si hay un error con uvicorn (no está en el PATH):
```bash
python -m uvicorn backend:app --reload
```

### Paso 3: Acceder a la Aplicación
Abre tu navegador y navega a:
```
http://127.0.0.1:8000
```

### Paso 4: Detener el Servidor
Presiona `Ctrl + C` en la terminal para detener el servidor.

---

## 4. Descripción de la Interfaz

La interfaz de usuario está dividida en **cuatro zonas principales**:

### 4.1 Header (Barra Superior)
```
┌────────────────────────────────────────────────────────────┐
│ 🛡️ G-23 SECURITY DEMO              [Selector de Modo ▼]   │
└────────────────────────────────────────────────────────────┘
```
- **Logo y título**: Identifica la aplicación
- **Selector de modo**: Dropdown para cambiar entre los 4 modos de demostración

### 4.2 Panel de Control (Lateral Izquierdo)
El contenido del panel cambia según el modo seleccionado:

#### En modos DoS:
- **QUIÉN ENVÍA**: Botones para seleccionar si el remitente es el SEMÁFORO (legítimo) o el HACKER
- **MAC ADDRESS**: Campo de texto para introducir la dirección MAC del dispositivo
- **RSSI**: Control deslizante para establecer la potencia de señal (-90 a -10 dBm)
- **ENVIAR PAQUETE**: Botón para enviar una solicitud de conexión
- **Estado Servidor**: Muestra los dispositivos registrados en la base de datos

#### En modos MitM:
- **ATAQUE ACTIVO**: Toggle para activar/desactivar la intervención del atacante. Al alternarlo, el protocolo se reinicia y se limpian la consola de logs y los paquetes animados.
- **Paso del Protocolo**: Contador dinámico. Vulnerable: 4 (sin ataque) o 10 (con ataque). Seguro: 6 (sin ataque) o 12 (con ataque).
- **INICIAR/SIGUIENTE PASO**: Botón para avanzar en la simulación del protocolo

### 4.3 Zona de Visualización (Centro)
Muestra una representación visual animada de:
- **Alice (Semáforo)**: A la izquierda, con borde verde
- **Bob (Cámara)**: A la derecha, con borde azul (rojo si está caída)
- **Hugo (Hacker)**: En el centro-inferior, con borde rojo triangular
- **Paquetes animados**: Círculos que viajan entre dispositivos mostrando el flujo de comunicación

### 4.4 Consola de Logs (Inferior)
```
┌────────────────────────────────────────────────────────────┐
│ ● System Security Logs                  [Limpiar Consola] │
├────────────────────────────────────────────────────────────┤
│ [12:34:56] ✅ ACCESO CONCEDIDO: Dispositivo verificado.      │
│ [12:34:57] ⛔ BLOQUEADO: La MAC ... ya tiene sesión activa.  │
│ [12:34:58] ❌ FALLO DEL SISTEMA: La CPU ha colapsado.        │
└────────────────────────────────────────────────────────────┘
```
- **Indicador de estado**: Punto verde parpadeante cuando está activo
- **Mensajes con código de colores**:
  - 🟢 Verde: Operaciones exitosas
  - 🔵 Azul: Información del sistema
  - 🔴 Rojo: Errores, ataques o fallos
- **Botón Limpiar**: Borra todos los logs de la consola

---

## 5. Modos de Demostración

### 5.1 DoS Attack (Vulnerable)

#### Descripción
Este modo demuestra cómo un sistema **sin protección** es vulnerable a ataques de Denegación de Servicio. Cualquier paquete recibido consume recursos de CPU, sin importar si es legítimo o malicioso.

#### Objetivo
Ilustrar que sin filtrado previo, un atacante puede agotar los recursos de un dispositivo IoT enviando paquetes falsos masivamente.

#### Cómo Usar

1. **Selecciona el modo** "DoS Attack (Vulnerable)" en el dropdown
2. **Observa la configuración inicial**:
   - Remitente: SEMÁFORO
   - MAC: `11:22:33:44:55:66` (dispositivo legítimo)
   - RSSI: `-45` dBm
3. **Envía varios paquetes** pulsando repetidamente "ENVIAR PAQUETE"
4. **Observa la degradación**:
   - Cada paquete reduce la "CPU" de la cámara
   - El contador baja progresivamente (20 → 19 → 18...)
   - Los logs muestran "Paquete legítimo aceptado"
5. **Continúa hasta el colapso**:
   - Cuando la CPU llega a 0, el sistema cae
   - El borde de Bob cambia a rojo y pulsa
   - La imagen cambia a una cámara rota
   - El botón cambia a "SISTEMA CAÍDO (CPU 0)"

#### Variante: Ataque desde el Hacker
1. Selecciona **HACKER** como remitente
2. Cambia la MAC a cualquier valor (ej: `AA:BB:CC:DD:EE:FF`)
3. Envía paquetes
4. **Resultado**: El sistema también acepta estos paquetes y se agota igualmente

#### Capturas de Pantalla

**Estado Inicial (Sistema operativo):**
![Estado inicial del modo DoS Vulnerable](img/01_estado_inicial_dos_vulnerable.png)

**Sistema Colapsado (CPU agotada):**
![Sistema caído tras ataque DoS](img/02_sistema_caido_dos.png)

> 💡 **Nota**: Cuando el sistema colapsa, aparece el mensaje:
> "❌ FALLO DEL SISTEMA: La CPU de la Cámara ha colapsado (CPU 0)."

---

### 5.2 DoS Protection (Paper)

#### Descripción
Este modo implementa el **algoritmo de filtrado propuesto en el artículo**. El sistema verifica la MAC y el RSSI antes de procesar la solicitud, descartando paquetes sospechosos sin gastar recursos de CPU.

#### Objetivo
Demostrar que un filtrado inteligente en la fase de descubrimiento previene ataques DoS al rechazar solicitudes maliciosas antes de que consuman recursos.

#### Mecanismos de Protección
El sistema aplica las siguientes reglas:

| Condición | Acción |
|-----------|--------|
| MAC conocida + sesión activa | ⛔ BLOQUEADO |
| MAC desconocida + mismo RSSI que otro dispositivo (diferencia de 5 dBm) | ⛔ BLOQUEADO |
| MAC conocida + parámetros válidos | ✅ ACCESO CONCEDIDO |
| MAC desconocida + RSSI único | 🆕 NUEVO DISPOSITIVO registrado |

#### Cómo Usar

**Escenario 1: Conexión Legítima**
1. Selecciona el modo "DoS Protection (Paper)"
2. Mantén los valores por defecto:
   - Remitente: SEMÁFORO
   - MAC: `11:22:33:44:55:66`
   - RSSI: `-45`
3. Pulsa "ENVIAR PAQUETE"
4. **Resultado esperado**: "✅ ACCESO CONCEDIDO: Dispositivo verificado."
5. Observa que el dispositivo aparece como "ONLINE" en el Estado del Servidor

**Escenario 2: Reintento de conexión (sesión activa)**
1. Sin reiniciar, envía otro paquete con los mismos datos
2. **Resultado esperado**: "⛔ BLOQUEADO: La MAC ... ya tiene sesión activa."

**Escenario 3: Utilizar el mismo RSSI**
1. Cambia a remitente HACKER
2. Cambia la MAC a un valor diferente (ej: `AA:BB:CC:DD:EE:FF`)
3. Mantén el RSSI cercano a `-45` (por ejemplo, `-47`)
4. Envía el paquete
5. **Resultado esperado**: "⛔ BLOQUEADO: Distinta MAC en misma ubicación."

#### Capturas de Pantalla

**Acceso Concedido (Dispositivo legítimo):**
![Acceso concedido en modo DoS Protection](img/03_dos_protection_acceso.png)

**Ataque Bloqueado (Spoofing detectado):**
![Bloqueo de ataque en modo DoS Protection](img/04_dos_protection_bloqueo.png)

#### Observación Clave
> ⚡ **Importante**: En este modo, la CPU de la cámara **NO se reduce** al rechazar paquetes, ya que el filtrado ocurre antes de consumir recursos.

---

### 5.3 MitM Attack (Vulnerable)

#### Descripción
Este modo simula el protocolo **SAS (Short Authentication String)** estándar sin las mejoras propuestas. Demuestra cómo un atacante puede interceptar y manipular el intercambio de claves Diffie-Hellman cuando los mensajes se envían en texto claro.

#### Objetivo
Ilustrar que sin esquemas de compromiso (Commit/Open) ni verificación temporal, un atacante puede establecer claves separadas con ambas partes sin ser detectado.

#### El Protocolo Vulnerable (4 pasos sin ataque / 10 pasos con ataque)

**Sin ataque activo (4 pasos):**

| Paso | Mensaje | Descripción |
|------|---------|-------------|
| 1 | Alice → Bob | `mA = IDA ∥ gᵃ ∥ NA` (en claro) |
| 2 | Bob → Alice | `mB = IDB ∥ gᵇ ∥ NB` (en claro) |
| 3 | Ambos | Calculan SAS: `S = NA ⊕ NB` |
| 4 | Resultado | Establecen clave: `K = gᵃᵇ mod p` |

**Con ataque activo (10 pasos):**

| Paso | Flujo | Descripción |
|------|-------|-------------|
| 1 | Alice → Hugo | Hugo intercepta `mA` en lugar de reenviarlo a Bob |
| 2 | Hugo → Bob | Hugo envía `mE = IDA ∥ gᵉ ∥ NE` suplantando a Alice |
| 3 | Bob → Hugo | Bob responde con `mB = IDB ∥ gᵇ ∥ NB` |
| 4 | Hugo → Alice | Hugo envía a Alice `mB' = IDB ∥ gᵉ ∥ NB` (reemplaza `gᵇ` por `gᵉ`) |
| 5 | Alice calcula | `SA = NA ⊕ NB` (usando el nonce de Bob) |
| 6 | Bob calcula | `SB = NE ⊕ NB` (usando el nonce falso de Hugo) |
| 7 | Hugo ↔ Alice | Hugo establece `KAE = gᵃᵉ mod p` con Alice |
| 8 | Hugo ↔ Bob | Hugo establece `KBE = gᵇᵉ mod p` con Bob |
| 9 | Resultado | Hugo puede leer mensajes de Alice con `KAE` |
| 10 | Resultado | Hugo puede leer mensajes de Bob con `KBE`; MITM exitoso |

#### Cómo Usar

**Sin Ataque Activo:**
1. Selecciona el modo "MitM Attack (Vulnerable)"
2. Mantén el toggle "ATAQUE ACTIVO" desactivado
3. Pulsa "▶ INICIAR PROTOCOLO"
4. Avanza paso a paso pulsando "⬇ SIGUIENTE PASO"
5. Observa los logs:
   - Paso 1: Alice envía sus parámetros
   - Paso 2: Bob responde con sus parámetros
   - Paso 3: Ambos calculan SAS
   - Paso 4: "✅ Autenticación exitosa. Alice y Bob establecen KAB"

**Con Ataque Activo (10 pasos):**
1. Activa el toggle "ATAQUE ACTIVO" (cambia a rojo)
2. Observa que Hugo (atacante) se ilumina en rojo
3. Inicia y avanza el protocolo (10 pasos):
   - Paso 1: Alice envía `mA` a Bob
   - Paso 2: "⚠️ Hugo intercepta `mA` y genera `mE = IDA ∥ gᵉ ∥ NE`"
   - Paso 3: "📤 Hugo → Bob: Envía `mE` falsificado. Bob responde con `mB = IDB ∥ gᵇ ∥ NB`"
   - Paso 4: "🔄 Hugo modifica `mB` → `mB' = IDB ∥ gᵉ ∥ NB` y lo envía a Alice"
   - Pasos 5-6: Alice y Bob calculan sus respectivos SAS (con valores alterados)
   - Pasos 7-8: Hugo establece claves separadas `KAE` con Alice y `KBE` con Bob
   - Pasos 9-10: "❌ MITM EXITOSO: Hugo puede descifrar y leer todos los mensajes"

#### Resultado del Ataque
Hugo (el atacante) ha establecido:
- Una clave `KAE = gᵃᵉ mod p` con Alice (ella cree que habla con Bob)
- Una clave `KBE = gᵇᵉ mod p` con Bob (él cree que habla con Alice)
- Hugo puede descifrar, leer, modificar y reenviar todos los mensajes sin ser detectado

#### Captura de Pantalla

**Ataque MitM Exitoso:**
![Ataque MitM exitoso en protocolo vulnerable](img/05_mitm_ataque_exitoso.png)

---

### 5.4 MitM Protection (Paper)

#### Descripción
Este modo implementa el protocolo **MAKE (Mutual Authentication and Key Establishment)** propuesto en el artículo. Utiliza el esquema Commit/Open y verificación temporal para prevenir ataques MitM.

#### Objetivo
Demostrar que el uso de compromisos criptográficos y marcas de tiempo impide que un atacante modifique los parámetros de negociación sin ser detectado.

#### El Protocolo Seguro (6 pasos sin ataque / 12 pasos con ataque)

**Sin ataque activo (6 pasos):**

| Paso | Mensaje | Descripción |
|------|---------|-------------|
| 1 | Alice → Bob | Envía valor de compromiso `cA` (hash del secreto) |
| 2 | Bob → Alice | Envía `mB = IDA ∥ IDB ∥ gᵇ ∥ NB` |
| 3 | Alice → Bob | Envía valor de apertura `dA` (Bob verifica integridad) |
| 4 | Alice → Bob | Envía `AuthA = TS ∥ LT ∥ MAC(KAB, SA ∥ TS ∥ LT)` |
| 5 | Bob → Alice | Envía `AuthB = MAC(KBA, SB ∥ TS ∥ LT)` |
| 6 | Resultado | Canal seguro establecido, claves verificadas |

**Con ataque activo (12 pasos):**

| Paso | Flujo | Descripción |
|------|-------|-------------|
| 1 | Alice → Hugo | Hugo intercepta `cA` (compromiso de Alice) |
| 2 | Hugo → Bob | Hugo envía `cE` (su propio compromiso falso) |
| 3 | Bob → Hugo | Bob responde con `mB = IDA ∥ IDB ∥ gᵇ ∥ NB` |
| 4 | Hugo → Alice | Hugo envía `mB' = IDA ∥ IDB ∥ gᵉ ∥ NB` (reemplaza `gᵇ` por `gᵉ`) |
| 5 | Alice → Hugo | Alice envía `dA` (apertura de su compromiso) |
| 6 | Hugo → Bob | Hugo envía `dE` (su falsa apertura) |
| 7 | Alice calcula | `SA = NA ⊕ NB` |
| 8 | Bob calcula | `SB = NA ⊕ NB` |
| 9 | Alice → Hugo | Alice envía `AuthA = TS ∥ LT ∥ MAC(KAE, SA ∥ TS ∥ LT)` |
| 10 | Bob → Hugo | Bob envía `AuthB = MAC(KBE, SB ∥ TS ∥ LT)` |
| 11 | Hugo intenta | Intenta falsificar MACs pero falla (KAE ≠ KBE) |
| 12 | Resultado | 🛡️ MITM DETECTADO: Los MACs no coinciden. Alice y Bob abortan la conexión |

#### Cómo Usar

**Sin Ataque Activo:**
1. Selecciona el modo "MitM Protection (Paper)"
2. Mantén el toggle desactivado
3. Avanza por los 6 pasos
4. Observa el establecimiento seguro del canal

**Con Ataque Activo:**
1. Activa el toggle "ATAQUE ACTIVO"
2. Avanza por los 12 pasos observando cómo Hugo intenta el ataque:
   - **Pasos 1-4**: Hugo intercepta el compromiso `cA` y sustituye el valor público de Bob con el suyo
   - **Pasos 5-6**: Hugo envía falsas aperturas (`dA` y `dE`) intentando mantener la ilusión
   - **Pasos 7-8**: Alice y Bob calculan sus cadenas cortas (que aparentemente coinciden a nivel de usuario)
   - **Pasos 9-10**: Alice y Bob envían sus autenticadores `AuthA` y `AuthB` con timestamps (`TS`) y duración (`LT`)
   - **Pasos 11-12**: "🛡️ DETECCIÓN DE MITM: Hugo no puede falsificar los MACs porque derivó claves diferentes (`KAE` y `KBE`). El protocolo aborta la conexión cuando los MACs no coinciden."

#### Captura de Pantalla

**Ataque Bloqueado en Paso 12:**
![Bloqueo del ataque MitM en protocolo seguro](img/06_mitm_bloqueo_seguro.png)

#### Clave del Éxito
> 🛡️ **Por qué funciona**: El protocolo seguro usa dos mecanismos de defensa:
> 1. **Compromisos Diffie-Hellman (Commit/Open)**: Hugo no puede modificar los exponentes públicos (`gᵃ`, `gᵇ`) sin que la verificación de integridad falle.
> 2. **Autenticación con MACs y Timestamps**: Aunque Hugo intente sustituir valores, los MACs derivados de claves diferentes (`KAE ≠ KBE`) no coincidirán. El protocolo aborta la conexión inmediatamente al detectar esta discrepancia, previniendo cualquier comunicación comprometida.

---

