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
6. [Escenarios de Uso Típicos](#6-escenarios-de-uso-típicos)
7. [Preguntas Frecuentes](#7-preguntas-frecuentes)
8. [Glosario de Términos](#8-glosario-de-términos)

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
- **Conexión a Internet** (para cargar librerías CDN)

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
O si uvicorn no está en el PATH:
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
┌──────────────────────────────────────────────────────────────┐
│ ● System Security Logs                    [Limpiar Consola] │
├──────────────────────────────────────────────────────────────┤
│ [12:34:56] ✅ ACCESO CONCEDIDO: Dispositivo verificado.      │
│ [12:34:57] ⛔ BLOQUEADO: La MAC ... ya tiene sesión activa.  │
│ [12:34:58] ❌ FALLO DEL SISTEMA: La CPU ha colapsado.        │
└──────────────────────────────────────────────────────────────┘
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

#### Objetivo Educativo
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

#### Objetivo Educativo
Demostrar que un filtrado inteligente en la fase de descubrimiento previene ataques DoS al rechazar solicitudes maliciosas antes de que consuman recursos.

#### Mecanismos de Protección
El sistema aplica las siguientes reglas:

| Condición | Acción |
|-----------|--------|
| MAC conocida + sesión activa | ⛔ BLOQUEADO |
| MAC conocida + RSSI anómalo (diferencia > 10 dBm) | ⛔ BLOQUEADO |
| MAC desconocida + mismo RSSI que otro dispositivo | ⛔ BLOQUEADO |
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

**Escenario 3: Ataque de spoofing por RSSI**
1. Cambia a remitente HACKER
2. Cambia la MAC a un valor diferente (ej: `AA:BB:CC:DD:EE:FF`)
3. Mantén el RSSI cercano a `-45` (por ejemplo, `-47`)
4. Envía el paquete
5. **Resultado esperado**: "⛔ BLOQUEADO: Distinta MAC en misma ubicación."

**Escenario 4: RSSI anómalo**
1. Usa la MAC legítima `11:22:33:44:55:66`
2. Cambia el RSSI drásticamente (ej: `-10` en vez de `-45`)
3. Envía el paquete
4. **Resultado esperado**: "⛔ BLOQUEADO: RSSI anómalo (-10 vs -45)."

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

#### Objetivo Educativo
Ilustrar que sin esquemas de compromiso (Commit/Open) ni verificación temporal, un atacante puede establecer claves separadas con ambas partes sin ser detectado.

#### El Protocolo Vulnerable (4 pasos sin ataque / 10 pasos con ataque)

| Paso | Mensaje | Descripción |
|------|---------|-------------|
| 1 | Alice → Bob | `mA = IDA ∥ gᵃ ∥ NA` (en claro) |
| 2 | Bob → Alice | `mB = IDB ∥ gᵇ ∥ NB` (en claro) |
| 3 | Ambos | Calculan SAS: `S = NA ⊕ NB` |
| 4 | Resultado | Establecen clave: `K = gᵃᵇ mod p` |

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

**Con Ataque Activo:**
1. Activa el toggle "ATAQUE ACTIVO" (cambia a rojo)
2. Observa que Hugo (atacante) se ilumina
3. Inicia y avanza el protocolo:
   - Paso 1: Alice envía mA normalmente
   - Paso 2: "⚠️ EVE intercepta mA y genera mE = IDA ∥ gᵉ ∥ NE"
   - Paso 3: "📤 EVE → Bob: Envía mE falsificado. Bob calcula SB = NE ⊕ NB"
   - Paso 4: "❌ MITM en curso: Eve deriva claves separadas con cada parte (KAE/KBE)"
   
> Nota: La demostración con ataque activo consta ahora de 10 pasos, incluyendo exposición de `SA`/`SB` y derivación de `KAE`/`KBE` por parte del atacante.

#### Resultado del Ataque
El atacante ha establecido:
- Una clave `KAE` con Alice (ella cree que habla con Bob)
- Una clave `KBE` con Bob (él cree que habla con Alice)
- Eve puede descifrar, leer y reenviar todos los mensajes

#### Captura de Pantalla

**Ataque MitM Exitoso:**
![Ataque MitM exitoso en protocolo vulnerable](img/05_mitm_ataque_exitoso.png)

---

### 5.4 MitM Protection (Paper)

#### Descripción
Este modo implementa el protocolo **MAKE (Mutual Authentication and Key Establishment)** propuesto en el artículo. Utiliza el esquema Commit/Open y verificación temporal para prevenir ataques MitM.

#### Objetivo Educativo
Demostrar que el uso de compromisos criptográficos y marcas de tiempo impide que un atacante modifique los parámetros de negociación sin ser detectado.

#### El Protocolo Seguro (6 pasos sin ataque / 12 pasos con ataque)

| Paso | Mensaje | Descripción |
|------|---------|-------------|
| 1 | Alice → Bob | Envía valor de compromiso `c` (hash del secreto) |
| 2 | Bob → Alice | Envía `mB = IDA ∥ IDB ∥ gᵇ ∥ NB` |
| 3 | Alice → Bob | Envía valor de apertura `d` (Bob verifica integridad) |
| 4 | Alice → Bob | Envía `AuthA = TS ∥ LT ∥ MAC(KAB, SA ∥ TS ∥ LT)` |
| 5 | Bob → Alice | Envía `AuthB = MAC(KBA, SB ∥ TS ∥ LT)` |
| 6 | Resultado | Canal seguro establecido, claves verificadas |

#### Cómo Usar

**Sin Ataque Activo:**
1. Selecciona el modo "MitM Protection (Paper)"
2. Mantén el toggle desactivado
3. Avanza por los 6 pasos
4. Observa el establecimiento seguro del canal

**Con Ataque Activo:**
1. Activa el toggle "ATAQUE ACTIVO"
2. Avanza por los pasos (12 en total):
   - Compromiso `cA`, respuesta `mB` y versión interceptada `mB'` por el atacante
   - Aperturas `dA` y `dE` (Hugo envía `dE` a Bob para intentar suplantar)
   - Cálculo de cadenas cortas `SA`/`SB` y autenticaciones `AuthA`/`AuthB` con `TS` y `LT`
   - Detección final: el atacante no puede falsificar el MAC, se detecta MITM (KAE ≠ KBE)

#### Captura de Pantalla

**Ataque Bloqueado en Paso 3:**
![Bloqueo del ataque MitM en protocolo seguro](img/06_mitm_bloqueo_seguro.png)

#### Clave del Éxito
> 🛡️ **Por qué funciona**: El atacante ve el compromiso `c` en el paso 1, pero al no conocer el secreto original `mA`, no puede generar un valor de apertura `d` válido. Cualquier intento de modificación es detectado al verificar que `hash(d) ≠ c`.

---

## 6. Escenarios de Uso Típicos

### Escenario 1: Demostración en Clase
**Objetivo**: Explicar la diferencia entre sistemas seguros e inseguros

1. Inicia en modo "DoS Attack (Vulnerable)"
2. Muestra cómo el sistema colapsa tras ~20 paquetes
3. Cambia a "DoS Protection (Paper)"
4. Demuestra cómo los mismos ataques son bloqueados
5. Compara los logs de ambos escenarios

### Escenario 2: Laboratorio de Ciberseguridad
**Objetivo**: Práctica hands-on de ataques y defensas

1. Divide a los estudiantes en equipos
2. Un equipo intenta "hacer caer" el sistema en modo vulnerable
3. Otro equipo intenta lo mismo en modo protegido
4. Discusión sobre las diferencias observadas

### Escenario 3: Presentación del Paper
**Objetivo**: Demostrar los hallazgos de la investigación

1. Presenta el contexto teórico (Smart Cities, WiFi Direct, vulnerabilidades)
2. Usa los modos vulnerables para mostrar el problema
3. Usa los modos protegidos para mostrar la solución
4. Los logs sirven como "evidencia" de cada paso del protocolo

---

## 7. Preguntas Frecuentes

### ¿Por qué no puedo enviar más paquetes en modo DoS Vulnerable?
Cuando la CPU llega a 0, el sistema está "caído" y no procesa más solicitudes. Cambia el modo en el dropdown para reiniciar automáticamente.

### ¿Cómo reinicio el sistema sin cambiar de modo?
Actualmente, cambiar de modo reinicia el backend. Si quieres reiniciar manualmente, recarga la página (`F5` o `Ctrl+R`).

### ¿Por qué el RSSI afecta a la seguridad?
El RSSI (potencia de señal) se usa como indicador de proximidad. Si dos MACs diferentes tienen el mismo RSSI, sugiere que provienen de la misma ubicación física, lo cual es sospechoso (posible spoofing).

### ¿Qué significa "MAC ya tiene sesión activa"?
En modo protegido, una vez que un dispositivo se conecta exitosamente, no puede volver a conectarse hasta que se cierre la sesión. Esto previene ataques de repetición.

### ¿Por qué el modo MitM Secure tiene 6/12 pasos?
Sin ataque activo, el protocolo seguro tiene 6 pasos por añadir:
1. Fase de compromiso (Commit/Open)
2. Verificación temporal con Timestamps (TS) y Lifetime (LT)
3. Intercambio de MACs (Message Authentication Codes)

Con ataque activo, la demostración se extiende a 12 pasos para evidenciar el intento de suplantación (incluye el paso adicional `dE`) y la posterior detección.

### ¿Qué ocurre al alternar "ATAQUE ACTIVO"?
Al activar/desactivar el ataque MITM, el protocolo se reinicia automáticamente (paso vuelve a 0) y se limpian tanto los logs como los paquetes animados. Esto asegura que el contador de pasos se ajuste a la nueva configuración (4/10 en vulnerable y 6/12 en seguro).

### ¿Puedo modificar el código para mis propias pruebas?
¡Sí! El código es abierto y modular:
- `index.html`: Frontend React (interfaz visual)
- `backend.py`: Backend FastAPI (lógica de negocio)
- `media/`: Imágenes de los dispositivos

---

## 8. Glosario de Términos

| Término | Definición |
|---------|------------|
| **D2D** | Device-to-Device. Comunicación directa entre dispositivos sin pasar por una estación base. |
| **DoS** | Denial of Service. Ataque que busca hacer un servicio inaccesible. |
| **IoT** | Internet of Things. Red de dispositivos físicos conectados a Internet. |
| **MAC** | Media Access Control. Identificador único de hardware de red. |
| **MAKE** | Mutual Authentication and Key Establishment. Protocolo propuesto en el paper. |
| **MitM** | Man-in-the-Middle. Ataque donde el adversario intercepta comunicaciones. |
| **Nonce** | Número aleatorio usado una sola vez para prevenir ataques de repetición. |
| **RSSI** | Received Signal Strength Indicator. Medida de la potencia de la señal recibida. |
| **SAS** | Short Authentication String. Protocolo de autenticación basado en comparación de cadenas. |
| **Timestamp** | Marca temporal que indica cuándo se creó un mensaje. |
| **WiFi Direct** | Estándar que permite conexión P2P entre dispositivos WiFi sin router. |

---

## Información del Proyecto

**Proyecto**: Comunicaciones seguras en el internet de las cosas en redes 5G  
**Grupo**: G-23  
**Universidad**: Universidad de Sevilla  
**Autores**: Francisco Gago Vázquez, Sergio García Eslava, Marco Antonio Herrera Luján

---

*Guía de Usuario v1.1 - Diciembre 2025*
