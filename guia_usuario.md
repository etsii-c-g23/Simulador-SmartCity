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

#### Opción B: Desde la terminal del ordenador

> Nota: en la carpeta, hacer click derecho y seleccionar Abrir en Terminal

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

> Nota: a veces es necesario recargar la página al iniciar el script.

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

##### Parámetros Diffie-Hellman y Valores de Actores
El panel inferior muestra los parámetros criptográficos editables:

**Parámetros comunes:**
- `g`: Generador (raíz primitiva de p). Valores comunes: 5
- `p`: Número primo usado en Diffie-Hellman. Valores comunes: 23, 29

> ⚠️ **Nota**: Los parámetros se validan automáticamente. Si `p` no es primo o `g` no es raíz primitiva de `p`, el protocolo no iniciará y mostrará un error descriptivo.

**Para cada actor (Alice, Bob, Hugo):**

| Parámetro | Alice | Bob | Hugo | Descripción |
|-----------|-------|-----|------|-------------|
| **MAC** | AA:BB:CC:DD:EE:01 | AA:BB:CC:DD:EE:02 | AA:BB:CC:DD:EE:03 | Identificador único del dispositivo (editable) |
| **a / b / e** | Exponente secreto `a` | Exponente secreto `b` | Exponente secreto `e` | Números aleatorios guardados en secreto |
| **NA / NB / NE** | Nonce (número aleatorio) | Nonce (número aleatorio) | Nonce (número aleatorio) | Valores de un solo uso para evitar ataques de repetición |
| **g^exp mod p** | `ga = g^a mod p` | `gb = g^b mod p` | `ge = g^e mod p` | Valores públicos (se calculan automáticamente al cambiar exponentes) |

**Comportamiento:**
- Los campos de exponentes y nonces se pueden editar manualmente para simular diferentes escenarios
- Los valores públicos (`g^exp mod p`) se recalculan automáticamente cuando cambias `g`, `p` o el exponente de un actor
- Durante un protocolo en curso, los parámetros están bloqueados para evitar cambios inconsistentes

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
│ [12:34:56] ✅ ACCESO CONCEDIDO: Dispositivo verificado.    │
│ [12:34:57] ⛔ BLOQUEADO: La MAC ... ya tiene sesión activa.│
│ [12:34:58] ❌ FALLO DEL SISTEMA: La CPU ha colapsado.      │
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
3. **Envía varios paquetes** pulsando repetidamente "ENVIAR PAQUETE" tanto con SEMÁFORO como con HACKER
4. **Observa la degradación**:
   - Cada paquete reduce la "CPU" de la cámara
   - El contador baja progresivamente (20 → 19 → 18...)
   - Los logs muestran "Paquete legítimo aceptado"
5. **Continúa hasta el colapso**:
   - Cuando la CPU llega a 0, el sistema cae
   - El borde de Bob cambia a rojo y pulsa
   - La imagen cambia a una cámara rota
   - El botón cambia a "SISTEMA CAÍDO (CPU 0)"

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
| MAC conocida | ⛔ BLOQUEADO |
| MAC desconocida + mismo RSSI que otro dispositivo (diferencia de 5 dBm) | ⛔ BLOQUEADO |
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

#### Observación Clave
> **Importante**: En este modo, la CPU de la cámara **NO se reduce** al rechazar paquetes, ya que el filtrado ocurre antes de consumir recursos.

---

### 5.3 MitM Attack (Vulnerable)

#### Descripción
Este modo simula el protocolo **SAS (Short Authentication String)** estándar sin las mejoras propuestas. Demuestra cómo un atacante puede interceptar y manipular el intercambio de claves Diffie-Hellman cuando los mensajes se envían en texto claro.

#### Objetivo
Ilustrar que sin esquemas de compromiso (Commit/Open) ni verificación temporal, un atacante puede establecer claves separadas con ambas partes sin ser detectado.

#### Cómo Usar

**Sin Ataque Activo:**
1. Selecciona el modo "MitM Attack (Vulnerable)"
2. Mantén el toggle "ATAQUE ACTIVO" desactivado
3. Pulsa "▶ INICIAR PROTOCOLO"
4. Avanza paso a paso pulsando "⬇ SIGUIENTE PASO"
5. Observa los logs

**Con Ataque Activo (10 pasos):**
1. Activa el toggle "ATAQUE ACTIVO" (cambia a rojo)
2. Observa que Hugo (atacante) se ilumina en rojo
3. Inicia y avanza el protocolo
4. Observa los logs

#### Resultado del Ataque
Hugo (el atacante) ha establecido:
- Una clave `KAE = gᵃᵉ mod p` con Alice (ella cree que habla con Bob)
- Una clave `KBE = gᵇᵉ mod p` con Bob (él cree que habla con Alice)
- Hugo puede descifrar, leer, modificar y reenviar todos los mensajes sin ser detectado

---

### 5.4 MitM Protection (Paper)

#### Descripción
Este modo implementa el protocolo **MAKE (Mutual Authentication and Key Establishment)** propuesto en el artículo. Utiliza el esquema Commit/Open y verificación temporal para prevenir ataques MitM.

#### Objetivo
Demostrar que el uso de compromisos criptográficos y marcas de tiempo impide que un atacante modifique los parámetros de negociación sin ser detectado.

#### Cómo Usar

**Sin Ataque Activo:**
1. Selecciona el modo "MitM Protection (Paper)"
2. Mantén el toggle desactivado
3. Avanza por los 6 pasos
4. Observa el establecimiento seguro del canal

**Con Ataque Activo:**
1. Activa el toggle "ATAQUE ACTIVO"
2. Avanza por los 12 pasos observando cómo Hugo intenta el ataque
3. Observa los logs

#### Clave del Éxito
> 🛡️ **Por qué funciona**: El protocolo seguro usa dos mecanismos de defensa:
> 1. **Compromisos Diffie-Hellman (Commit/Open)**: Hugo no puede modificar los exponentes públicos (`gᵃ`, `gᵇ`) sin que la verificación de integridad falle.
> 2. **Autenticación con MACs y Timestamps**: Aunque Hugo intente sustituir valores, los MACs derivados de claves diferentes (`KAE ≠ KBE`) no coincidirán. El protocolo aborta la conexión inmediatamente al detectar esta discrepancia, previniendo cualquier comunicación comprometida.

---

