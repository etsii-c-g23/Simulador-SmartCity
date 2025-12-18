# backend.py
"""
Sistema de simulación de ciberseguridad con ataque DoS y protocolo MITM.
Gestiona la verificación de dispositivos IoT y autenticación de comunicación.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
import random

# ==========================================
# CONFIGURACIÓN E INICIALIZACIÓN
# ==========================================

app = FastAPI()

# Servir archivos estáticos (imágenes)
app.mount("/media", StaticFiles(directory="media"), name="media")

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# MODELOS DE DATOS
# ==========================================

class DoSRequest(BaseModel):
    """Solicitud para verificación de dispositivo y ataque DoS."""
    mac: str
    rssi: int
    is_secure_mode: bool

class ProtocolRequest(BaseModel):
    """Solicitud para paso del protocolo de autenticación."""
    step: int
    mode: str
    mitm_active: bool

class MitmParamsRequest(BaseModel):
    """Solicitud para actualizar parámetros MITM."""
    g: int
    p: int
    alice: dict  # {id, secret, nonce, public}
    bob: dict
    hugo: dict

class MitmCalculateRequest(BaseModel):
    """Solicitud para calcular valores de Hugo basado en Alice y Bob."""
    g: int
    p: int
    alice: dict
    bob: dict

# ==========================================
# CONSTANTES
# ==========================================

# Estado de dispositivos
DEVICE_STATUS_DISCONNECTED = 'disconnected'
DEVICE_STATUS_CONNECTED = 'connected'

# Estado de cámara
CAMERA_STATUS_OK = 'OK'
CAMERA_STATUS_DOWN = 'DOWN'

# Modos de protocolo
PROTOCOL_MODE_SECURE = 'mitm_secure'
PROTOCOL_MODE_INSECURE = 'mitm_insecure'

# Pasos del protocolo
SECURE_PROTOCOL_STEPS = 6
INSECURE_PROTOCOL_STEPS = 4

# Umbrales de RSSI
RSSI_ANOMALY_THRESHOLD = 10  # Diferencia máxima permitida en RSSI
RSSI_LOCATION_THRESHOLD = 5   # Diferencia para detectar misma ubicación

# Salud de CPU
INITIAL_CPU_HEALTH = 20

# Parámetros MITM por defecto
DEFAULT_PRIME_P = 23
DEFAULT_BASE_G = 5

# BD inicial de dispositivos
INITIAL_DB = {
    '11:22:33:44:55:66': {
        'rssi': -45,
        'trusted': True,
        'status': DEVICE_STATUS_DISCONNECTED
    }
}

# Estado inicial de cámara
INITIAL_CAMERA_STATE = {
    'cpu_health': INITIAL_CPU_HEALTH,
    'max_health': INITIAL_CPU_HEALTH,
    'status': CAMERA_STATUS_OK,
    'image': '/media/camara.png',
}

# ==========================================
# FUNCIONES MATEMÁTICAS (CRIPTOGRAFÍA)
# ==========================================

def modExp(base: int, exp: int, mod: int) -> int:
    """
    Calcula base^exp mod mod usando exponenciación modular rápida.
    Esencial para Diffie-Hellman: g^secret mod p
    """
    result = 1
    b = base % mod
    e = exp
    while e > 0:
        if e & 1:
            result = (result * b) % mod
        b = (b * b) % mod
        e >>= 1
    return result

def xorInt(a: int, b: int) -> int:
    """
    Realiza XOR bitwise entre dos enteros.
    Se usa para calcular claves compartidas: SA = NA ⊕ NB
    """
    return a ^ b

# ==========================================
# ESTADO INICIAL DE PARÁMETROS MITM
# ==========================================

def create_initial_mitm_params():
    """Genera parámetros MITM iniciales."""
    alice_secret = random.randint(2, DEFAULT_PRIME_P - 2)
    bob_secret = random.randint(2, DEFAULT_PRIME_P - 2)
    hugo_secret = random.randint(2, DEFAULT_PRIME_P - 2)
    
    alice_nonce = random.randint(1000, 9999)
    bob_nonce = random.randint(1000, 9999)
    hugo_nonce = random.randint(1000, 9999)
    
    return {
        'g': DEFAULT_BASE_G,
        'p': DEFAULT_PRIME_P,
        'alice': {
            'id': 'IDA',
            'secret': alice_secret,
            'nonce': alice_nonce,
            'public': modExp(DEFAULT_BASE_G, alice_secret, DEFAULT_PRIME_P)
        },
        'bob': {
            'id': 'IDB',
            'secret': bob_secret,
            'nonce': bob_nonce,
            'public': modExp(DEFAULT_BASE_G, bob_secret, DEFAULT_PRIME_P)
        },
        'hugo': {
            'id': 'IDE',
            'secret': hugo_secret,
            'nonce': hugo_nonce,
            'public': modExp(DEFAULT_BASE_G, hugo_secret, DEFAULT_PRIME_P)
        }
    }

# ==========================================
# ESTADO GLOBAL
# ==========================================

server_db = INITIAL_DB.copy()
camera_state = INITIAL_CAMERA_STATE.copy()
mitm_params = create_initial_mitm_params()

# ==========================================
# FUNCIONES AUXILIARES
# ==========================================

def load_frontend_html() -> str:
    """Carga el archivo index.html del frontend."""
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Error: No se encuentra el archivo index.html</h1>"

def reset_all_state() -> None:
    """Reinicia el estado global del sistema."""
    global server_db, camera_state, mitm_params
    server_db = {k: v.copy() for k, v in INITIAL_DB.items()}
    camera_state = INITIAL_CAMERA_STATE.copy()
    mitm_params = create_initial_mitm_params()

def is_camera_down() -> bool:
    """Verifica si la cámara está caída."""
    return camera_state['status'] == CAMERA_STATUS_DOWN

def reduce_cpu_health() -> None:
    """Reduce la salud de CPU en 1 unidad y chequea si cae."""
    camera_state['cpu_health'] = max(0, camera_state['cpu_health'] - 1)
    
    if camera_state['cpu_health'] <= 0:
        camera_state['status'] = CAMERA_STATUS_DOWN
        camera_state['image'] = '/media/camara_rota.png'

def get_device_by_mac(mac: str) -> dict | None:
    """Obtiene un dispositivo de la BD por su MAC."""
    return server_db.get(mac)

def register_device(mac: str, rssi: int) -> None:
    """Registra un nuevo dispositivo en la BD."""
    server_db[mac] = {
        'rssi': rssi,
        'trusted': True,
        'status': DEVICE_STATUS_CONNECTED
    }

def is_rssi_anomalous(stored_rssi: int, request_rssi: int) -> bool:
    """Chequea si el RSSI es anómalo comparado con el registrado."""
    return abs(stored_rssi - request_rssi) > RSSI_ANOMALY_THRESHOLD

def is_same_location(stored_rssi: int, request_rssi: int) -> bool:
    """Chequea si la RSSI es muy similar (misma ubicación)."""
    return abs(stored_rssi - request_rssi) < RSSI_LOCATION_THRESHOLD

# ==========================================
# LÓGICA DE VALIDACIÓN DoS
# ==========================================

def check_device_secure_mode(req: DoSRequest) -> dict:
    """
    Valida un dispositivo en MODO SEGURO.
    Retorna diccionario con estatus y mensaje.
    """
    entry = get_device_by_mac(req.mac)
    
    if entry:
        # MAC ESTÁ EN LA BASE DE DATOS
        if entry['status'] == DEVICE_STATUS_CONNECTED:
            return {
                "status": "error",
                "msg": f"⛔ BLOQUEADO: La MAC {req.mac} ya tiene sesión activa."
            }
        
        # RSSI NO ES LO SUFICIENTEMENTE DISTINTO AL DE LA BASE DE DATOS
        if is_rssi_anomalous(entry['rssi'], req.rssi):
            return {
                "status": "error",
                "msg": f"⛔ BLOQUEADO: RSSI anómalo ({req.rssi} vs {entry['rssi']})."
            }
        
        # TANTO LA MAC COMO EL RSSI SON DISTINTOS A LAS ENTRADAS EN LA BASE DE DATOS
        server_db[req.mac]['status'] = DEVICE_STATUS_CONNECTED
        return {
            "status": "success",
            "msg": "✅ ACCESO CONCEDIDO: Dispositivo verificado."
        }
    
    else:
        # MAC DESCONOCIDA - Chequear si está en misma ubicación
        for stored_mac, data in server_db.items():
            if is_same_location(data['rssi'], req.rssi):
                return {
                    "status": "error",
                    "msg": f"⛔ BLOQUEADO: Distinta MAC en misma ubicación."
                }
        
        # Registrar nuevo dispositivo
        register_device(req.mac, req.rssi)
        return {
            "status": "success",
            "msg": "🆕 NUEVO DISPOSITIVO: Registrado exitosamente."
        }

def check_device_insecure_mode(req: DoSRequest) -> dict:
    """
    Valida un dispositivo en MODO INSEGURO (VULNERABLE).
    Cualquier paquete es aceptado sin validaciones.
    """
    return {"status": "success", "msg": "Paquete aceptado."}

# ==========================================
# LÓGICA DEL PROTOCOLO DE AUTENTICACIÓN
# ==========================================

class ProtocolMessage:
    """Encapsula la información de un paso del protocolo."""
    def __init__(self, msg: str, type_: str = "info", source: str = "alice", target: str = "bob", values: dict = None):
        self.msg = msg
        self.type = type_
        self.source = source
        self.target = target
        self.values = values or {}

def get_secure_protocol_message(step: int, mitm_active: bool, params: dict = None) -> ProtocolMessage:
    """
    Genera el mensaje para un paso del protocolo SEGURO (6 pasos).
    
    Pasos:
    1. Alice -> Bob: c (commit de mA)
    2. Bob -> Alice: mB = IDA || IDB || gb || NB
    3. Alice -> Bob: mA = IDA || ga || NA + d (decommit)
    4. Alice -> Bob: AuthA = TS || LT || MAC(KAB, SA || TS || LT)
    5. Bob -> Alice: AuthB = MAC(KBA, SB || TS || LT)
    6. Verificación mutua exitosa
    
    Con MITM: Hugo intenta interceptar pero la autenticación lo detecta.
    """
    if params is None:
        params = {}
    
    alice = params.get('alice', {})
    bob = params.get('bob', {})
    hugo = params.get('hugo', {})
    g = params.get('g', 0)
    p = params.get('p', 0)
    
    ga = modExp(g, alice.get('secret', 0), p) if p > 0 else 0
    gb = modExp(g, bob.get('secret', 0), p) if p > 0 else 0
    ge = modExp(g, hugo.get('secret', 0), p) if p > 0 else 0
    
    if step == 1:
        return ProtocolMessage(
            "📤 Alice -> Bob [M1]: c (commit, hash de mA)",
            "info", "alice", "bob",
            {"c": f"hash(IDA || {ga} || {alice.get('nonce', 0)})"}
        )
    
    elif step == 2:
        return ProtocolMessage(
            "📤 Bob -> Alice [M2]: mB = IDA || IDB || gb || NB",
            "info", "bob", "alice",
            {"mB": f"{alice.get('id', 'IDA')} || {bob.get('id', 'IDB')} || {gb} || {bob.get('nonce', 0)}"}
        )
    
    elif step == 3:
        return ProtocolMessage(
            "📤 Alice -> Bob [M3]: mA = IDA || ga || NA (decommit: verifica c)",
            "info", "alice", "bob",
            {
                "mA": f"{alice.get('id', 'IDA')} || {ga} || {alice.get('nonce', 0)}",
                "d": "open(c) ✓"
            }
        )
    
    elif step == 4:
        SA = xorInt(alice.get('nonce', 0), bob.get('nonce', 0))
        KAB = modExp(g, alice.get('secret', 0) * bob.get('secret', 0), p) if p > 0 else 0
        return ProtocolMessage(
            "📤 Alice -> Bob [M4]: AuthA = TS || LT || MAC(KAB, SA || TS || LT)",
            "info", "alice", "bob",
            {
                "SA": SA,
                "KAB": KAB,
                "AuthA": f"MAC({KAB}, {SA} || TS || LT)"
            }
        )
    
    elif step == 5:
        SB = xorInt(alice.get('nonce', 0), bob.get('nonce', 0))  # Igual a SA
        KAB = modExp(g, alice.get('secret', 0) * bob.get('secret', 0), p) if p > 0 else 0
        return ProtocolMessage(
            "📤 Bob -> Alice [M5]: AuthB = MAC(KBA, SB || TS || LT)",
            "info", "bob", "alice",
            {
                "SB": SB,
                "KAB": KAB,
                "AuthB": f"MAC({KAB}, {SB} || TS || LT)"
            }
        )
    
    elif step == 6:
        if mitm_active:
            return ProtocolMessage(
                "🛡️ BLOQUEADO: Verificación de autenticidad falla. Hugo no tiene la clave correcta.",
                "success", "bob", "alice",
                {"result": "✅ MITM detectado y prevenido"}
            )
        else:
            return ProtocolMessage(
                "✅ CANAL SEGURO: Autenticación mutua exitosa. Claves verificadas.",
                "success", "bob", "alice",
                {"result": "Comunicación segura establecida"}
            )
    
    return ProtocolMessage("Paso inválido", "error")

def get_insecure_protocol_message(step: int, mitm_active: bool, params: dict = None) -> ProtocolMessage:
    """
    Genera el mensaje para un paso del protocolo INSEGURO (4 pasos).
    
    Pasos:
    1. Alice -> Bob: mA = IDA || ga || NA
    2. Hugo intercepta y suplanta: mE = IDA || ge || NE (a Bob)
    3. Bob -> Alice: mB = IDB || gb || NB
    4. Hugo intercepta y suplanta: mE = IDB || ge || NE (a Alice)
    
    Luego ambos calculan claves:
    - Alice y Hugo comparten: KAE = g^(a*e) mod p
    - Hugo y Bob comparten: KBE = g^(b*e) mod p
    """
    if params is None:
        params = {}
    
    alice = params.get('alice', {})
    bob = params.get('bob', {})
    hugo = params.get('hugo', {})
    g = params.get('g', 0)
    p = params.get('p', 0)
    
    ga = modExp(g, alice.get('secret', 0), p) if p > 0 else 0
    gb = modExp(g, bob.get('secret', 0), p) if p > 0 else 0
    ge = modExp(g, hugo.get('secret', 0), p) if p > 0 else 0
    
    # Claves calculadas por Hugo
    KAE = modExp(ga, hugo.get('secret', 0), p) if p > 0 and ga > 0 else 0
    KBE = modExp(gb, hugo.get('secret', 0), p) if p > 0 and gb > 0 else 0
    
    if step == 1:
        # Alice envía su mensaje con su valor público y nonce
        return ProtocolMessage(
            "📤 Alice -> Bob [M1]: mA = IDA || ga || NA (En claro).",
            "info", "alice", "bob",
            {"mA": f"{alice.get('id', 'IDA')} || {ga} || {alice.get('nonce', 0)}"}
        )
    
    elif step == 2:
        if mitm_active:
            # Hugo intercepta mA de Alice y suplanta ante Bob con mE
            return ProtocolMessage(
                "⚠️ HUGO intercepta M1 y suplanta ante Bob: mE = IDA || ge || NE (Hugo usa IDA)",
                "danger", "hugo", "bob",
                {"mE": f"{alice.get('id', 'IDA')} || {ge} || {hugo.get('nonce', 0)}"}
            )
        else:
            # Sin MITM, Bob recibe normalmente de Alice
            return ProtocolMessage(
                "📤 Bob <- Alice [M2]: mB = IDB || gb || NB (respuesta normal).",
                "info", "bob", "alice",
                {"mB": f"{bob.get('id', 'IDB')} || {gb} || {bob.get('nonce', 0)}"}
            )
    
    elif step == 3:
        if mitm_active:
            # Bob responde (recibió el mensaje falso de Hugo)
            return ProtocolMessage(
                "📤 Bob -> Hugo: mB = IDB || gb || NB (Bob responde al falso M1 de Hugo)",
                "info", "bob", "hugo",
                {"mB": f"{bob.get('id', 'IDB')} || {gb} || {bob.get('nonce', 0)}"}
            )
        else:
            # Sin MITM, intercambio normal
            SA = xorInt(alice.get('nonce', 0), bob.get('nonce', 0))
            KAB = modExp(g, alice.get('secret', 0) * bob.get('secret', 0), p) if p > 0 else 0
            return ProtocolMessage(
                "✅ Protocolo completado: SA = NA ⊕ NB, KAB = g^(ab) mod p",
                "success", "alice", "bob",
                {"SA": SA, "KAB": KAB}
            )
    
    elif step == 4:
        if mitm_active:
            # Hugo intercepta mB de Bob y suplanta ante Alice
            return ProtocolMessage(
                "⚠️ HUGO intercepta M2 y suplanta ante Alice: mE = IDB || ge || NE (Hugo usa IDB)",
                "danger", "hugo", "alice",
                {
                    "mE_to_Alice": f"{bob.get('id', 'IDB')} || {ge} || {hugo.get('nonce', 0)}",
                    "KAE": KAE,
                    "KBE": KBE
                }
            )
        else:
            # Sin MITM, nunca alcanza paso 4
            return ProtocolMessage(
                "❌ Paso 4 no alcanzado (protocolo completado en paso 3)",
                "error"
            )
    
    return ProtocolMessage("Paso inválido", "error")

# ==========================================
# ENDPOINTS HTTP
# ==========================================

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    """Sirve el archivo HTML del frontend."""
    return load_frontend_html()

@app.post("/reset")
def reset_system():
    """Reinicia el sistema a su estado inicial."""
    reset_all_state()
    return {"msg": "Sistema reiniciado correctamente"}

@app.get("/db")
def get_db():
    """Retorna el estado actual de la BD de dispositivos y la cámara."""
    return {"db": server_db, "camera_state": camera_state}

@app.post("/check_dos")
def check_dos(req: DoSRequest):
    """
    Verifica si un paquete es legítimo o realiza un ataque DoS.
    
    En modo seguro: Valida el dispositivo contra patrones de seguridad.
    En modo inseguro: Acepta cualquier paquete y drena la CPU.
    """
    global camera_state
    
    # 1. Chequeo si la cámara ya está caída
    if is_camera_down():
        return {
            "status": "error",
            "msg": "❌ FALLO DEL SISTEMA: La Cámara está fuera de servicio (CPU 0).",
            "camera_state": camera_state
        }
    
    # 2. Validar dispositivo según el modo
    if req.is_secure_mode:
        response_data = check_device_secure_mode(req)
    else:
        response_data = check_device_insecure_mode(req)
    
    # 3. Aplicar daño a CPU en modo inseguro
    if not req.is_secure_mode:
        reduce_cpu_health()
        
        if is_camera_down():
            response_data['msg'] = "❌ FALLO DEL SISTEMA: La CPU de la Cámara ha colapsado (CPU 0)."
            response_data['status'] = "danger"
    
    # 4. Incluir estado de cámara en respuesta
    response_data["camera_state"] = camera_state
    return response_data

@app.post("/protocol_step")
def protocol_step(req: ProtocolRequest):
    """
    Procesa un paso del protocolo de autenticación.
    Calcula y devuelve valores numéricos del protocolo MITM (Diffie-Hellman).
    
    Soporta dos modos:
    - mitm_secure: Protocolo seguro contra MITM (6 pasos)
    - mitm_insecure: Protocolo vulnerable a MITM (4 pasos)
    """
    is_secure = 'insecure' not in req.mode
    
    # Obtener mensaje del protocolo con valores calculados
    if is_secure:
        protocol_msg = get_secure_protocol_message(req.step, req.mitm_active, mitm_params)
        max_steps = SECURE_PROTOCOL_STEPS
    else:
        protocol_msg = get_insecure_protocol_message(req.step, req.mitm_active, mitm_params)
        max_steps = INSECURE_PROTOCOL_STEPS
    
    # Calcular siguiente paso
    next_step = req.step if req.step >= max_steps else req.step + 1
    
    return {
        "msg": protocol_msg.msg,
        "type": protocol_msg.type,
        "source": protocol_msg.source,
        "target": protocol_msg.target,
        "values": protocol_msg.values,
        "next_step": next_step
    }

@app.get("/mitm_params")
def get_mitm_params():
    """Retorna los parámetros MITM actuales."""
    return mitm_params

@app.post("/mitm_params")
def update_mitm_params(req: MitmParamsRequest):
    """
    Actualiza los parámetros MITM globales.
    Se usa cuando el usuario modifica g, p, IDs, secrets o nonces.
    """
    global mitm_params
    mitm_params = {
        "g": req.g,
        "p": req.p,
        "alice": {
            "id": req.alice.get("id", "IDA"),
            "secret": req.alice.get("secret", 1),
            "nonce": req.alice.get("nonce", 1000),
            "public": modExp(req.g, req.alice.get("secret", 1), req.p)
        },
        "bob": {
            "id": req.bob.get("id", "IDB"),
            "secret": req.bob.get("secret", 2),
            "nonce": req.bob.get("nonce", 2000),
            "public": modExp(req.g, req.bob.get("secret", 2), req.p)
        },
        "hugo": {
            "id": req.hugo.get("id", "IDE"),
            "secret": req.hugo.get("secret", 3),
            "nonce": req.hugo.get("nonce", 3000),
            "public": modExp(req.g, req.hugo.get("secret", 3), req.p)
        }
    }
    return mitm_params

@app.post("/mitm_calculate_hugo")
def calculate_hugo_values(req: MitmCalculateRequest):
    """
    Calcula los valores de Hugo basados en lo que "escucha" del protocolo.
    
    Hugo obtiene:
    - ga = g^a mod p (del mensaje de Alice en M1)
    - gb = g^b mod p (del mensaje de Bob en M2)
    
    Hugo genera su propio secreto e y calcula:
    - KAE = ga^e mod p = g^(a*e) mod p (clave compartida con Alice)
    - KBE = gb^e mod p = g^(b*e) mod p (clave compartida con Bob)
    
    Esto permite que Hugo suplante tanto a Alice como a Bob de forma simultánea.
    """
    global mitm_params
    
    g = req.g
    p = req.p
    
    # Hugo obtiene los valores públicos que "escucha"
    alice_secret = req.alice.get("secret", 1)
    bob_secret = req.bob.get("secret", 2)
    
    # Calcular ga y gb (valores públicos de Alice y Bob)
    ga = modExp(g, alice_secret, p)
    gb = modExp(g, bob_secret, p)
    
    # Hugo genera su propio secreto y nonce
    hugo_secret = random.randint(2, p - 2)
    hugo_nonce = random.randint(1000, 9999)
    hugo_public = modExp(g, hugo_secret, p)
    
    # Hugo calcula las claves compartidas:
    # KAE = ga^e mod p (clave con Alice, basada en ga que escucha)
    # KBE = gb^e mod p (clave con Bob, basada en gb que escucha)
    KAE = modExp(ga, hugo_secret, p)  # Elevar ga a la potencia de secreto_hugo
    KBE = modExp(gb, hugo_secret, p)  # Elevar gb a la potencia de secreto_hugo
    
    # Actualizar parámetros MITM globales
    mitm_params["hugo"] = {
        "id": "IDE",
        "secret": hugo_secret,
        "nonce": hugo_nonce,
        "public": hugo_public
    }
    mitm_params["g"] = g
    mitm_params["p"] = p
    mitm_params["alice"] = {
        "id": req.alice.get("id", "IDA"),
        "secret": alice_secret,
        "nonce": req.alice.get("nonce", 1000),
        "public": ga
    }
    mitm_params["bob"] = {
        "id": req.bob.get("id", "IDB"),
        "secret": bob_secret,
        "nonce": req.bob.get("nonce", 2000),
        "public": gb
    }
    
    return {
        "hugo": mitm_params["hugo"],
        "ga": ga,
        "gb": gb,
        "ge": hugo_public,
        "KAE": KAE,
        "KBE": KBE,
        "explanation": f"Hugo escucha ga={ga}, gb={gb}. Calcula ge={hugo_public}. Luego: KAE=ga^e={KAE}, KBE=gb^e={KBE}"
    }