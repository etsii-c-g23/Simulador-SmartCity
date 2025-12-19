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
    alice: dict  # {mac, a, NA, public}
    bob: dict
    hugo: dict

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
SECURE_PROTOCOL_STEPS_NO_ATTACK = 6  # Sin MITM activo
SECURE_PROTOCOL_STEPS_WITH_ATTACK = 12  # Con MITM activo
INSECURE_PROTOCOL_STEPS_NO_ATTACK = 4  # Sin MITM activo
INSECURE_PROTOCOL_STEPS_WITH_ATTACK = 10  # Con MITM activo

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
    alice_a = random.randint(2, DEFAULT_PRIME_P - 2)
    bob_b = random.randint(2, DEFAULT_PRIME_P - 2)
    hugo_e = random.randint(2, DEFAULT_PRIME_P - 2)

    alice_na = random.randint(1000, 9999)
    bob_nb = random.randint(1000, 9999)
    hugo_ne = random.randint(1000, 9999)

    return {
        'g': DEFAULT_BASE_G,
        'p': DEFAULT_PRIME_P,
        'alice': {
            'mac': 'AA:BB:CC:DD:EE:01',
            'a': alice_a,
            'NA': alice_na,
            'public': modExp(DEFAULT_BASE_G, alice_a, DEFAULT_PRIME_P)
        },
        'bob': {
            'mac': 'AA:BB:CC:DD:EE:02',
            'b': bob_b,
            'NB': bob_nb,
            'public': modExp(DEFAULT_BASE_G, bob_b, DEFAULT_PRIME_P)
        },
        'hugo': {
            'mac': 'AA:BB:CC:DD:EE:03',
            'e': hugo_e,
            'NE': hugo_ne,
            'public': modExp(DEFAULT_BASE_G, hugo_e, DEFAULT_PRIME_P)
        }
    }

# ==========================================
# ESTADO GLOBAL
# ==========================================

server_db = INITIAL_DB.copy()
camera_state = INITIAL_CAMERA_STATE.copy()
mitm_params = create_initial_mitm_params()
protocol_session_ts = None  # TS persistente por sesión de protocolo

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
    global server_db, camera_state, mitm_params, protocol_session_ts
    server_db = {k: v.copy() for k, v in INITIAL_DB.items()}
    camera_state = INITIAL_CAMERA_STATE.copy()
    mitm_params = create_initial_mitm_params()
    protocol_session_ts = None

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
    Genera el mensaje para un paso del protocolo SEGURO.
    
    SIN ATAQUE ACTIVO (6 pasos):
    1. Alice -> Bob: c (commit de mA)
    2. Bob -> Alice: mB = IDA || IDB || gb || NB
    3. Alice -> Bob: mA = IDA || ga || NA + d (decommit)
    4. Alice -> Bob: AuthA = TS || LT || MAC(KAB, SA || TS || LT)
    5. Bob -> Alice: AuthB = MAC(KBA, SB || TS || LT)
    6. Verificación mutua exitosa
    
    CON ATAQUE ACTIVO (12 pasos):
    1. Alice -> Hugo: cA (Hugo intercepta)
    2. Hugo -> Bob: cE (Hugo suplanta a Alice)
    3. Bob -> Hugo: mB = IDB || gb || NB
    4. Hugo modifica mB a mB' (reemplaza gb con ge)
    5. Hugo -> Alice: mB'
    6. Alice -> Hugo: dA
    7. Hugo -> Bob: dE
    8. Alice calcula: SA = NA ⊕ NB
    9. Bob calcula: SB = NA ⊕ NB
    10. Alice -> Hugo: AuthA = TS || LT || MAC(KAE, SA || TS || LT)
    11. Bob -> Hugo: AuthB = MAC(KBE, SB || TS || LT)
    12. Hugo intenta manipular autenticadores pero falla (MITM detectado)
    """
    if params is None:
        params = {}
    
    import time
    global protocol_session_ts

    if protocol_session_ts is None or step == 1:
        protocol_session_ts = int(time.time())

    alice = params.get('alice', {})
    bob = params.get('bob', {})
    hugo = params.get('hugo', {})
    g = params.get('g', 0)
    p = params.get('p', 0)

    ga = modExp(g, alice.get('a', 0), p) if p > 0 else 0
    gb = modExp(g, bob.get('b', 0), p) if p > 0 else 0
    ge = modExp(g, hugo.get('e', 0), p) if p > 0 else 0

    KAE = modExp(ga, hugo.get('e', 0), p) if p > 0 and ga > 0 else 0
    KBE = modExp(gb, hugo.get('e', 0), p) if p > 0 and gb > 0 else 0

    # Generar TS (Timestamp) y LT (Lifetime) para seguridad
    ts = protocol_session_ts
    lt = 3600  # 1 hora de validez

    commit_ca = f"hash({alice.get('mac', 'IDA')}||{ga}||{alice.get('NA', 0)})"
    commit_ce = f"hash({alice.get('mac', 'IDA')}||{ge}||{hugo.get('NE', 0)})"
    decommit_da = f"open({commit_ca}) => {alice.get('mac', 'IDA')}||{ga}||{alice.get('NA', 0)}"
    
    # ===== SIN ATAQUE ACTIVO (6 pasos) =====
    if not mitm_active:
        if step == 1:
            return ProtocolMessage(
                "📤 Alice -> Bob [M1]: cA (commit de mA)",
                "info", "alice", "bob",
                {"c": commit_ca, "mA": f"{alice.get('mac', 'IDA')}||{ga}||{alice.get('NA', 0)}"}
            )
        
        elif step == 2:
            return ProtocolMessage(
                "📤 Bob -> Alice [M2]: mB = IDA || IDB || gb || NB",
                "info", "bob", "alice",
                {"mB": f"{alice.get('mac', 'IDA')} || {bob.get('mac', 'IDB')} || {gb} || {bob.get('NB', 0)}"}
            )
        
        elif step == 3:
            return ProtocolMessage(
                "📤 Alice -> Bob [M3]: dA => mA = IDA || ga || NA",
                "info", "alice", "bob",
                {
                    "mA": f"{alice.get('mac', 'IDA')} || {ga} || {alice.get('NA', 0)}",
                    "c": commit_ca,
                    "dA": decommit_da
                }
            )
        
        elif step == 4:
            SA = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            KAB = modExp(g, alice.get('a', 0) * bob.get('b', 0), p) if p > 0 else 0
            return ProtocolMessage(
                f"📤 Alice -> Bob [M4]: AuthA = {ts} || {lt} || MAC(KAB, SA || {ts} || {lt})",
                "info", "alice", "bob",
                {
                    "SA": SA,
                    "KAB": KAB,
                    "TS": ts,
                    "LT": lt,
                    "AuthA": f"MAC({KAB}, {SA} || {ts} || {lt})"
                }
            )
        
        elif step == 5:
            SB = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            KAB = modExp(g, alice.get('a', 0) * bob.get('b', 0), p) if p > 0 else 0
            return ProtocolMessage(
                f"📤 Bob -> Alice [M5]: AuthB = MAC(KAB, {SB} || {ts} || {lt})",
                "info", "bob", "alice",
                {
                    "SB": SB,
                    "KAB": KAB,
                    "TS": ts,
                    "LT": lt,
                    "AuthB": f"MAC({KAB}, {SB} || {ts} || {lt})"
                }
            )
        
        elif step == 6:
            return ProtocolMessage(
                "✅ CANAL SEGURO: Autenticación mutua exitosa. Claves verificadas. TS y LT validados.",
                "success", "bob", "alice",
                {"result": "Comunicación segura establecida", "TS": ts, "LT": lt}
            )

    # ===== CON ATAQUE ACTIVO (11 pasos) =====
    else:
        if step == 1:
            return ProtocolMessage(
                "📤 Alice -> Hugo [M1]: cA (Hugo intercepta)",
                "info", "alice", "hugo",
                {"cA": commit_ca, "mA": f"{alice.get('mac', 'IDA')} || {ga} || {alice.get('NA', 0)}"}
            )

        elif step == 2:
            return ProtocolMessage(
                "⚠️ Hugo -> Bob [M2]: cE (Hugo suplanta a Alice)",
                "danger", "hugo", "bob",
                {"cE": commit_ce, "mE": f"{alice.get('mac', 'IDA')} || {ge} || {hugo.get('NE', 0)}"}
            )

        elif step == 3:
            return ProtocolMessage(
                "📤 Bob -> Hugo [M3]: mB = IDB || gb || NB",
                "info", "bob", "hugo",
                {"mB": f"{bob.get('mac', 'IDB')} || {gb} || {bob.get('NB', 0)}"}
            )

        elif step == 4:
            return ProtocolMessage(
                "⚠️ Hugo modifica mB [M4]: mB' = IDB || ge || NB (reemplaza gb con ge)",
                "danger", "hugo", "hugo",
                {
                    "mB": f"{bob.get('mac', 'IDB')} || {gb} || {bob.get('NB', 0)}",
                    "mBp": f"{bob.get('mac', 'IDB')} || {ge} || {bob.get('NB', 0)}"
                }
            )

        elif step == 5:
            return ProtocolMessage(
                "⚠️ Hugo -> Alice [M5]: mB' (Hugo suplanta a Bob)",
                "danger", "hugo", "alice",
                {"mBp": f"{bob.get('mac', 'IDB')} || {ge} || {bob.get('NB', 0)}"}
            )

        elif step == 6:
            return ProtocolMessage(
                "📤 Alice -> Hugo [M6]: dA => mA = IDA || ga || NA",
                "info", "alice", "hugo",
                {"dA": decommit_da, "cA": commit_ca}
            )

        elif step == 7:
            decommit_de = f"open({commit_ce}) => {alice.get('mac', 'IDA')}||{ge}||{hugo.get('NE', 0)}"
            return ProtocolMessage(
                "⚠️ Hugo -> Bob [M7]: dE => mE = IDA || ge || NE",
                "danger", "hugo", "bob",
                {"dE": decommit_de, "cE": commit_ce}
            )

        elif step == 8:
            SA = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            return ProtocolMessage(
                f"📤 Alice calcula [M8]: SA = NA ⊕ NB = {SA}",
                "info", "alice", "alice",
                {"SA": SA}
            )

        elif step == 9:
            SB = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            return ProtocolMessage(
                f"📤 Bob calcula [M9]: SB = NA ⊕ NB = {SB}",
                "info", "bob", "bob",
                {"SB": SB}
            )

        elif step == 10:
            SA = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            return ProtocolMessage(
                f"📤 Alice -> Hugo [M10]: AuthA = {ts} || {lt} || MAC(KAE, {SA} || {ts} || {lt})",
                "info", "alice", "hugo",
                {
                    "SA": SA,
                    "KAE": KAE,
                    "TS": ts,
                    "LT": lt,
                    "AuthA": f"MAC({KAE}, {SA} || {ts} || {lt})"
                }
            )

        elif step == 11:
            SB = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            return ProtocolMessage(
                f"📤 Bob -> Hugo [M11]: AuthB = MAC(KBE, {SB} || {ts} || {lt})",
                "info", "bob", "hugo",
                {
                    "SB": SB,
                    "KBE": KBE,
                    "TS": ts,
                    "LT": lt,
                    "AuthB": f"MAC({KBE}, {SB} || {ts} || {lt})"
                }
            )

        elif step == 12:
            return ProtocolMessage(
                "🛡️ BLOQUEADO [M12]: Hugo no puede falsificar el MAC correcto. KAE ≠ KBE. MITM detectado y prevenido.",
                "success", "hugo", "alice",
                {
                    "result": "✅ MITM detectado y prevenido",
                    "reason": "Hugo no puede crear MACs válidos porque KAE ≠ KBE",
                    "KAE": KAE,
                    "KBE": KBE,
                    "TS": ts,
                    "LT": lt
                }
            )
    
    return ProtocolMessage("Paso inválido", "error")

def get_insecure_protocol_message(step: int, mitm_active: bool, params: dict = None) -> ProtocolMessage:
    """
    Genera el mensaje para un paso del protocolo INSEGURO.
    
    SIN ATAQUE ACTIVO (4 pasos):
    1. Alice -> Bob: mA = IDA || ga || NA
    2. Bob -> Alice: mB = IDB || gb || NB
    3. Alice -> Bob: d (decommit)
    4. Completado: SA = NA ⊕ NB
    
    CON ATAQUE ACTIVO (10 pasos):
    1. Alice -> Hugo: commit c (Hugo intercepta la request a Bob)
    2. Hugo -> Bob: suplanta a Alice enviando commit ce
    3. Bob -> Hugo: mB = IDB || gb || NB
    4. Hugo -> Alice: mB' = IDB || ge || NB
    5. Alice -> Hugo: dA y se obtiene mA
    6. Hugo -> Bob: dE
    7. Alice -> Hugo: SA = NA ⊕ NE
    8. Bob -> Hugo: SB = NB ⊕ NE
    9. Hugo -> Alice: SAE = NA ⊕ NE
    10. Hugo -> Bob: SBE = NB ⊕ NE, MITM completado
    """
    if params is None:
        params = {}
    
    alice = params.get('alice', {})
    bob = params.get('bob', {})
    hugo = params.get('hugo', {})
    g = params.get('g', 0)
    p = params.get('p', 0)

    ga = modExp(g, alice.get('a', 0), p) if p > 0 else 0
    gb = modExp(g, bob.get('b', 0), p) if p > 0 else 0
    ge = modExp(g, hugo.get('e', 0), p) if p > 0 else 0

    KAE = modExp(ga, hugo.get('e', 0), p) if p > 0 and ga > 0 else 0
    KBE = modExp(gb, hugo.get('e', 0), p) if p > 0 and gb > 0 else 0

    commit_c = f"hash({alice.get('mac', 'IDA')}||{ga}||{alice.get('NA', 0)})"
    commit_ce = f"hash({alice.get('mac', 'IDA')}||{ge}||{hugo.get('NE', 0)})"
    decommit_da = f"open({commit_c}) => {alice.get('mac', 'IDA')}||{ga}||{alice.get('NA', 0)}"
    decommit_de = f"open({commit_ce}) => {alice.get('mac', 'IDA')}||{ge}||{hugo.get('NE', 0)}"

    # ===== SIN ATAQUE ACTIVO (4 pasos) =====
    if not mitm_active:
        if step == 1:
            return ProtocolMessage(
                "📤 Alice -> Bob [M1]: c (commit)",
                "info", "alice", "bob",
                {"c": commit_c, "mA": f"{alice.get('mac', 'IDA')} || {ga} || {alice.get('NA', 0)}"}
            )

        elif step == 2:
            return ProtocolMessage(
                "📤 Bob -> Alice [M2]: mB = IDB || gb || NB",
                "info", "bob", "alice",
                {"mB": f"{bob.get('mac', 'IDB')} || {gb} || {bob.get('NB', 0)}"}
            )

        elif step == 3:
            return ProtocolMessage(
                "📤 Alice -> Bob [M3]: dA => mA = IDA || ga || NA",
                "info", "alice", "bob",
                {"dA": decommit_da, "c": commit_c}
            )

        elif step == 4:
            SA = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            SB = xorInt(alice.get('NA', 0), bob.get('NB', 0))
            return ProtocolMessage(
                "✅ Autenticación mutua completada: SA = SB = NA ⊕ NB",
                "success", "alice", "bob",
                {"SA": SA, "SB": SB}
            )

    # ===== CON ATAQUE ACTIVO (10 pasos) =====
    else:
        if step == 1:
            return ProtocolMessage(
                "📤 Alice -> Hugo [M1]: c (Hugo intercepta)",
                "info", "alice", "hugo",
                {"c": commit_c, "mA": f"{alice.get('mac', 'IDA')} || {ga} || {alice.get('NA', 0)}"}
            )

        elif step == 2:
            return ProtocolMessage(
                "⚠️ Hugo -> Bob [M2]: ce (Hugo suplanta a Alice)",
                "danger", "hugo", "bob",
                {"ce": commit_ce, "mE": f"{alice.get('mac', 'IDA')} || {ge} || {hugo.get('NE', 0)}"}
            )

        elif step == 3:
            return ProtocolMessage(
                "📤 Bob -> Hugo [M3]: mB = IDB || gb || NB",
                "info", "bob", "hugo",
                {"mB": f"{bob.get('mac', 'IDB')} || {gb} || {bob.get('NB', 0)}"}
            )

        elif step == 4:
            return ProtocolMessage(
                "⚠️ Hugo -> Alice [M4]: mB' = IDB || ge || NE (Hugo suplanta a Bob)",
                "danger", "hugo", "alice",
                {
                    "mBp": f"{bob.get('mac', 'IDB')} || {ge} || {hugo.get('NE', 0)}",
                    "KAE": KAE
                }
            )

        elif step == 5:
            return ProtocolMessage(
                "📤 Alice -> Hugo [M5]: dA => mA = IDA || ga || NA",
                "info", "alice", "hugo",
                {"dA": decommit_da, "c": commit_c}
            )

        elif step == 6:
            return ProtocolMessage(
                "⚠️ Hugo -> Bob [M6]: dE => mE = IDA || ge || NE",
                "danger", "hugo", "bob",
                {"dE": decommit_de, "ce": commit_ce}
            )

        elif step == 7:
            SAE = xorInt(alice.get('NA', 0), hugo.get('NE', 0))
            return ProtocolMessage(
                "📤 Alice -> Hugo [M7]: SA = NA ⊕ NE",
                "info", "alice", "hugo",
                {"SA": SAE}
            )

        elif step == 8:
            SBE = xorInt(bob.get('NB', 0), hugo.get('NE', 0))
            return ProtocolMessage(
                "📤 Bob -> Hugo [M8]: SB = NB ⊕ NE",
                "info", "bob", "hugo",
                {"SB": SBE}
            )

        elif step == 9:
            SAE = xorInt(alice.get('NA', 0), hugo.get('NE', 0))
            return ProtocolMessage(
                "⚠️ Hugo -> Alice [M9]: SAE = NA ⊕ NE",
                "danger", "hugo", "alice",
                {"SAE": SAE}
            )

        elif step == 10:
            SBE = xorInt(bob.get('NB', 0), hugo.get('NE', 0))
            return ProtocolMessage(
                "⚠️ Hugo -> Bob [M10]: SBE = NB ⊕ NE - MITM COMPLETADO",
                "danger", "hugo", "bob",
                {
                    "SBE": SBE,
                    "KAE": KAE,
                    "KBE": KBE
                }
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
    - mitm_insecure: Protocolo vulnerable a MITM
      - Sin ataque (mitm_active=False): 4 pasos
      - Con ataque (mitm_active=True): 6 pasos
    """
    is_secure = 'insecure' not in req.mode
    
    # Obtener mensaje del protocolo con valores calculados
    if is_secure:
        protocol_msg = get_secure_protocol_message(req.step, req.mitm_active, mitm_params)
        # Determinar max_steps de forma dinámica según el estado del ataque
        max_steps = SECURE_PROTOCOL_STEPS_WITH_ATTACK if req.mitm_active else SECURE_PROTOCOL_STEPS_NO_ATTACK
    else:
        protocol_msg = get_insecure_protocol_message(req.step, req.mitm_active, mitm_params)
        # Determinar max_steps de forma dinámica según el estado del ataque
        max_steps = INSECURE_PROTOCOL_STEPS_WITH_ATTACK if req.mitm_active else INSECURE_PROTOCOL_STEPS_NO_ATTACK
    
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
    Se usa cuando el usuario modifica g, p, MACs, exponentes (a/b/e) o nonces.
    """
    global mitm_params
    mitm_params = {
        "g": req.g,
        "p": req.p,
        "alice": {
            "mac": req.alice.get("mac", "AA:BB:CC:DD:EE:01"),
            "a": req.alice.get("a", 1),
            "NA": req.alice.get("NA", 1000),
            "public": modExp(req.g, req.alice.get("a", 1), req.p)
        },
        "bob": {
            "mac": req.bob.get("mac", "AA:BB:CC:DD:EE:02"),
            "b": req.bob.get("b", 2),
            "NB": req.bob.get("NB", 2000),
            "public": modExp(req.g, req.bob.get("b", 2), req.p)
        },
        "hugo": {
            "mac": req.hugo.get("mac", "AA:BB:CC:DD:EE:03"),
            "e": req.hugo.get("e", 3),
            "NE": req.hugo.get("NE", 3000),
            "public": modExp(req.g, req.hugo.get("e", 3), req.p)
        }
    }
    return mitm_params
