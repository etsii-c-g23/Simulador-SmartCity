# backend.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os

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

# --- MODELOS DE DATOS ---
class DoSRequest(BaseModel):
    mac: str
    rssi: int
    is_secure_mode: bool

class ProtocolRequest(BaseModel):
    step: int
    mode: str
    mitm_active: bool

# --- BASE DE DATOS EN MEMORIA ---
INITIAL_DB = {
    '11:22:33:44:55:66': {'rssi': -45, 'trusted': True, 'status': 'disconnected'}
}
server_db = INITIAL_DB.copy()

# ==========================================
#  NUEVO: RUTA PARA SERVIR EL FRONTEND
# ==========================================
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    # Esto lee tu archivo index.html y lo manda al navegador
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Error: No se encuentra el archivo index.html</h1>"

# --- ENDPOINTS API (LÓGICA) ---

@app.post("/reset")
def reset_system():
    global server_db
    server_db = {k: v.copy() for k, v in INITIAL_DB.items()}
    return {"msg": "Sistema reiniciado correctamente"}

@app.get("/db")
def get_db():
    return server_db

@app.post("/check_dos")
def check_dos(req: DoSRequest):
    global server_db
    
    if not req.is_secure_mode:
        return {"status": "success", "msg": "Paquete aceptado (Sin verificación de seguridad)."}

    entry = server_db.get(req.mac)

    if entry:
        # MAC CONOCIDA
        if entry['status'] == 'connected':
            return {"status": "error", "msg": f"⛔ BLOQUEADO: La MAC {req.mac} ya tiene sesión activa."}
        
        if abs(entry['rssi'] - req.rssi) > 10:
            return {"status": "error", "msg": f"⛔ BLOQUEADO: RSSI anómalo ({req.rssi} vs {entry['rssi']})."}
        
        server_db[req.mac]['status'] = 'connected'
        return {"status": "success", "msg": "✅ ACCESO CONCEDIDO: Dispositivo verificado."}

    else:
        # MAC DESCONOCIDA
        for stored_mac, data in server_db.items():
            if abs(data['rssi'] - req.rssi) < 5:
                return {"status": "error", "msg": f"⛔ BLOQUEADO: Distinta MAC en misma ubicación."}
        
        server_db[req.mac] = {'rssi': req.rssi, 'trusted': True, 'status': 'connected'}
        return {"status": "success", "msg": "🆕 NUEVO DISPOSITIVO: Registrado exitosamente."}

@app.post("/protocol_step")
def protocol_step(req: ProtocolRequest):
    step = req.step
    active = req.mitm_active
    is_secure = (req.mode == 'mitm_secure')

    msg = ""
    type_ = "info"
    # Definimos origen y destino por defecto
    source = "alice"
    target = "bob"

    if is_secure:
        # --- PROTOCOLO SEGURO (6 PASOS) ---
        if step == 1: 
            msg = f"📤 Alice -> Bob [M1]: Valor c. {'🙈 Hacker ve el commit, no el secreto mA.' if active else ''}"
            source, target = "alice", "bob"
        
        elif step == 2: 
            msg = f"📤 Bob -> Alice [M2]: mB = IDA || IDB || gb || Nb. {'👀 Hacker intercepta mB.' if active else ''}"
            source, target = "bob", "alice"
        
        elif step == 3: 
            if active: 
                msg = "🛡️ Alice -> Bob [M3]: Valor d. Hacker intenta modificar, pero falla la comprobación. BLOQUEADO."
                type_ = "success"
                # Visualmente: Hacker intenta inyectar a Bob, pero rebota
                source, target = "eve", "bob"
            else: 
                msg = "📤 Alice -> Bob [M3]: Valor d. Bob verifica integridad de d y c. OK."
                source, target = "alice", "bob"
        
        elif step == 4: 
            msg = f"📤 Alice -> Bob [M4]: AuthA = TS || LT || MAC(KAB, SA || TS || LT). {'👀 Hacker intercepta pero no puede descifrar.' if active else 'Bob recibe AuthA.'}"
            source, target = "alice", "bob"
        
        elif step == 5: 
            msg = f"📤 Bob -> Alice [M5]: AuthB = MAC(KBA, SB || TS || LT). {'👀 Hacker intercepta pero no puede descifrar.' if active else 'Alice recibe AuthB.'}"
            source, target = "bob", "alice"
        
        elif step == 6: 
            msg = "✅ CANAL SEGURO: Autenticación mutua exitosa. Claves SAS verificadas MACA == MACB."
            type_ = "success"
            source, target = "bob", "alice" # Cierre de conexión

    else:
        # --- PROTOCOLO INSEGURO (4 PASOS) ---
        if step == 1: 
            msg = "📤 Alice -> Bob [M1]: mA = IDA || ga || NA (En claro)."
            source, target = "alice", "bob"
        
        elif step == 2: 
            if active: 
                msg = "⚠️ EVE intercepta mA y genera mE = IDA || ge || NE"
                type_ = "danger"
                # Visualmente: Eve suplanta a Alice hacia Bob
                source, target = "eve", "bob"
            else: 
                msg = "📤 Bob -> Alice [M2]: mB = IDB || gb || NB (En claro)."
                source, target = "bob", "alice"
        
        elif step == 3:
            if active:
                msg = "📤 EVE -> Bob: Envía mE falsificado. Bob calcula SB = NE ⊕ NB"
                type_ = "danger"
                # Visualmente: Eve sigue atacando a Bob
                source, target = "eve", "bob"
            else:
                msg = "Alice calcula SA = NA ⊕ NB. Bob calcula SB = NA ⊕ NB."
                source, target = "alice", "bob"
        
        elif step == 4:
            if active:
                msg = "❌ MITM EXITOSO: Eve establece KAE = gᵃᵉ con Alice y KBE = gbe con Bob."
                type_ = "danger"
                # Visualmente: Bob responde al atacante creyendo que es Alice
                source, target = "bob", "eve"
            else:
                msg = "✅ Autenticación exitosa. Alice y Bob establecen KAB = gab mod p."
                type_ = "success"
                source, target = "bob", "alice"

    # Calculamos límites (6 para seguro, 4 para inseguro)
    max_steps = 6 if is_secure else 4
    next_s = step if step >= max_steps else step + 1

    return {
        "msg": msg, 
        "type": type_, 
        "source": source, 
        "target": target, 
        "next_step": next_s
    }