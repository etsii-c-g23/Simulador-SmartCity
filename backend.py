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
                return {"status": "error", "msg": f"⛔ BLOQUEADO: Misma MAC en nueva en ubicación."}
        
        server_db[req.mac] = {'rssi': req.rssi, 'trusted': True, 'status': 'connected'}
        return {"status": "success", "msg": "🆕 NUEVO DISPOSITIVO: Registrado exitosamente."}

@app.post("/protocol_step")
def protocol_step(req: ProtocolRequest):
    step = req.step
    active = req.mitm_active
    is_secure = (req.mode == 'mitm_secure')

    msg = ""
    type_ = "info"
    intercepted = False
    
    if active and not is_secure and step == 2:
        intercepted = True

    if is_secure:
        if step == 1: msg = f"📤 Alice -> Bob [M1]: Valor c. {'🙈 Hacker ve el commit, no el secreto mA.' if active else ''}"
        elif step == 2: msg = f"📤 Bob -> Alice [M2]: mB = IDA || IDB || gb || Nb. {'👀 Hacker intercepta mB.' if active else ''}"
        elif step == 3: 
            if active: msg = "🛡️ Alice -> Bob [M3]: Valor d. Hacker intenta modificar, pero falla la comprobación. BLOQUEADO."; type_="success"
            else: msg = "📤 Alice -> Bob [M3]: Valor d. Bob verifica integridad de d y c. OK."
        elif step == 4: 
            msg = f"📤 Alice -> Bob [M4]: AuthA = TS || LT || MAC(KAB, SA || TS || LT). {'👀 Hacker intercepta pero no puede descifrar.' if active else 'Bob recibe AuthA.'}"
        elif step == 5: 
            msg = f"📤 Bob -> Alice [M5]: AuthB = MAC(KBA, SB || TS || LT). {'👀 Hacker intercepta pero no puede descifrar.' if active else 'Alice recibe AuthB.'}"
        elif step == 6: 
            msg = "✅ CANAL SEGURO: Autenticación mutua exitosa. Claves SAS verificadas MACA == MACB."; type_="success"
    else:
        if step == 1: 
            msg = "📤 Alice -> Bob [M1]: mA = IDA || ga || NA (En claro)."
        elif step == 2: 
            if active: 
                msg = "⚠️ EVE intercepta mA y genera mE = IDA || ge || NE"; type_="danger"
            else: 
                msg = "📤 Bob -> Alice [M2]: mB = IDB || gb || NB (En claro)."
        elif step == 3:
            if active:
                msg = "📤 EVE -> Bob: Envía mE falsificado. Bob calcula SB = NE ⊕ NB"; type_="danger"
            else:
                msg = "Alice calcula SA = NA ⊕ NB. Bob calcula SB = NA ⊕ NB."
        elif step == 4:
            if active:
                msg = "❌ MITM EXITOSO: Eve establece KAE = gᵃᵉ con Alice y KBE = gbe con Bob."; type_="danger"
            else:
                msg = "✅ Autenticación exitosa. Alice y Bob establecen KAB = gab mod p."

    return {
        "msg": msg, 
        "type": type_, 
        "intercepted": intercepted,
        "next_step": step if step >= (6 if is_secure else 3) else step + 1
    }
