import random
from config import MITAD_ICONO, ANCHO, CPU_CAMARA, VELOCIDAD_PAQUETE, FRECUENCIA_ATAQUE, ESPACIO_PAQUETE



posiciones_escenario = {
    1: { 'camara': (750, 200), 'semaforo': (100, 70), 'hacker': (100, 370), 'papelera': (0, 0) },
    2: { 'camara': (700, 200), 'semaforo': (100, 70), 'hacker': (100, 370), 'papelera': (850, 390) },
    3: { 'camara': (800, 70), 'semaforo': (50, 70), 'hacker': (425, 70), 'papelera': (0, 0) },
    4: { 'camara': (800, 70), 'semaforo': (50, 70), 'hacker': (425, 70), 'papelera': (800, 310) },
}

class Paquete:
    def __init__(self, x, y, destino_x, destino_y, es_malicioso, payload="DATA"):
        self.x = x
        self.y = y
        self.origen_x = x
        self.origen_y = y
        self.destino_x = destino_x
        self.destino_y = destino_y
        self.es_malicioso = es_malicioso
        self.payload = payload
        self.velocidad = VELOCIDAD_PAQUETE
        self.activo = True
        self.interceptado = False
        
        self.en_basura = False 
        self.rechazado_memoria = False 

    def mover(self):
        dx = self.destino_x - self.x
        dy = self.destino_y - self.y
        dist = (dx**2 + dy**2)**0.5
        if dist < self.velocidad: return True
        self.x += (dx / dist) * self.velocidad
        self.y += (dy / dist) * self.velocidad
        return False

class Actor:
    def __init__(self, x, y, nombre, rol):
        self.x = x
        self.y = y
        self.nombre = nombre
        self.rol = rol 

class GestorSimulacion:
    def __init__(self):
        self.escenario_actual = 0 
        self.paquetes = []
        
        self.timer_dos = 0
        self.fase_mitm = 0 
        self.paquete_mitm = None
        self.estado_msg = ""
        self.memoria_ips = set()

        # ESTADÍSTICAS
        self.stats_buenos_ok = 0    
        self.stats_malos_ok = 0     
        self.stats_bloqueados = 0   
        self.stats_perdidos = 0     

    def resetear(self, escenario_id):
        self.escenario_actual = escenario_id
        self.paquetes = []
        self.stats_buenos_ok = 0
        self.stats_malos_ok = 0
        self.stats_bloqueados = 0
        self.stats_perdidos = 0
        
        
        pos = posiciones_escenario[escenario_id]
        self.camara = Actor(pos['camara'][0], pos['camara'][1], "Cámara", 'camara')     
        self.semaforo = Actor(pos['semaforo'][0], pos['semaforo'][1], "Semáforo", 'semaforo')
        self.hacker = Actor(pos['hacker'][0], pos['hacker'][1], "Hacker", 'hacker')
        self.papelera = Actor(pos['papelera'][0], pos['papelera'][1], "Papelera", 'papelera')  
        self.camara.cpu = CPU_CAMARA


        self.fase_mitm = 0
        self.timer_dos = 0
        self.memoria_ips = set()
        
        msgs = {
            1: "Ejemplo 1: Ataque DoS (Sin protección)",
            2: "Ejemplo 2: Solución DoS (Filtro Inteligente)",
            3: "Ejemplo 3: Ataque MITM (Texto Plano)",
            4: "Ejemplo 4: Solución MITM (Commit/Open)"
        }
        self.estado_msg = msgs.get(escenario_id, "")

    def _centro(self, actor):
        return actor.x + MITAD_ICONO, actor.y + MITAD_ICONO

    def actualizar(self):
        if self.escenario_actual in [1, 2]: self._logica_dos()
        elif self.escenario_actual in [3, 4]: self._logica_mitm()

    def _enviar_a_papelera(self, paquete):
        if self.camara.cpu > 0:
            cx, cy = self._centro(self.papelera)
            paquete.destino_x = cx
            paquete.destino_y = cy
            paquete.en_basura = True 
            paquete.velocidad = 8 
        else:
            self._rechazar_por_memoria(paquete)

    def _rechazar_por_memoria(self, paquete):
        paquete.destino_x = ANCHO + 50 
        paquete.destino_y = -50        
        paquete.rechazado_memoria = True
        paquete.velocidad = 8 

    def _procesar_legitimo(self, paquete):
        self.paquetes.remove(paquete)
        if self.camara.cpu > 0:
            self.camara.cpu -= ESPACIO_PAQUETE 
            if self.camara.cpu < 0: self.camara.cpu = 0
            self.stats_buenos_ok += 1 
        else:
            self.stats_perdidos += 1 

    def _logica_dos(self):
        self.timer_dos += 1
        hx, hy = self._centro(self.hacker)
        sx, sy = self._centro(self.semaforo)
        cx, cy = self._centro(self.camara)

        if self.timer_dos > FRECUENCIA_ATAQUE:
            self.paquetes.append(Paquete(hx, hy, cx, cy, True))
            self.timer_dos = 0
        if random.randint(0, 150) < 2:
            self.paquetes.append(Paquete(sx, sy, cx, cy, False))

        for p in self.paquetes[:]:
            if p.mover(): 
                if p.en_basura:
                    self.paquetes.remove(p)
                    self.stats_bloqueados += 1 
                    continue
                if p.rechazado_memoria:
                    self.paquetes.remove(p)
                    self.stats_perdidos += 1
                    continue
                
                # SI MEMORIA ESTÁ LLENA (CPU <= 0): Rebote 
                if self.camara.cpu <= 0:
                    self._rechazar_por_memoria(p)
                    self.estado_msg = "💀 MEMORIA LLENA: Rechazando paquetes..."
                    continue

                # ESCENARIO 1: VULNERABLE
                if self.escenario_actual == 1:
                    self.paquetes.remove(p)
                    self.camara.cpu -= ESPACIO_PAQUETE
                    if self.camara.cpu < 0: self.camara.cpu = 0
                    
                    if p.es_malicioso: self.stats_malos_ok += 1
                    else: self.stats_buenos_ok += 1
                
                # ESCENARIO 2: SEGURO
                else:
                    identificador_origen = (p.origen_x, p.origen_y)
                    
                    if p.es_malicioso:
                        if identificador_origen not in self.memoria_ips:
                            # PRIMERO (Entra y daña)
                            self.memoria_ips.add(identificador_origen)
                            self.paquetes.remove(p)
                            self.camara.cpu -= ESPACIO_PAQUETE
                            self.stats_malos_ok += 1 
                            self.estado_msg = "⚠️ ALERTA: Nueva conexión registrada..."
                        else:
                            # REPETIDOS (Filtro -> Papelera)
                            self._enviar_a_papelera(p)
                            self.estado_msg = "🛡️ BLOQUEADO: Origen conocido (Filtro)"
                    else:
                        # Legítimo
                        self.memoria_ips.add(identificador_origen)
                        self._procesar_legitimo(p)

    def _logica_mitm(self):
        es_seguro = (self.escenario_actual == 4)
        hx, hy = self._centro(self.hacker)
        sx, sy = self._centro(self.semaforo)
        cx, cy = self._centro(self.camara)
        
        if self.fase_mitm == 0 and len(self.paquetes) == 0:
            if random.randint(0, 60) == 0:
                self.paquete_mitm = Paquete(sx, sy, hx, hy, False, "VERDE")
                self.paquetes.append(self.paquete_mitm)
                self.fase_mitm = 1
                self.estado_msg = "Semáforo enviando: 'VERDE'..."

        for p in self.paquetes[:]:
            if p.mover(): 
                if p.en_basura:
                    self.paquetes.remove(p)
                    self.stats_bloqueados += 1
                    self.fase_mitm = 0
                    continue
                if p.rechazado_memoria:
                    self.paquetes.remove(p)
                    self.stats_perdidos += 1
                    self.fase_mitm = 0
                    continue

                if self.fase_mitm == 1:
                    self.paquetes.remove(p)
                    self.fase_mitm = 2
                    self.estado_msg = "⚠️ HACKER MODIFICANDO A 'ROJO'..."
                    self.paquete_mitm = Paquete(hx, hy, cx, cy, True, "ROJO")
                    self.paquete_mitm.interceptado = True
                    self.paquetes.append(self.paquete_mitm)

                elif self.fase_mitm == 2:
                    # Si CPU muerta, rebote 
                    if self.camara.cpu <= 0:
                        self._rechazar_por_memoria(p)
                        self.estado_msg = "💀 SISTEMA CAÍDO"
                        continue

                    if not es_seguro:
                        self.paquetes.remove(p)
                        self.fase_mitm = 0
                        self.stats_malos_ok += 1 
                        self.estado_msg = "❌ FALLO: Cámara cree ROJO, multa a un inocente"
                    else:
                        self._enviar_a_papelera(p)
                        self.estado_msg = "✅ ÉXITO: Cámara detecta manipulación"