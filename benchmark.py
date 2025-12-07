from logic import GestorSimulacion
from config import CPU_CAMARA
import time

def ejecutar_benchmark(escenario_id, ciclos=1000):
    gestor = GestorSimulacion()
    gestor.resetear(escenario_id)
    
    print(f"--- Iniciando Benchmark: Escenario {escenario_id} ({ciclos} ciclos) ---")
    start_time = time.time()
    
    for _ in range(ciclos):
        gestor.actualizar()
        
    end_time = time.time()
    duration = end_time - start_time
    
    total_paquetes = gestor.stats_buenos_ok + gestor.stats_malos_ok + \
                gestor.stats_bloqueados + gestor.stats_perdidos
    
    if total_paquetes == 0: total_paquetes = 1
    
    tasa_bloqueo = (gestor.stats_bloqueados / total_paquetes) * 100
    tasa_perdida = (gestor.stats_perdidos / total_paquetes) * 100
    tasa_exito_ataque = (gestor.stats_malos_ok / total_paquetes) * 100
    
    print(f"   [Resultados]")
    print(f"   - CPU Final Cámara: {gestor.camara.cpu/CPU_CAMARA*100:.2f}%")
    print(f"   - Paquetes Procesados (OK): {gestor.stats_buenos_ok}")
    print(f"   - Ataques Exitosos: {gestor.stats_malos_ok}")
    print(f"   - Amenazas Neutralizadas: {gestor.stats_bloqueados}")
    print(f"   - Paquetes Perdidos (DoS): {gestor.stats_perdidos}")
    print(f"   --------------------------------")
    print(f"   > Eficacia del Filtro: {tasa_bloqueo:.2f}%")
    print(f"   > Disponibilidad del Sistema: {100 - tasa_perdida:.2f}%")
    print(f"   > Tasa de Éxito de Ataques: {tasa_exito_ataque:.2f}%")
    print(f"   > Tiempo de simulación: {duration:.4f}s\n")

if __name__ == "__main__":
    print("=== INFORME DE RENDIMIENTO DEL PROTOCOLO ===\n")
    ejecutar_benchmark(1, ciclos=2000) # DoS Vulnerable
    ejecutar_benchmark(2, ciclos=2000) # DoS Seguro
    ejecutar_benchmark(3, ciclos=1000) # MITM Vulnerable
    ejecutar_benchmark(4, ciclos=1000) # MITM Seguro