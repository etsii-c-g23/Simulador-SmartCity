import pygame

CPU_CAMARA = 1000
VELOCIDAD_PAQUETE = 5
FRECUENCIA_ATAQUE = 5
ESPACIO_PAQUETE = 5


ANCHO = 1000
ALTO = 600
FPS = 60

BLANCO = (255, 255, 255)
NEGRO = (0, 0, 0)
ROJO = (220, 50, 50)     
VERDE = (50, 200, 50)    
AZUL = (50, 50, 200)    
GRIS_CLARO = (230, 230, 230)
GRIS_OSCURO = (100, 100, 100)
AMARILLO = (255, 200, 0)

TAMANO_ICONO = 150  
MITAD_ICONO = TAMANO_ICONO // 2

def get_fuentes():
    return {
        'titulo': pygame.font.SysFont('Arial', 40, bold=True),
        'subtitulo': pygame.font.SysFont('Arial', 24),
        'texto': pygame.font.SysFont('Arial', 18),
        'alerta': pygame.font.SysFont('Arial', 18, bold=True)
    }