import pygame
from config import *
from logic import GestorSimulacion
from views import VistaSimulador

def main():
    pygame.init()
    pantalla = pygame.display.set_mode((ANCHO, ALTO))
    pygame.display.set_caption("Proyecto Smart City - Protocolo G-23")
    reloj = pygame.time.Clock()

    gestor = GestorSimulacion()
    vista = VistaSimulador(pantalla)

    # Estado: 0=Menu, 1,2,3,4=Escenarios
    estado_app = 0
    ejecutando = True

    while ejecutando:
        reloj.tick(FPS)
        
        for evento in pygame.event.get():
            if evento.type == pygame.QUIT:
                ejecutando = False
            
            if estado_app == 0:
                accion = vista.manejar_eventos_menu(evento)
                if accion:
                    estado_app = accion
                    gestor.resetear(accion)
            else:
                volver = vista.manejar_eventos_escenario(evento)
                if volver:
                    estado_app = 0

        if estado_app != 0:
            gestor.actualizar()

        if estado_app == 0:
            vista.dibujar_menu()
        else:
            vista.dibujar_escenario(gestor)

        pygame.display.flip()

    pygame.quit()

if __name__ == "__main__":
    main()