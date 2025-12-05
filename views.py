import pygame
import os
from config import *

class Boton:
    def __init__(self, x, y, ancho, alto, texto, id_accion):
        self.rect = pygame.Rect(x, y, ancho, alto)
        self.texto = texto
        self.id_accion = id_accion
        self.color_base = AZUL
        self.color_hover = (100, 100, 255)

    def dibujar(self, pantalla, fuentes):
        pos_mouse = pygame.mouse.get_pos()
        color = self.color_hover if self.rect.collidepoint(pos_mouse) else self.color_base
        pygame.draw.rect(pantalla, color, self.rect, border_radius=12)
        pygame.draw.rect(pantalla, NEGRO, self.rect, 2, border_radius=12)
        txt_surf = fuentes['subtitulo'].render(self.texto, True, BLANCO)
        rect_txt = txt_surf.get_rect(center=self.rect.center)
        pantalla.blit(txt_surf, rect_txt)

    def es_cliqueado(self, evento):
        if evento.type == pygame.MOUSEBUTTONDOWN and self.rect.collidepoint(evento.pos):
            return True
        return False

class VistaSimulador:
    def __init__(self, pantalla):
        self.pantalla = pantalla
        self.fuentes = get_fuentes()
        
        self.imgs = {}
        nombres = ['semaforo', 'camara', 'camara_rota', 'hacker', 'papelera']
        for nombre in nombres:
            ruta = os.path.join('media', f'{nombre}.png')
            try:
                img_original = pygame.image.load(ruta).convert_alpha() 
                self.imgs[nombre] = pygame.transform.smoothscale(img_original, (TAMANO_ICONO, TAMANO_ICONO))
            except Exception as e:
                print(f"Error cargando {nombre}: {e}")
                self.imgs[nombre] = None

        center_x = ANCHO // 2 - 150
        self.botones = [
            Boton(center_x, 150, 300, 50, "1. Problema Conexión (DoS)", 1),
            Boton(center_x, 220, 300, 50, "2. Solución Conexión (Filtro)", 2),
            Boton(center_x, 290, 300, 50, "3. Problema Claves (MITM)", 3),
            Boton(center_x, 360, 300, 50, "4. Solución Claves (Seguro)", 4),
        ]
        self.boton_volver = Boton(20, 20, 100, 40, "< Volver", 0)

    def dibujar_menu(self):
        self.pantalla.fill(GRIS_CLARO)
        titulo = self.fuentes['titulo'].render(u"Simulador Seguridad Smart City", True, NEGRO)
        self.pantalla.blit(titulo, (ANCHO//2 - titulo.get_width()//2, 50))
        for btn in self.botones:
            btn.dibujar(self.pantalla, self.fuentes)

    def dibujar_escenario(self, gestor):
        self.pantalla.fill(BLANCO)
        
        # Header
        header = self.fuentes['subtitulo'].render(gestor.estado_msg, True, NEGRO)
        self.pantalla.blit(header, (150, 25))
        self.boton_volver.dibujar(self.pantalla, self.fuentes)

        # Actores
        self._dibujar_actor_imagen(gestor.camara)
        self._dibujar_actor_imagen(gestor.semaforo)
        self._dibujar_actor_imagen(gestor.hacker)
        
        if gestor.escenario_actual in [2, 4]:
            self._dibujar_actor_imagen(gestor.papelera)
        
        # --- PAQUETES (MODIFICADO SOLO ESTO) ---
        for p in gestor.paquetes:
            color = VERDE # Por defecto buenos
            
            if p.en_basura:
                color = AMARILLO # A papelera
            elif p.rechazado_memoria:
                color = GRIS_OSCURO     # A esquina (memoria llena)
            elif p.es_malicioso:
                color = ROJO     # Atacante activo
            
            pygame.draw.circle(self.pantalla, color, (int(p.x), int(p.y)), 10)
            if p.interceptado:
                pygame.draw.circle(self.pantalla, NEGRO, (int(p.x), int(p.y)), 10, 3)

        # --- PANEL DE ESTADÍSTICAS (TU DISEÑO EXACTO) ---
        altura_panel = 60  
        panel_y = ALTO - altura_panel
        
        pygame.draw.rect(self.pantalla, GRIS_OSCURO, (0, panel_y, ANCHO, altura_panel))
        
        info_cajas = [
            (f"Paquetes buenos recibidos: {gestor.stats_buenos_ok}", VERDE),
            (f"Paquetes malos recibidos: {gestor.stats_malos_ok}", ROJO),
            (f"Bloqueados: {gestor.stats_bloqueados}", AMARILLO),
            (f"Perdidos (Fallo del sistema): {gestor.stats_perdidos}", GRIS_CLARO)
        ]

        margen_x = 10
        ancho_columna = ANCHO // 4
        ancho_caja = ancho_columna - (margen_x * 2)
        alto_caja = 40 
        
        # Centrado vertical
        pos_y_caja = panel_y + (altura_panel - alto_caja) // 2
        
        for i, (texto, color) in enumerate(info_cajas):
            pos_x = (i * ancho_columna) + margen_x
            
            rect_caja = pygame.Rect(pos_x, pos_y_caja, ancho_caja, alto_caja)
            
            pygame.draw.rect(self.pantalla, color, rect_caja, border_radius=8)
            pygame.draw.rect(self.pantalla, NEGRO, rect_caja, 2, border_radius=8)
            
            surf_texto = self.fuentes['texto'].render(texto, True, NEGRO)
            rect_texto = surf_texto.get_rect(center=rect_caja.center)
            self.pantalla.blit(surf_texto, rect_texto)

    def _dibujar_actor_imagen(self, actor):
        imagen_a_usar = None
        
        if actor.rol == 'camara':
            if actor.cpu <= 0:
                imagen_a_usar = self.imgs.get('camara_rota')
            else:
                imagen_a_usar = self.imgs.get('camara')
        else:
            imagen_a_usar = self.imgs.get(actor.rol)

        if imagen_a_usar:
            self.pantalla.blit(imagen_a_usar, (actor.x, actor.y))
        else:
            pygame.draw.rect(self.pantalla, GRIS_OSCURO, (actor.x, actor.y, TAMANO_ICONO, TAMANO_ICONO))

        
        if actor.rol == 'camara':
            ratio = actor.cpu / 100
            color_cpu = AZUL if ratio > 0.5 else ROJO
            bar_y = actor.y + TAMANO_ICONO + 5
            pygame.draw.rect(self.pantalla, NEGRO, (actor.x, bar_y, TAMANO_ICONO, 10))
            if actor.cpu > 0:
                pygame.draw.rect(self.pantalla, color_cpu, (actor.x, bar_y, TAMANO_ICONO * ratio, 10))
            
            if actor.cpu <= 0:
                alerta = self.fuentes['alerta'].render("FALLO DEL SISTEMA", True, ROJO)
                self.pantalla.blit(alerta, (actor.x + (TAMANO_ICONO//2) - (alerta.get_width()//2), bar_y + 15))

    def manejar_eventos_menu(self, evento):
        for btn in self.botones:
            if btn.es_cliqueado(evento):
                return btn.id_accion
        return None

    def manejar_eventos_escenario(self, evento):
        if self.boton_volver.es_cliqueado(evento):
            return True 
        return False