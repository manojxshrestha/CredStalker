#!/usr/bin/env python3
from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size):
    # Criar imagem com gradiente
    img = Image.new('RGB', (size, size), color='white')
    draw = ImageDraw.Draw(img)

    # Criar gradiente (aproximado)
    for y in range(size):
        for x in range(size):
            r = int(102 + (118 - 102) * (x + y) / (2 * size))
            g = int(126 + (75 - 126) * (x + y) / (2 * size))
            b = int(234 + (162 - 234) * (x + y) / (2 * size))
            img.putpixel((x, y), (r, g, b))

    draw = ImageDraw.Draw(img)

    # Desenhar lupa (círculo + linha)
    center_x = int(size * 0.4)
    center_y = int(size * 0.4)
    radius = int(size * 0.2)
    thickness = max(2, int(size * 0.05))

    # Círculo da lupa
    draw.ellipse([center_x - radius, center_y - radius,
                  center_x + radius, center_y + radius],
                 outline='white', width=thickness)

    # Cabo da lupa
    handle_start_x = center_x + int(radius * 0.7)
    handle_start_y = center_y + int(radius * 0.7)
    handle_end_x = int(size * 0.7)
    handle_end_y = int(size * 0.7)
    draw.line([handle_start_x, handle_start_y, handle_end_x, handle_end_y],
              fill='white', width=thickness)

    # Desenhar ponto de exclamação (alerta)
    alert_x = int(size * 0.67)
    alert_y = int(size * 0.31)
    alert_radius = int(size * 0.14)

    # Círculo vermelho
    draw.ellipse([alert_x - alert_radius, alert_y - alert_radius,
                  alert_x + alert_radius, alert_y + alert_radius],
                 fill='#f5576c')

    # Exclamação
    try:
        font_size = int(size * 0.15)
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
    except:
        font = ImageFont.load_default()

    draw.text((alert_x, alert_y), "!", fill='white', anchor='mm', font=font)

    return img

# Criar ícones em diferentes tamanhos
sizes = [16, 48, 128]
for size in sizes:
    icon = create_icon(size)
    icon.save(f'/root/PENTEST/hardcodedExtension/icons/icon{size}.png')
    print(f'Ícone {size}x{size} criado com sucesso!')

print('Todos os ícones foram criados!')
