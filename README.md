# PNTSTNG-SUITE

```text
                 uuuuuuu
             uu$$$$$$$$$$$uu
          uu$$$$$$$$$$$$$$$$$uu
         u$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$"   "$$$"   "$$$$$$u
       "$$$$"      u$u       $$$$"
        $$$u       u$u       u$$$
        $$$u      u$$$u      u$$$
         "$$$$uu$$$   $$$uu$$$$"
          "$$$$$$"   "$$$$$$$"
            u$$$$$$$u$$$$$$$u
             u$"$"$"$"$"$"$u
  uuu        $$u$ $ $ $ $u$$       uuu
 u$$$$        $$$$$u$u$u$$$       u$$$$
  $$$$$uu      "$$$$$$$$$"     uu$$$$$$
u$$$$$$$$$$$uu    """""    uuuu$$$$$$$$$$
$$$$"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"
 """      ""$$$$$$$$$$$uu ""$"""
           uuuu ""$$$$$$$$$$uuu
  u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$
  $$$$$$$$$$""""           ""$$$$$$$$$$$"
   "$$$$$"                      ""$$$$""
     $$$"                         $$$$"
```

> **Suite personal de scripts y herramientas para pentesting de red, reconocimiento activo/pasivo, auditoría de seguridad y ciberseguridad ofensiva en entornos 100 % controlados y autorizados.**

---

## Features

- **Banner ASCII malévolo** integrado en todos los módulos (calavera roja).
- **Menús interactivos con flechas** para selección de targets sin necesidad de tipear IPs a mano.
- **Detección automática de la subred local** y gateway por defecto.
- **Reconocimiento de red vía ARP** con resolución de vendor MAC (OUI lookup offline).
- **Fallbacks multi-herramienta**: si no hay `scapy`, usa `nmap`, `arp-scan` o ping sweep.
- **Diseño modular**: cada técnica es un script independiente bajo `recon/`, `exploit/`, `post/`, etc.
- **Colores ANSI retro-terminal** para una experiencia clásica de consola.

---

## Instalación

```bash
git clone https://github.com/samilososami/pntstng-suite.git
cd pntstng-suite

# Entorno virtual recomendado
python3 -m venv .venv
source .venv/bin/activate

# Dependencias
pip install -r requirements.txt

# Opcional: instalar herramientas de sistema para fallbacks
sudo apt update && sudo apt install -y nmap arp-scan wireshark-common
```

> **Nota:** El suite está diseñado para ejecutarse en **WSL** o **Linux nativo**. Algunos módulos que usan raw sockets requieren privilegios de root.

---

## Uso

### Reconocimiento de red (netrecon)

```bash
sudo python3 -m recon.netrecon
```

1. Aparece el **banner rojo** y la calavera.
2. El script detecta tu interfaz y subred.
3. Lanza el **ARP scan** (o fallback).
4. Muestra una **lista interactiva**:
   ```
   > 192.168.1.1    aa:bb:cc:dd:ee:ff    Router/Access Point
     192.168.1.14   aa:bb:cc:dd:ee:ff    Apple, Inc.
     192.168.1.42   aa:bb:cc:dd:ee:ff    Unknown
   ```
5. Navega con **↑ ↓**, confirma con **Enter**.
6. El script te confirma el target seleccionado.

---

## Estructura del repo

```
pntstng-suite/
├── README.md              # Este archivo
├── LICENSE                # Licencia (MIT por defecto)
├── requirements.txt       # Dependencias Python
├── assets/
│   └── skull.txt          # Banner ASCII compartido
├── recon/
│   ├── __init__.py
│   └── netrecon.py        # Descubrimiento de hosts (ARP + fallback)
├── scan/
│   └── (próximamente: port scanners)
├── wifi/
│   └── (próximamente: auditoría 802.11)
└── post/
    └── (próximamente: post-explotación)
```

---

## Disclaimer

**Este repositorio es puramente educativo y para uso en auditorías de seguridad autorizadas.**  
El autor no se hace responsable del uso indebido de estas herramientas.  

- **NO** ejecutes estos scripts en redes que no te pertenezcan o sobre las que no tengas permiso explícito por escrito.
- **NO** utilices técnicas de interferencia activa (jamming, deauth floods, DoS) fuera de laboratorios controlados.
- Cumple siempre la legislación local y las normativas de tu país sobre ciberseguridad.

> *"With great power comes great responsibility."*

---

## Roadmap

- [x] Banner ASCII + estructura base
- [x] Reconocimiento de red con menú interactivo
- [ ] Escáner de puertos multi-threaded
- [ ] Módulo de auditoría WiFi (sniffing pasivo + handshake capture)
- [ ] Brute-forcers modulares (SSH, FTP, HTTP)
- [ ] Report generator en Markdown

---

## Contribuciones

Este es un repo personal de aprendizaje, pero si encuentras bugs o tienes ideas para módulos nuevos, abre un **Issue** o un **PR**.

---

**Author:** samilososami  
**Status:** En desarrollo activo
