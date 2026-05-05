#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netrecon.py
Descubrimiento de hosts en red local con menú interactivo por flechas.
Parte de pntstng-suite.

Uso:
    sudo python3 -m recon.netrecon
    sudo python3 recon/netrecon.py
"""

import os
import sys
import re
import subprocess
import time
import ipaddress

# ─── ANSI palette ──────────────────────────────────────────────
R = "\033[1;31m"       # bright red
DR = "\033[31m"        # dark red
G = "\033[1;32m"       # green
Y = "\033[1;33m"       # yellow
C = "\033[1;36m"       # cyan
W = "\033[1;37m"       # white
RST = "\033[0m"

SCRIPT_NAME = "netrecon"
MODULE_DESC = "Network Reconnaissance Scanner"


def clear():
    os.system('clear' if os.name != 'nt' else 'cls')


def banner():
    """Muestra la calavera roja y la cabecera del módulo."""
    skull_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "assets", "skull.txt"
    )
    skull = ""
    if os.path.exists(skull_path):
        with open(skull_path) as f:
            skull = f.read()
    else:
        skull = "   [ SKULL NOT FOUND ]"
    print(R + skull + RST)
    print(f"{C}         [ {W}{SCRIPT_NAME.upper()}{C} | {W}{MODULE_DESC}{C} ]{RST}")
    print(f"{DR}         Entorno controlado - Uso autorizado únicamente{RST}\n")


def check_platform():
    if sys.platform.startswith('win'):
        print(f"{Y}[!] Advertencia:{RST} Este script está diseñado para WSL/Linux.")
        print("    Ejecútalo dentro de un entorno Linux para funcionalidad completa.\n")
        sys.exit(1)


def get_key():
    """Lee una tecla incluyendo secuencias de flechas (Unix/WSL)."""
    import termios, tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            ch += sys.stdin.read(2)
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def get_local_info():
    """Devuelve (iface, subnet_cidr, gateway)."""
    try:
        route = subprocess.check_output(
            ['ip', 'route', 'show', 'default'],
            text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r'dev\s+(\S+)', route)
        iface = m.group(1) if m else None
        m_gw = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', route)
        gateway = m_gw.group(1) if m_gw else None

        if not iface:
            return None, None, None

        addr = subprocess.check_output(
            ['ip', '-o', '-f', 'inet', 'addr', 'show', iface],
            text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', addr)
        subnet = m.group(1) if m else None
        return iface, subnet, gateway
    except Exception:
        return None, None, None


def load_ouis():
    """Carga OUI desde archivos de sistema + fallback embebido."""
    ouis = {}
    paths = [
        '/usr/share/wireshark/manuf',
        '/usr/share/nmap/nmap-mac-prefixes',
        '/etc/manuf',
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            prefix = parts[0].replace(':', '').replace('-', '').replace('.', '').upper()[:6]
                            vendor = parts[1]
                            ouis[prefix] = vendor
            except Exception:
                pass

    fallback = {
        '000347': 'Apple', '001B11': 'Apple', '00A040': 'Apple',
        '041E64': 'Apple', '04D3B0': 'Apple', '080007': 'Apple',
        '0C3E9F': 'Apple', '102A6C': 'Samsung', '1866DA': 'Samsung',
        '1CBFC0': 'Samsung', '28CC01': 'Samsung', '308CFB': 'Samsung',
        '38D40B': 'Samsung', '3C5AB4': 'Google', '54A050': 'Google',
        '00155D': 'Microsoft', '0016CB': 'Sony', '001A80': 'Google',
        '001CBF': 'Dell', '001E4F': 'Asus', '0021B7': 'Intel',
        '002312': 'Cisco', '00241D': 'Hewlett-Packard', '00259E': 'Cisco',
        '00C0CA': 'Intel', '00D0B7': 'Intel', '00E018': 'Asus',
        '00E04C': 'Realtek', '00E0FC': 'TP-LINK', '020101': 'Nintendo',
        '04C5A4': 'Cisco', '080027': 'VirtualBox', '0A0027': 'VirtualBox',
        '0C8268': 'Intel', '100BA9': 'Intel', '149D99': 'Intel',
        '18D6C7': 'TP-LINK', '1C872C': 'Intel', '200BCF': 'Amazon',
        '24FD52': 'Intel', '28F10E': 'Google', '2C27D7': 'Hewlett-Packard',
        '2C4D54': 'ASRock', '2CAB00': 'Intel', '30B5C2': 'TP-LINK',
        '3495DB': 'Google', '38F9D3': 'Apple', '3C5A2D': 'Samsung',
        '3C77E6': 'Microsoft', '40A3CC': 'Intel', '44D884': 'Huawei',
        '485AB6': 'Hewlett-Packard', '4C3488': 'Intel', '4CEBB4': 'Asus',
        '50E549': 'Cisco', '548999': 'Intel', '54BF64': 'Dell',
        '5C5181': 'Intel', '6002B4': 'Wistron', '60F677': 'AzureWave',
        '640F28': 'Intel', '64E837': 'Intel', '6C2995': 'Intel',
        '74E50B': 'Intel', '74E543': 'Google', '78AC44': 'Intel',
        '78D94E': 'Amazon', '7C67A2': 'Intel', '7C7A91': 'Intel',
        '7C8BCA': 'Intel', '84A423': 'Amazon', '8C476E': 'Intel',
        '90B931': 'Intel', '94A67E': 'Intel', '98E743': 'Intel',
        '9CFC28': 'Intel', 'A036BC': 'Intel', 'A0C589': 'Intel',
        'A44E31': 'Intel', 'A4AE12': 'Intel', 'AC1F6B': 'Intel',
        'B0BE76': 'Amazon', 'B0C745': 'Intel', 'B808D7': 'Intel',
        'B88A44': 'Intel', 'BCA511': 'Intel', 'C05627': 'Intel',
        'C0D2F3': 'Samsung', 'C4346B': 'Hewlett-Packard', 'C48508': 'Intel',
        'C8B373': 'Intel', 'CC2F71': 'Intel', 'D017C2': 'Asus',
        'D0E10E': 'Intel', 'D4507A': 'Intel', 'D8CB8A': 'Intel',
        'DC5360': 'Intel', 'E036A5': 'Intel', 'E0D55E': 'Intel',
        'E8B748': 'Intel', 'EC086B': 'Intel', 'F0761C': 'Intel',
        'F0D5BF': 'Intel',
    }
    ouis.update(fallback)
    return ouis


def lookup_vendor(mac, ouis):
    if not mac or mac.startswith('???'):
        return 'Unknown'
    prefix = mac.replace(':', '').replace('-', '').upper()[:6]
    return ouis.get(prefix, 'Unknown')


def arp_scan_scapy(subnet):
    try:
        from scapy.all import srp, Ether, ARP, conf
        conf.verb = 0
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3, retry=2
        )
        hosts = []
        for _, rcv in ans:
            hosts.append({'ip': rcv.psrc, 'mac': rcv.hwsrc})
        return hosts
    except Exception as e:
        print(f"{Y}[!] Scapy falló:{RST} {e}")
        return []


def arp_scan_nmap(subnet):
    try:
        out = subprocess.check_output(
            ['nmap', '-sn', '-PR', subnet],
            text=True, stderr=subprocess.DEVNULL, timeout=60
        )
        hosts = []
        current_ip = None
        current_mac = None
        for line in out.splitlines():
            if line.startswith('Nmap scan report for'):
                if current_ip and current_mac:
                    hosts.append({'ip': current_ip, 'mac': current_mac})
                current_mac = None
                parts = line.split()
                current_ip = parts[-1].strip('()')
            elif 'MAC Address:' in line:
                parts = line.split('MAC Address:')
                if len(parts) == 2:
                    mac = parts[1].strip().split()[0]
                    current_mac = mac
        if current_ip and current_mac:
            hosts.append({'ip': current_ip, 'mac': current_mac})
        return hosts
    except Exception as e:
        print(f"{Y}[!] Nmap falló:{RST} {e}")
        return []


def ping_sweep(subnet):
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except Exception:
        return []
    if net.prefixlen > 24:
        print(f"{Y}[!] Red muy grande para ping sweep; usa nmap o scapy.{RST}")
        return []
    print(f"{C}[*] Lanzando ping sweep sobre {subnet} ...{RST}")
    procs = {}
    for ip in net.hosts():
        ip_str = str(ip)
        procs[ip_str] = subprocess.Popen(
            ['ping', '-c', '1', '-W', '1', ip_str],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    time.sleep(2.5)
    hosts = []
    for ip_str, p in procs.items():
        if p.poll() == 0:
            hosts.append({'ip': ip_str, 'mac': '???:????:???', 'vendor': 'Unknown'})
    return hosts


def discover_hosts(subnet, ouis):
    hosts = arp_scan_scapy(subnet)
    if not hosts:
        print(f"{Y}[!] Scapy no devolvió resultados, probando nmap...{RST}")
        hosts = arp_scan_nmap(subnet)
    if not hosts:
        print(f"{Y}[!] Nmap tampoco, usando ping sweep básico...{RST}")
        hosts = ping_sweep(subnet)
    for h in hosts:
        h['vendor'] = lookup_vendor(h.get('mac', ''), ouis)
    return hosts


def draw_menu(hosts, idx):
    clear()
    banner()
    print(f"{C}[+] Hosts detectados en la subred:{RST}\n")
    print(f"    {'IP':<16} {'MAC':<18} {'VENDOR / Rol':<22}")
    print(f"    {'-'*16} {'-'*18} {'-'*22}")
    for i, h in enumerate(hosts):
        cursor = f"{G} >{RST}" if i == idx else "  "
        ip = h['ip']
        mac = h.get('mac', '???:????:???')
        vendor = h.get('vendor', 'Unknown')
        line = f"{cursor} {ip:<16} {mac:<18} {Y}{vendor}{RST}"
        print(line)
    print(f"\n{DR}[↑/↓] Navegar    [Enter] Seleccionar    [Q] Salir{RST}")


def interactive_select(hosts):
    if not hosts:
        print(f"{R}[X] No se detectaron hosts.{RST}")
        return None
    idx = 0
    while True:
        draw_menu(hosts, idx)
        try:
            key = get_key()
        except Exception:
            # Fallback sin termios
            val = input("\nSelecciona índice del host: ")
            try:
                return hosts[int(val)]
            except (IndexError, ValueError):
                continue
        if key in ('\x1b[A', 'k'):
            idx = (idx - 1) % len(hosts)
        elif key in ('\x1b[B', 'j'):
            idx = (idx + 1) % len(hosts)
        elif key in ('\r', '\n', ' '):
            return hosts[idx]
        elif key.lower() == 'q':
            return None


def main():
    check_platform()
    clear()
    banner()

    iface, subnet, gateway = get_local_info()
    if not subnet:
        print(f"{R}[X] No se pudo detectar la subred local.{RST}")
        sys.exit(1)

    print(f"{C}[*] Interfaz:{RST} {iface}")
    print(f"{C}[*] Gateway:{RST}  {gateway}")
    print(f"{C}[*] Subred:{RST}   {subnet}\n")

    ouis = load_ouis()
    print(f"{C}[*] Escaneando hosts activos...{RST}\n")
    hosts = discover_hosts(subnet, ouis)

    # Asegurar que el gateway aparezca (por si ARP no lo detectó)
    if gateway:
        found = any(h['ip'] == gateway for h in hosts)
        if not found:
            try:
                out = subprocess.check_output(
                    ['ip', 'neigh', 'show', gateway],
                    text=True, stderr=subprocess.DEVNULL
                )
                mac = None
                if 'lladdr' in out:
                    parts = out.split()
                    for i, p in enumerate(parts):
                        if p == 'lladdr':
                            mac = parts[i + 1]
                            break
                hosts.insert(0, {
                    'ip': gateway,
                    'mac': mac or '???:????:???',
                    'vendor': lookup_vendor(mac or '', ouis) if mac else 'Gateway'
                })
            except Exception:
                hosts.insert(0, {'ip': gateway, 'mac': '???:????:???', 'vendor': 'Gateway'})

    target = interactive_select(hosts)
    clear()
    banner()
    if target:
        print(f"\n{G}[✓] TARGET SELECCIONADO:{RST}")
        print(f"    IP:     {W}{target['ip']}{RST}")
        print(f"    MAC:    {W}{target.get('mac', 'N/A')}{RST}")
        print(f"    VENDOR: {W}{target.get('vendor', 'Unknown')}{RST}")
        print(f"\n{DR}    Este target puede ser usado por módulos posteriores del suite.{RST}\n")
    else:
        print(f"\n{Y}[!] Cancelado por el usuario.{RST}\n")


if __name__ == '__main__':
    main()
