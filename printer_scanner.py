#!/usr/bin/env python3
"""
Scanner de Impressoras em Rede com Suporte a IPv4/IPv6
Interface moderna com Flet
"""

import sys
import socket
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple, Dict
import time
import threading

try:
    from pysnmp.hlapi import *
except ImportError:
    print("ERRO: A biblioteca pysnmp não está instalada.")
    print("Instale com: pip install pysnmp")
    sys.exit(1)

try:
    import flet as ft
    FLET_AVAILABLE = True
except ImportError:
    FLET_AVAILABLE = False
    print("Aviso: Flet não disponível. Instale com: pip install flet")


# OIDs SNMP padrão
OID_SYSNAME = '1.3.6.1.2.1.1.5.0'
OID_SYSDESCR = '1.3.6.1.2.1.1.1.0'
OID_PAGE_COUNTER = '1.3.6.1.2.1.43.10.2.1.4.1.1'

# Portas comuns de impressoras
PRINTER_PORTS = {
    9100: "HP JetDirect",
    631: "IPP (Internet Printing Protocol)",
    515: "LPD (Line Printer Daemon)",
    80: "HTTP (Web Interface)",
    443: "HTTPS (Secure Web)",
    9220: "JetDirect Tunnel"
}

# Community strings comuns para tentar
SNMP_COMMUNITIES = ['public', 'private', 'admin', 'snmp', 'administrator']

# Timeout para conexões
SOCKET_TIMEOUT = 1.5
SNMP_TIMEOUT = 1.5


class PrinterInfo:
    """Classe para armazenar informações da impressora"""
    def __init__(self, ip: str, hostname: str = "", model: str = "", 
                 page_count: int = 0, open_ports: Dict[int, str] = None,
                 snmp_community: str = "", snmp_version: str = ""):
        self.ip = ip
        self.hostname = hostname
        self.model = model
        self.page_count = page_count
        self.open_ports = open_ports or {}
        self.snmp_community = snmp_community
        self.snmp_version = snmp_version


class ProgressTracker:
    """Rastreador de progresso thread-safe"""
    def __init__(self, total: int):
        self.total = total
        self.current = 0
        self.lock = threading.Lock()
    
    def increment(self):
        with self.lock:
            self.current += 1
            return self.current
    
    def get_progress(self):
        with self.lock:
            if self.total == 0:
                return 0
            return (self.current / self.total) * 100


def check_port_open(ip: str, port: int, timeout: float = SOCKET_TIMEOUT) -> bool:
    """Verifica se uma porta está aberta em um host"""
    try:
        addr_info = socket.getaddrinfo(ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False
        
        family = addr_info[0][0]
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((ip, port))
        sock.close()
        
        return result == 0
    except (socket.error, socket.timeout, OSError):
        return False


def scan_all_ports(ip: str) -> Dict[int, str]:
    """Escaneia todas as portas de impressora e retorna as abertas"""
    open_ports = {}
    for port, service in PRINTER_PORTS.items():
        if check_port_open(ip, port, timeout=1.0):
            open_ports[port] = service
    return open_ports


def snmp_get_with_community(ip: str, oid: str, community: str, version: int = 1, 
                            timeout: int = SNMP_TIMEOUT) -> Optional[str]:
    """Realiza consulta SNMP com community string específica"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            transport = Udp6TransportTarget((ip, 161), timeout=timeout, retries=0)
        else:
            transport = UdpTransportTarget((ip, 161), timeout=timeout, retries=0)
        
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=version),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        if errorIndication or errorStatus:
            return None
        
        for varBind in varBinds:
            return str(varBind[1])
        
        return None
    except Exception:
        return None


def snmp_get(ip: str, oid: str, timeout: int = SNMP_TIMEOUT) -> Optional[tuple]:
    """Tenta obter valor SNMP testando múltiplas community strings e versões"""
    # Tenta SNMPv2c com cada community
    for community in SNMP_COMMUNITIES:
        result = snmp_get_with_community(ip, oid, community, version=1, timeout=timeout)
        if result:
            return (result, community, 'v2c')
    
    # Tenta SNMPv1 com cada community
    for community in SNMP_COMMUNITIES:
        result = snmp_get_with_community(ip, oid, community, version=0, timeout=timeout)
        if result:
            return (result, community, 'v1')
    
    return None


def query_printer_info(ip: str, open_ports: Dict[int, str]) -> Optional[PrinterInfo]:
    """Consulta informações da impressora via SNMP"""
    snmp_result = snmp_get(ip, OID_SYSDESCR)
    
    if snmp_result is None:
        return PrinterInfo(
            ip=ip, 
            hostname="", 
            model="⚠️ Dispositivo de rede (SNMP desabilitado ou bloqueado)", 
            page_count=0, 
            open_ports=open_ports,
            snmp_community="N/A",
            snmp_version="N/A"
        )
    
    sysdescr, community, version = snmp_result
    
    sysname_result = snmp_get_with_community(ip, OID_SYSNAME, community, 
                                             1 if version == 'v2c' else 0)
    sysname = sysname_result if sysname_result else ""
    
    page_result = snmp_get_with_community(ip, OID_PAGE_COUNTER, community,
                                          1 if version == 'v2c' else 0)
    page_count_str = page_result if page_result else "0"
    
    try:
        page_count = int(page_count_str)
    except (ValueError, TypeError):
        page_count = 0
    
    model = sysdescr.split('\n')[0].strip() if sysdescr else "Desconhecido"
    
    return PrinterInfo(
        ip=ip, 
        hostname=sysname, 
        model=model, 
        page_count=page_count, 
        open_ports=open_ports,
        snmp_community=community,
        snmp_version=version
    )


def scan_single_host(ip_str: str) -> Tuple[str, Optional[PrinterInfo], str]:
    """Escaneia um único host em busca de impressora"""
    open_ports = scan_all_ports(ip_str)
    
    if not open_ports:
        return (ip_str, None, "no_printer_port")
    
    printer_info = query_printer_info(ip_str, open_ports)
    
    if printer_info:
        return (ip_str, printer_info, "success")
    else:
        return (ip_str, None, "snmp_failed")


class PrinterScannerApp:
    """Aplicação Flet para scanner de impressoras"""
    
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "🖨️ Scanner de Impressoras"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 0
        self.page.window_width = 1200
        self.page.window_height = 800
        
        self.scanning = False
        self.printers = []
        
        # Cores
        self.colors = {
            'primary': '#0066cc',
            'success': '#28a745',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'dark': '#343a40',
            'light': '#f8f9fa',
            'bg': '#ffffff'
        }
        
        self.setup_ui()
    
    def setup_ui(self):
        """Configura a interface do usuário"""
        
        # Header
        header = ft.Container(
            content=ft.Column([
                ft.Text(
                    "🖨️ Scanner de Impressoras em Rede",
                    size=32,
                    weight=ft.FontWeight.BOLD,
                    color=ft.colors.WHITE
                ),
                ft.Text(
                    "Detecte impressoras IPv4/IPv6 e obtenha informações via SNMP",
                    size=14,
                    color=ft.colors.WHITE70
                )
            ], spacing=5),
            bgcolor=self.colors['primary'],
            padding=30,
            margin=ft.margin.only(bottom=20)
        )
        
        # Configurações
        self.subnet_field = ft.TextField(
            label="Sub-redes (CIDR)",
            hint_text="Ex: 192.168.1.0/24 10.0.0.0/24",
            value="192.168.1.0/24",
            width=400,
            border_color=self.colors['primary']
        )
        
        self.threads_field = ft.TextField(
            label="Threads",
            value="100",
            width=120,
            keyboard_type=ft.KeyboardType.NUMBER,
            border_color=self.colors['primary']
        )
        
        self.scan_button = ft.ElevatedButton(
            "🔍 Iniciar Escaneamento",
            on_click=self.start_scan,
            bgcolor=self.colors['primary'],
            color=ft.colors.WHITE,
            height=50,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
            )
        )
        
        config_card = ft.Container(
            content=ft.Column([
                ft.Text("⚙️ Configurações", size=18, weight=ft.FontWeight.BOLD),
                ft.Row([
                    self.subnet_field,
                    self.threads_field,
                    self.scan_button
                ], spacing=15, alignment=ft.MainAxisAlignment.START)
            ], spacing=15),
            bgcolor=ft.colors.WHITE,
            padding=20,
            border_radius=10,
            border=ft.border.all(1, ft.colors.GREY_300)
        )
        
        # Progresso
        self.progress_bar = ft.ProgressBar(
            width=float('inf'),
            height=8,
            color=self.colors['primary'],
            bgcolor=ft.colors.GREY_300
        )
        
        self.status_text = ft.Text(
            "✓ Pronto para escanear",
            size=14,
            color=self.colors['success'],
            weight=ft.FontWeight.BOLD
        )
        
        self.stats_text = ft.Text(
            "",
            size=12,
            color=ft.colors.GREY_700
        )
        
        progress_card = ft.Container(
            content=ft.Column([
                ft.Text("📊 Progresso", size=18, weight=ft.FontWeight.BOLD),
                self.progress_bar,
                ft.Row([
                    self.status_text,
                    self.stats_text
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
            ], spacing=10),
            bgcolor=ft.colors.WHITE,
            padding=20,
            border_radius=10,
            border=ft.border.all(1, ft.colors.GREY_300)
        )
        
        # Portas verificadas
        port_chips = []
        for port, service in PRINTER_PORTS.items():
            port_chips.append(
                ft.Container(
                    content=ft.Row([
                        ft.Text(f":{port}", weight=ft.FontWeight.BOLD, size=12),
                        ft.Text(service, size=11, color=ft.colors.GREY_700)
                    ], spacing=5),
                    bgcolor=ft.colors.BLUE_50,
                    padding=ft.padding.symmetric(horizontal=12, vertical=6),
                    border_radius=20
                )
            )
        
        ports_card = ft.Container(
            content=ft.Column([
                ft.Text("🔌 Portas Verificadas", size=18, weight=ft.FontWeight.BOLD),
                ft.Row(port_chips, wrap=True, spacing=8)
            ], spacing=15),
            bgcolor=ft.colors.WHITE,
            padding=20,
            border_radius=10,
            border=ft.border.all(1, ft.colors.GREY_300)
        )
        
        # Resultados
        self.results_column = ft.Column(
            [],
            spacing=10,
            scroll=ft.ScrollMode.AUTO,
            expand=True
        )
        
        results_card = ft.Container(
            content=ft.Column([
                ft.Text("📋 Impressoras Encontradas", size=18, weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=self.results_column,
                    bgcolor=ft.colors.GREY_50,
                    padding=15,
                    border_radius=8,
                    expand=True
                )
            ], spacing=15, expand=True),
            bgcolor=ft.colors.WHITE,
            padding=20,
            border_radius=10,
            border=ft.border.all(1, ft.colors.GREY_300),
            expand=True
        )
        
        # Layout principal
        main_content = ft.Container(
            content=ft.Column([
                header,
                ft.Container(
                    content=ft.Column([
                        config_card,
                        progress_card,
                        ports_card,
                        results_card
                    ], spacing=15, expand=True),
                    padding=20,
                    expand=True
                )
            ], spacing=0, expand=True),
            bgcolor=self.colors['light'],
            expand=True
        )
        
        self.page.add(main_content)
    
    def add_log(self, message: str, color: str = None):
        """Adiciona mensagem ao log"""
        log_text = ft.Text(
            message,
            size=13,
            color=color or ft.colors.BLACK87,
            font_family="Consolas"
        )
        self.results_column.controls.append(log_text)
        self.page.update()
    
    def add_printer_card(self, printer: PrinterInfo):
        """Adiciona card de impressora encontrada"""
        
        # Portas abertas
        port_badges = []
        for port, service in printer.open_ports.items():
            port_badges.append(
                ft.Container(
                    content=ft.Text(f":{port} - {service}", size=11),
                    bgcolor=ft.colors.GREEN_50,
                    padding=ft.padding.symmetric(horizontal=8, vertical=4),
                    border_radius=5
                )
            )
        
        # Card da impressora
        printer_card = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.icons.PRINT, color=self.colors['success'], size=30),
                    ft.Column([
                        ft.Text(printer.ip, size=18, weight=ft.FontWeight.BOLD, color=self.colors['success']),
                        ft.Text(printer.model, size=14, color=ft.colors.GREY_700)
                    ], spacing=2)
                ], spacing=15),
                ft.Divider(height=1),
                ft.Column([
                    ft.Row([
                        ft.Icon(ft.icons.LABEL, size=16, color=ft.colors.GREY_600),
                        ft.Text(f"Nome: {printer.hostname or 'N/A'}", size=13)
                    ], spacing=5) if printer.hostname else ft.Container(),
                    ft.Row([
                        ft.Icon(ft.icons.DESCRIPTION, size=16, color=ft.colors.GREY_600),
                        ft.Text(f"Páginas: {printer.page_count:,}", size=13, weight=ft.FontWeight.BOLD)
                    ], spacing=5),
                    ft.Row([
                        ft.Icon(ft.icons.SECURITY, size=16, color=ft.colors.GREY_600),
                        ft.Text(f"SNMP: {printer.snmp_version} (community: '{printer.snmp_community}')", size=13)
                    ], spacing=5) if printer.snmp_community != "N/A" else ft.Container(),
                    ft.Column([
                        ft.Row([
                            ft.Icon(ft.icons.CABLE, size=16, color=ft.colors.GREY_600),
                            ft.Text("Portas abertas:", size=13, weight=ft.FontWeight.BOLD)
                        ], spacing=5),
                        ft.Row(port_badges, wrap=True, spacing=5)
                    ], spacing=5)
                ], spacing=8)
            ], spacing=15),
            bgcolor=ft.colors.WHITE,
            padding=20,
            border_radius=10,
            border=ft.border.all(2, self.colors['success']),
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=10,
                color=ft.colors.with_opacity(0.1, ft.colors.BLACK),
            )
        )
        
        self.results_column.controls.append(printer_card)
        self.page.update()
    
    def update_status(self, message: str, icon: str = "ℹ", color: str = None):
        """Atualiza status"""
        self.status_text.value = f"{icon} {message}"
        self.status_text.color = color or ft.colors.GREY_700
        self.page.update()
    
    def start_scan(self, e):
        """Inicia o escaneamento"""
        if self.scanning:
            return
        
        subnets = self.subnet_field.value.split()
        if not subnets:
            self.update_status("Digite pelo menos uma sub-rede!", "⚠", self.colors['warning'])
            return
        
        self.scanning = True
        self.scan_button.disabled = True
        self.results_column.controls.clear()
        self.printers = []
        self.page.update()
        
        threads = int(self.threads_field.value)
        
        self.update_status("Iniciando escaneamento...", "⟳", self.colors['primary'])
        
        scan_thread = threading.Thread(target=self.scan_subnets, args=(subnets, threads))
        scan_thread.daemon = True
        scan_thread.start()
    
    def scan_subnets(self, subnets, max_workers):
        """Escaneia sub-redes"""
        start_time = time.time()
        
        self.add_log("═" * 80, ft.colors.BLUE_700)
        self.add_log("🚀 SCANNER DE IMPRESSORAS INICIADO", ft.colors.BLUE_700)
        self.add_log("═" * 80, ft.colors.BLUE_700)
        self.add_log("")
        
        for subnet in subnets:
            self.scan_single_subnet(subnet, max_workers)
        
        elapsed = time.time() - start_time
        
        self.add_log("")
        self.add_log("═" * 80, ft.colors.GREEN_700)
        self.add_log("✅ ESCANEAMENTO CONCLUÍDO", ft.colors.GREEN_700)
        self.add_log("═" * 80, ft.colors.GREEN_700)
        self.add_log(f"📊 Impressoras encontradas: {len(self.printers)}", ft.colors.BLACK87)
        self.add_log(f"⏱️  Tempo de execução: {elapsed:.2f}s", ft.colors.BLACK87)
        
        self.scanning = False
        self.scan_button.disabled = False
        self.update_status("Escaneamento concluído!", "✓", self.colors['success'])
        self.stats_text.value = f"{len(self.printers)} impressora(s) encontrada(s)"
        self.page.update()
    
    def scan_single_subnet(self, subnet, max_workers):
        """Escaneia uma única sub-rede"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            self.add_log(f"🔍 Escaneando: {subnet}", ft.colors.BLUE_600)
            
            total = network.num_addresses
            if total > 1000:
                self.add_log(f"⚠️  Rede grande ({total:,} hosts). Limitando a 1000.", self.colors['warning'])
                hosts = list(network.hosts())[:1000]
            else:
                hosts = list(network.hosts())
            
            self.add_log(f"📊 Total de hosts: {len(hosts):,}", ft.colors.GREY_700)
            self.add_log("")
            
            progress = ProgressTracker(len(hosts))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(scan_single_host, str(ip)): ip for ip in hosts}
                
                for future in as_completed(futures):
                    current = progress.increment()
                    percentage = (current / len(hosts))
                    
                    self.progress_bar.value = percentage
                    self.update_status(
                        f"Escaneando: {current}/{len(hosts)} hosts ({percentage*100:.1f}%)",
                        "⟳",
                        self.colors['primary']
                    )
                    self.stats_text.value =  f"{len(self.printers)} encontrada(s) • {current}/{len(hosts)}"
                    self.page.update()
                    
                    ip_str, printer_info, status = future.result()
                    
                    if status == "success" and printer_info:
                        self.printers.append(printer_info)
                        self.add_printer_card(printer_info)
            
            self.add_log("")
            self.add_log(f"✓ Sub-rede {subnet} concluída\n", ft.colors.GREEN_600)
        
        except ValueError as e:
            self.add_log(f"❌ Erro: {e}", self.colors['danger'])


def main_gui():
    """Inicia a aplicação Flet"""
    def start_app(page: ft.Page):
        app = PrinterScannerApp(page)
    
    ft.app(target=start_app)


if __name__ == "__main__":
    if not FLET_AVAILABLE:
        print("Erro: Flet não está instalado.")
        print("Instale com: pip install flet")
        sys.exit(1)
    
    main_gui()