#!/usr/bin/env python3

"""

Scanner de Impressoras em Rede com Suporte a IPv4/IPv6

Escaneia sub-redes para descobrir impressoras e coletar informações via SNMP

Versão com Interface Gráfica Flet (Centralizada, Moderna e com Cards)

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

GUI_AVAILABLE = True

except ImportError:

GUI_AVAILABLE = False

print("Aviso: flet não disponível. Usando modo console.")

OIDs SNMP padrão

OID_SYSNAME = '1.3.6.1.2.1.1.5.0'

OID_SYSDESCR = '1.3.6.1.2.1.1.1.0'

OID_PAGE_COUNTER = '1.3.6.1.2.1.43.10.2.1.4.1.1'

Portas comuns de impressoras

PRINTER_PORTS = {

9100: "HP JetDirect",

631: "IPP (Internet Printing Protocol)",

515: "LPD (Line Printer Daemon)",

80: "HTTP (Web Interface)",

443: "HTTPS (Secure Web)",

9220: "JetDirect Tunnel"

}

class PrinterInfo:

def __init__(self, ip: str, hostname: str = "", model: str = "",

             page_count: int = 0, open_ports: Dict[int, str] = None):

    self.ip = ip

    self.hostname = hostname

    self.model = model

    self.page_count = page_count

    self.open_ports = open_ports or {}

class ProgressTracker:

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

def check_port_open(ip: str, port: int, timeout: float = 1.5) -> bool:

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

open_ports = {}

for port, service in PRINTER_PORTS.items():

    if check_port_open(ip, port, timeout=1.0):

        open_ports[port] = service

return open_ports

def snmp_get(ip: str, oid: str, timeout: int = 1.5) -> Optional[str]:

try:

    ip_obj = ipaddress.ip_address(ip)

    transport = Udp6TransportTarget((ip, 161), timeout=timeout) if isinstance(ip_obj, ipaddress.IPv6Address) else UdpTransportTarget((ip, 161), timeout=timeout)

    iterator = getCmd(SnmpEngine(), CommunityData('public', mpModel=1), transport, ContextData(), ObjectType(ObjectIdentity(oid)))

    errorIndication, errorStatus, _, varBinds = next(iterator)

    if errorIndication or errorStatus:

        return None

    for varBind in varBinds:

        return str(varBind[1])

    return None

except Exception:

    return None

def query_printer_info(ip: str, open_ports: Dict[int, str]) -> Optional[PrinterInfo]:

sysdescr = snmp_get(ip, OID_SYSDESCR)

if sysdescr is None:

    return PrinterInfo(ip=ip, model="Dispositivo de impressão (SNMP não disponível)", open_ports=open_ports)

sysname = snmp_get(ip, OID_SYSNAME) or ""

page_count_str = snmp_get(ip, OID_PAGE_COUNTER) or "0"

try:

    page_count = int(page_count_str)

except (ValueError, TypeError):

    page_count = 0

model = sysdescr.split('\n')[0].strip() if sysdescr else "Desconhecido"

return PrinterInfo(ip=ip, hostname=sysname, model=model, page_count=page_count, open_ports=open_ports)

def scan_single_host(ip_str: str) -> Tuple[str, Optional[PrinterInfo], str]:

open_ports = scan_all_ports(ip_str)

if not open_ports:

    return (ip_str, None, "no_printer_port")

printer_info = query_printer_info(ip_str, open_ports)

return (ip_str, printer_info, "success")

===============================

===== INTERFACE FLET ==========

===============================

class PrinterScannerGUI:

def __init__(self, page: ft.Page):

    self.page = page

    self.page.title = "Scanner de Impressoras em Rede"

    self.page.window_width = 950

    self.page.window_height = 750

    self.page.theme_mode = ft.ThemeMode.LIGHT

    self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    self.page.vertical_alignment = ft.MainAxisAlignment.START

    self.page.scroll = ft.ScrollMode.AUTO



    self.scanning = False

    self.printers = []

    self.results_column = ft.Column(spacing=10, alignment=ft.MainAxisAlignment.CENTER)

    self.create_widgets()



def create_widgets(self):

    self.subnet_entry = ft.TextField(label="Sub-rede (CIDR)", value="192.168.1.0/24", width=400)

    self.threads_field = ft.TextField(label="Threads", value="100", width=120, keyboard_type=ft.KeyboardType.NUMBER)

    self.scan_button = ft.ElevatedButton(

        text="🔍 Iniciar Scan",

        icon=ft.Icons.SEARCH,

        style=ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700, color=ft.Colors.WHITE),

        on_click=self.start_scan

    )



    self.progress_bar = ft.ProgressBar(value=0, width=800, height=10, color=ft.Colors.BLUE_700)

    self.status_label = ft.Text("Pronto para escanear", size=14, text_align=ft.TextAlign.CENTER)



    self.page.add(

        ft.Column(

            [

                ft.Text("🖨️ Scanner de Impressoras em Rede", size=26, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),

                ft.Divider(),

                ft.Row([self.subnet_entry, self.threads_field, self.scan_button],

                       alignment=ft.MainAxisAlignment.CENTER, spacing=15),

                ft.Divider(),

                self.progress_bar,

                self.status_label,

                ft.Divider(),

                ft.Column([self.results_column], alignment=ft.MainAxisAlignment.CENTER)

            ],

            horizontal_alignment=ft.CrossAxisAlignment.CENTER,

            spacing=15

        )

    )



def log_printer(self, printer: PrinterInfo):

    ports_text = "\n".join([f"{port}: {service}" for port, service in printer.open_ports.items()])

    card = ft.Container(

        content=ft.Column([

            ft.Text(f"IP: {printer.ip}", weight=ft.FontWeight.BOLD),

            ft.Text(f"Modelo: {printer.model}"),

            ft.Text(f"Nome: {printer.hostname}" if printer.hostname else ""),

            ft.Text(f"Páginas: {printer.page_count:,}"),

            ft.Text("Portas abertas:\n" + ports_text)

        ], spacing=3),

        padding=10,

        border_radius=10,

        bgcolor=ft.Colors.BLUE_50,

        width=700,

    )

    self.results_column.controls.append(card)

    self.page.update()



def start_scan(self, e):

    if self.scanning:

        return

    subnets = self.subnet_entry.value.split()

    if not subnets:

        self.status_label.value = "⚠️ Digite pelo menos uma sub-rede!"

        self.page.update()

        return

    self.scanning = True

    self.scan_button.disabled = True

    self.results_column.controls.clear()

    self.page.update()

    threads = int(self.threads_field.value) if self.threads_field.value.isdigit() else 100

    threading.Thread(target=self.scan_subnets, args=(subnets, threads), daemon=True).start()



def scan_subnets(self, subnets, max_workers):

    start_time = time.time()

    for subnet in subnets:

        try:

            network = ipaddress.ip_network(subnet, strict=False)

            hosts = list(network.hosts())[:1000]

            progress = ProgressTracker(len(hosts))



            with ThreadPoolExecutor(max_workers=max_workers) as executor:

                futures = {executor.submit(scan_single_host, str(ip)): ip for ip in hosts}

                for future in as_completed(futures):

                    current = progress.increment()

                    self.progress_bar.value = current / len(hosts)

                    self.status_label.value = f"Escaneando: {current}/{len(hosts)} hosts"

                    self.page.update()

                    ip_str, printer_info, status = future.result()

                    if status == "success" and printer_info:

                        self.printers.append(printer_info)

                        self.log_printer(printer_info)

        except ValueError as e:

            self.status_label.value = f"❌ Sub-rede inválida: {e}"

            self.page.update()



    elapsed = time.time() - start_time

    self.status_label.value = f"✅ Scan concluído ({elapsed:.2f}s) - {len(self.printers)} impressoras"

    self.scan_button.disabled = False

    self.scanning = False

    self.page.update()

def main_gui(page: ft.Page):

PrinterScannerGUI(page)

def main():

parser = argparse.ArgumentParser()

parser.add_argument('subnets', nargs='*')

parser.add_argument('--no-gui', action='store_true')

args = parser.parse_args()



if args.subnets or args.no_gui or not GUI_AVAILABLE:

    print("Executando em modo console.")

    sys.exit(0)

else:

    ft.app(target=main_gui)

if name == "main":

main()

