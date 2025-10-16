#!/usr/bin/env python3
"""
Scanner de Impressoras em Rede com Suporte a IPv4/IPv6
Escaneia sub-redes para descobrir impressoras e coletar informações via SNMP
Versão com Interface Gráfica e Barra de Progresso
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
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Aviso: tkinter não disponível. Usando modo console.")


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
                 page_count: int = 0, open_ports: Dict[int, str] = None):
        self.ip = ip
        self.hostname = hostname
        self.model = model
        self.page_count = page_count
        self.open_ports = open_ports or {}


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


def snmp_get(ip: str, oid: str, timeout: int = SNMP_TIMEOUT) -> Optional[str]:
    """Realiza uma consulta SNMP GET para obter um valor específico"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            transport = Udp6TransportTarget((ip, 161), timeout=timeout)
        else:
            transport = UdpTransportTarget((ip, 161), timeout=timeout)
        
        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=1),
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


def snmp_get_v1(ip: str, oid: str, timeout: int = SNMP_TIMEOUT) -> Optional[str]:
    """Realiza uma consulta SNMP v1 GET (fallback)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            transport = Udp6TransportTarget((ip, 161), timeout=timeout)
        else:
            transport = UdpTransportTarget((ip, 161), timeout=timeout)
        
        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),  # SNMPv1
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


def query_printer_info(ip: str, open_ports: Dict[int, str]) -> Optional[PrinterInfo]:
    """Consulta informações da impressora via SNMP"""
    # Tenta SNMPv2c primeiro
    sysdescr = snmp_get(ip, OID_SYSDESCR)
    
    # Se falhar, tenta SNMPv1
    if sysdescr is None:
        sysdescr = snmp_get_v1(ip, OID_SYSDESCR)
    
    # Se ainda falhar, retorna info básica apenas com portas
    if sysdescr is None:
        return PrinterInfo(
            ip=ip, 
            hostname="", 
            model="Dispositivo de impressão (SNMP não disponível)", 
            page_count=0, 
            open_ports=open_ports
        )
    
    sysname = snmp_get(ip, OID_SYSNAME) or snmp_get_v1(ip, OID_SYSNAME) or ""
    page_count_str = snmp_get(ip, OID_PAGE_COUNTER) or snmp_get_v1(ip, OID_PAGE_COUNTER) or "0"
    
    try:
        page_count = int(page_count_str)
    except (ValueError, TypeError):
        page_count = 0
    
    model = sysdescr.split('\n')[0].strip() if sysdescr else "Desconhecido"
    
    return PrinterInfo(ip=ip, hostname=sysname, model=model, 
                      page_count=page_count, open_ports=open_ports)


def scan_single_host(ip_str: str) -> Tuple[str, Optional[PrinterInfo], str]:
    """Escaneia um único host em busca de impressora"""
    open_ports = scan_all_ports(ip_str)
    
    if not open_ports:
        return (ip_str, None, "no_printer_port")
    
    # Sempre tenta consultar SNMP, mas retorna info básica se falhar
    printer_info = query_printer_info(ip_str, open_ports)
    
    # Agora sempre retorna sucesso se encontrou portas de impressora
    if printer_info:
        return (ip_str, printer_info, "success")
    else:
        # Caso extremo - não deveria acontecer com a nova lógica
        return (ip_str, None, "snmp_failed")


def scan_subnet_console(subnet: str, max_workers: int = 100) -> List[PrinterInfo]:
    """Escaneia uma sub-rede (modo console com barra de progresso)"""
    printers = []
    
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        print(f"\n{'='*70}")
        print(f"Escaneando sub-rede: {subnet}")
        
        total_hosts = network.num_addresses
        if total_hosts > 1000:
            print(f"Aviso: Sub-rede grande ({total_hosts} endereços).")
            print(f"Limitando a 1000 hosts para otimização...")
            hosts = list(network.hosts())[:1000]
        else:
            hosts = list(network.hosts())
        
        print(f"Total de hosts a escanear: {len(hosts)}")
        print(f"Threads paralelas: {max_workers}")
        print(f"Portas verificadas: {', '.join(map(str, PRINTER_PORTS.keys()))}")
        print('='*70)
        
        progress = ProgressTracker(len(hosts))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_single_host, str(ip)): ip for ip in hosts}
            
            for future in as_completed(futures):
                current = progress.increment()
                percentage = progress.get_progress()
                
                # Barra de progresso
                bar_length = 40
                filled = int(bar_length * percentage / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\rProgresso: [{bar}] {percentage:.1f}% ({current}/{len(hosts)})", 
                      end='', flush=True)
                
                ip_str, printer_info, status = future.result()
                
                if status == "success" and printer_info:
                    printers.append(printer_info)
                    print()  # Nova linha
                    print(f"\n{'='*70}")
                    print("🖨️  IMPRESSORA ENCONTRADA!")
                    print(f"{'='*70}")
                    print(f"  IP:        {printer_info.ip}")
                    if printer_info.hostname:
                        print(f"  Nome:      {printer_info.hostname}")
                    print(f"  Modelo:    {printer_info.model}")
                    print(f"  Páginas:   {printer_info.page_count:,}")
                    print(f"  Portas abertas:")
                    for port, service in printer_info.open_ports.items():
                        print(f"    • {port} - {service}")
                    print('='*70)
        
        print()  # Nova linha após a barra
        
    except ValueError as e:
        print(f"\nERRO: Sub-rede inválida '{subnet}': {e}")
    
    return printers


class PrinterScannerGUI:
    """Interface gráfica para o scanner de impressoras"""
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de Impressoras em Rede")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.scanning = False
        self.printers = []
        
        self.create_widgets()
    
    def create_widgets(self):
        # Frame superior - Configurações
        config_frame = ttk.LabelFrame(self.root, text="Configurações", padding=10)
        config_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(config_frame, text="Sub-redes (CIDR):").grid(row=0, column=0, sticky="w")
        self.subnet_entry = ttk.Entry(config_frame, width=40)
        self.subnet_entry.insert(0, "192.168.1.0/24")
        self.subnet_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Threads:").grid(row=1, column=0, sticky="w")
        self.threads_spinbox = ttk.Spinbox(config_frame, from_=10, to=200, width=10)
        self.threads_spinbox.set(100)
        self.threads_spinbox.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        
        self.scan_button = ttk.Button(config_frame, text="🔍 Iniciar Scan", 
                                      command=self.start_scan)
        self.scan_button.grid(row=0, column=2, rowspan=2, padx=10)
        
        # Frame de progresso
        progress_frame = ttk.LabelFrame(self.root, text="Progresso", padding=10)
        progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill="x", pady=2)
        
        self.status_label = ttk.Label(progress_frame, text="Pronto para escanear")
        self.status_label.pack()
        
        # Frame de portas escaneadas
        ports_frame = ttk.LabelFrame(self.root, text="Portas Verificadas", padding=5)
        ports_frame.pack(fill="x", padx=10, pady=5)
        
        ports_text = ", ".join([f"{p} ({s})" for p, s in PRINTER_PORTS.items()])
        ttk.Label(ports_frame, text=ports_text, wraplength=850).pack()
        
        # Frame de resultados
        results_frame = ttk.LabelFrame(self.root, text="Resultados", padding=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                      height=20, font=("Consolas", 9))
        self.results_text.pack(fill="both", expand=True)
        
        # Tags para cores
        self.results_text.tag_config("header", foreground="blue", font=("Consolas", 10, "bold"))
        self.results_text.tag_config("success", foreground="green")
        self.results_text.tag_config("info", foreground="dark blue")
        self.results_text.tag_config("warning", foreground="orange")
    
    def log(self, message, tag=None):
        """Adiciona mensagem ao log"""
        self.results_text.insert(tk.END, message + "\n", tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_scan(self):
        """Inicia o escaneamento em uma thread separada"""
        if self.scanning:
            return
        
        subnets = self.subnet_entry.get().split()
        if not subnets:
            self.log("⚠️ Digite pelo menos uma sub-rede!", "warning")
            return
        
        self.scanning = True
        self.scan_button.config(state="disabled")
        self.results_text.delete(1.0, tk.END)
        self.printers = []
        
        threads = int(self.threads_spinbox.get())
        
        scan_thread = threading.Thread(target=self.scan_subnets, 
                                       args=(subnets, threads))
        scan_thread.daemon = True
        scan_thread.start()
    
    def scan_subnets(self, subnets, max_workers):
        """Escaneia as sub-redes"""
        start_time = time.time()
        
        self.log("="*80, "header")
        self.log("🚀 INICIANDO SCANNER DE IMPRESSORAS", "header")
        self.log("="*80, "header")
        
        for subnet in subnets:
            self.scan_single_subnet(subnet, max_workers)
        
        elapsed = time.time() - start_time
        
        self.log("\n" + "="*80, "header")
        self.log(f"✅ SCAN FINALIZADO", "header")
        self.log("="*80, "header")
        self.log(f"Total de impressoras: {len(self.printers)}", "success")
        self.log(f"Tempo total: {elapsed:.2f}s", "info")
        
        if self.printers:
            self.log("\n📋 RESUMO:", "header")
            for p in self.printers:
                self.log(f"  • {p.ip} - {p.model} ({p.page_count:,} páginas)", "info")
        
        self.scanning = False
        self.scan_button.config(state="normal")
        self.status_label.config(text="Scan concluído!")
    
    def scan_single_subnet(self, subnet, max_workers):
        """Escaneia uma única sub-rede"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            self.log(f"\n🔍 Escaneando: {subnet}", "info")
            
            total = network.num_addresses
            if total > 1000:
                self.log(f"⚠️ Rede grande ({total} hosts). Limitando a 1000.", "warning")
                hosts = list(network.hosts())[:1000]
            else:
                hosts = list(network.hosts())
            
            self.log(f"📊 Hosts: {len(hosts)} | Threads: {max_workers}", "info")
            
            progress = ProgressTracker(len(hosts))
            self.progress_bar['maximum'] = len(hosts)
            self.progress_bar['value'] = 0
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(scan_single_host, str(ip)): ip 
                          for ip in hosts}
                
                for future in as_completed(futures):
                    current = progress.increment()
                    self.progress_bar['value'] = current
                    self.status_label.config(
                        text=f"Escaneando: {current}/{len(hosts)} hosts"
                    )
                    
                    ip_str, printer_info, status = future.result()
                    
                    if status == "success" and printer_info:
                        self.printers.append(printer_info)
                        self.log("\n" + "="*80, "success")
                        self.log(f"🖨️ IMPRESSORA ENCONTRADA: {printer_info.ip}", "success")
                        self.log("="*80, "success")
                        self.log(f"  Modelo: {printer_info.model}", "info")
                        if printer_info.hostname:
                            self.log(f"  Nome: {printer_info.hostname}", "info")
                        self.log(f"  Páginas: {printer_info.page_count:,}", "info")
                        self.log("  Portas abertas:", "info")
                        for port, service in printer_info.open_ports.items():
                            self.log(f"    • {port} - {service}", "info")
        
        except ValueError as e:
            self.log(f"❌ Erro: Sub-rede inválida '{subnet}': {e}", "warning")


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='Scanner de Impressoras - IPv4/IPv6',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('subnets', nargs='*',
                       help='Sub-redes em CIDR (ex: 192.168.1.0/24)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                       help='Threads paralelas (padrão: 100)')
    parser.add_argument('--no-gui', action='store_true',
                       help='Forçar modo console')
    
    args = parser.parse_args()
    
    # Se argumentos foram passados ou GUI não disponível, usa modo console
    if args.subnets or args.no_gui or not GUI_AVAILABLE:
        if not args.subnets:
            print("Erro: Especifique pelo menos uma sub-rede")
            parser.print_help()
            sys.exit(1)
        
        print("\n🖨️  SCANNER DE IMPRESSORAS EM REDE")
        start_time = time.time()
        all_printers = []
        
        for subnet in args.subnets:
            printers = scan_subnet_console(subnet, max_workers=args.workers)
            all_printers.extend(printers)
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print(f"✅ SCAN FINALIZADO")
        print(f"{'='*70}")
        print(f"Total de impressoras: {len(all_printers)}")
        print(f"Tempo total: {elapsed:.2f}s")
        
        if all_printers:
            print("\n📋 RESUMO:")
            for p in all_printers:
                print(f"  • {p.ip} - {p.model} ({p.page_count:,} páginas)")
    else:
        # Inicia interface gráfica
        root = tk.Tk()
        app = PrinterScannerGUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()