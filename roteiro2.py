import socket
import ipaddress
import errno
import whois
import dns.resolver
import requests
import subprocess

# PortScan TCP/UDP
def get_tcp_port_status(result):
    if result == 0:
        return "Aberta"
    elif result == errno.ECONNREFUSED:
        return "Fechada (RST)"
    elif result == errno.ETIMEDOUT:
        return "Filtrada (TIMEOUT)"
    else:
        return f"Indeterminado (Código: {result})"

def scan_tcp_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.05)
    result = sock.connect_ex((target, port))
    status = get_tcp_port_status(result)
    if result == 0:
        try:
            service = socket.getservbyport(port)
        except Exception:
            service = "Desconhecido"
        print(f"Porta {port} (TCP): {status} - Serviço: {service}")
    else:
        print(f"Porta {port} (TCP): {status}")
    sock.close()

def scan_udp_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.sendto(b'', (target, port))
        data, addr = sock.recvfrom(1024)
        status = "Aberta"
    except socket.timeout:
        status = "Aberta/Filtrada (sem resposta)"
    except socket.error as e:
        if e.errno == errno.ECONNREFUSED:
            status = "Fechada (ICMP Port Unreachable)"
        else:
            status = f"Erro: {e}"
    finally:
        sock.close()
    try:
        service = socket.getservbyport(port, 'udp')
    except Exception:
        service = "Desconhecido"
    print(f"Porta {port} (UDP): {status} - Serviço: {service}")

def scan_host(target, start_port, end_port, protocol):
    print(f"\nEscaneando {target} de {start_port} até {end_port} usando {protocol.upper()}...")
    for port in range(start_port, end_port + 1):
        if protocol.lower() == 'tcp':
            scan_tcp_port(target, port)
        elif protocol.lower() == 'udp':
            scan_udp_port(target, port)
        else:
            print("Protocolo inválido! Utilize 'tcp' ou 'udp'.")

# WHOIS Lookup
def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        print("\nWHOIS Lookup")
        print(f"Domínio: {domain}")
        print(f"Registrado por: {info.get('org', 'Desconhecido')}")
        print(f"Data de criação: {info.get('creation_date', 'Desconhecido')}")
        print(f"Data de expiração: {info.get('expiration_date', 'Desconhecido')}")
        print(f"Servidores DNS: {info.get('name_servers', 'Desconhecido')}")
    except Exception as e:
        print(f"Erro ao realizar WHOIS: {e}")

# DNS Enumeration
def dns_enumeration(domain):
    print("\nDNS Enumeration")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=3)
            print(f"\n{rtype} Records:")
            for rdata in answers:
                print(f"- {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            print(f"\n{rtype} Records: Nenhuma resposta.")
        except dns.resolver.NXDOMAIN:
            print("\nDomínio não encontrado.")
            break
        except dns.exception.Timeout:
            print(f"\n{rtype} Records: Timeout.")
        except Exception as e:
            print(f"\nErro ao buscar {rtype} Records: {e}")

# Geolocalização de IP
def geolocate_ip(ip):
    print("\nGeolocalização de IP")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        print(f"IP: {ip}")
        print(f"País: {data.get('country', 'Desconhecido')}")
        print(f"Cidade: {data.get('city', 'Desconhecido')}")
        print(f"Org: {data.get('org', 'Desconhecido')}")
        print(f"Região: {data.get('region', 'Desconhecido')}")
        print(f"Localização: {data.get('loc', 'Desconhecido')}")
    except Exception as e:
        print(f"Erro ao obter localização do IP: {e}")

# Banner Grabbing
def banner_grab(ip, port):
    print(f"\nBanner Grabbing {ip}:{port}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
            banner = s.recv(1024).decode(errors="ignore")
            print(f"Resposta do serviço:\n{banner}")
    except Exception as e:
        print(f"Erro ao conectar: {e}")

# WAFW00F Scan
def wafw00f_scan(domain):
    print(f"\nWAFW00F para {domain}")
    try:
        result = subprocess.run(
            ['wafw00f', domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(result.stdout)
        if result.stderr:
            print("⚠️ Erros:", result.stderr)
    except FileNotFoundError:
        print("Erro: wafw00f não encontrado. Instale com `pip install wafw00f`.")
    except Exception as e:
        print(f"Erro ao executar WAFW00F: {e}")

# SSL/TLS Analysis (SSLyze)
def sslyze_scan(domain, port):
    target = f"{domain}:{port}"
    print(f"\nSSLyze {target}")
    try:
        result = subprocess.run(
            ['sslyze', '--certinfo', '--heartbleed', '--compression', target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(result.stdout)
        # filtra warnings de depreciação
        erros = [
            linha for linha in result.stderr.splitlines()
            if 'CryptographyDeprecationWarning' not in linha
        ]
        if erros:
            print("⚠️ Erros:", "\n".join(erros))
    except FileNotFoundError:
        print("Erro: sslyze não encontrado. Instale com `pip install sslyze`.")
    except Exception as e:
        print(f"Erro ao executar SSLyze: {e}")

def port_scan_workflow():
    target = input('Alvo (IP, domínio ou rede): ').strip()
    proto = input('Protocolo (tcp/udp): ').strip().lower()
    intervalo = input('Intervalo de portas (ex: 1-1000): ').strip()
    try:
        start, end = map(int, intervalo.split('-'))
    except:
        print('Intervalo inválido!')
        return
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts())
    except ValueError:
        hosts = [target]
    for h in hosts:
        print(f'\nEscaneando {h}')
        scan_host(str(h), start, end, proto)

def main():
    options = {
        '0': ('Sair', lambda: exit(0)),
        '1': ('Port Scan', port_scan_workflow),
        '2': ('WHOIS Lookup', lambda: whois_lookup(input('Domínio: ').strip())),
        '3': ('DNS Enumeration', lambda: dns_enumeration(input('Domínio: ').strip())),
        '4': ('Geolocalização de IP', lambda: geolocate_ip(input('IP: ').strip())),
        '5': ('Banner Grabbing', lambda: banner_grab(
            input('IP: ').strip(),
            int(input('Porta: ').strip()) )),
        '6': ('WAFW00F Scan', lambda: wafw00f_scan(input('Domínio: ').strip())),
        '7': ('SSL/TLS Analysis', lambda: sslyze_scan(
            input('Domínio: ').strip(),
            int(input('Porta SSL (padrão 443): ').strip() or 443) )),
    }
    while True:
        print('\nMenu Principal')
        for key, (desc, _) in options.items():
            print(f'{key}. {desc}')
        choice = input('Escolha: ').strip()
        action = options.get(choice)
        if action:
            action[1]()
        else:
            print('Opção inválida!')

if __name__ == '__main__':
    main()