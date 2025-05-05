# roteiro2TechHack

## Além do PortScan, quais são as 5 ferramentas mais úteis para reconhecimento em um pentest?

1. Wapiti - Escanear aplicações web para buscar vunerabilidades como XSS, SQLi e CSRF

2. Nikto - Verificar configurações inseguras de servidores we

3. Dirb - Força bruta em arquivos / diretórios escondidos de sites

4. WhatWeb - Identifica tecnologias usadas

5. OWAS ZAP - Ferramenta de proxy de pentest automatizado

## Qual a diferença entre um scanner de portas SYN e um TCP Connect Scan?

O TCP connect scan usa uma função padrão do sistema para estabelecer a conexão. Além disso, ela faz o processo completo da conexão. Ele pode ser feito sem privilégios e por finalizar a conexão é mais facil de ser detectado por firewalls. Em comparação um scanner de portas SYN envia só o primeiro pacote e espera pela resposta. Ao invés de finalizar a conexão ele interrompe o processo. Por último, ele requer de privilégios root para enviar os pacotes.

## Como um pentester pode evitar ser detectado por sistemas de prevenção de intrusão (IPS) durante o reconhecimento?

É possivel adotar diversas tecnicas para previnir o reconhecimento pelos sistemas de prevenção durante a intrusão. Algumas das tecnicas são:
1. Reduzir a velocidade do scan (--scan-delay)
2. Fragmentar pacotes (-f)
3. Usar IPs falsos como decoy (-D)
4. Outros métodos de ocutar o IP do atacante (VPNs, proxies, Tor)

Outras tecnicas são radomizar a ordem dos alvos, utilizar scans menos agressivos e evitar padrões previsiveis. Essas tecnicas podem aumentar o tempo do scan e reduzir a precisão mas são essenciais para deixar o reconhecimento mais discreto 


# Documentação Básica

Este documento descreve as dependências, instalação e uso do script de reconhecimento e análise de segurança (roteiro2.py).

# Pré-requisitos

- Python 3.7+ instalado no sistema.

- pip para instalar pacotes Python.

# Instalação das dependências

Execute no terminal:

```
pip install python-whois dnspython requests wafw00f sslyze
```

Isso instalará as bibliotecas necessárias para todas as funcionalidades atuais.

# Estrutura do script

O arquivo principal é roteiro2.py. Ele contém as seguintes funções:

1. port_scan_workflow(): fluxo de varredura de portas (TCP/UDP).

2. whois_lookup(domain): consulta WHOIS de um domínio.

3. dns_enumeration(domain): enumeração de registros DNS.

4. geolocate_ip(ip): geolocalização via API do ipinfo.io.

5. banner_grab(ip, port): captura de banners em serviços HTTP básicos.

6. wafw00f_scan(domain): detecção de WAF com WAFW00F.

7. sslyze_scan(domain, port): análise SSL/TLS com SSLyze.


# Como executar

1. Abra um terminal.

2. Navegue até a pasta contendo roteiro2.py.

3. Execute:

```
python3 roteiro2.py
```

4. No menu, insira o número da opção desejada e forneça os parâmetros solicitados.

## Opções disponíveis

Menu Principal
```
0. Sair
1. Port Scan
2. WHOIS Lookup
3. DNS Enumeration
4. Geolocalização de IP
5. Banner Grabbing
6. WAFW00F Scan
7. SSL/TLS Analysis
```

0. Sair: encerra o programa.

1. Port Scan: pede alvo, protocolo e intervalo de portas.

2. WHOIS Lookup: pede domínio.

3. DNS Enumeration: pede domínio.

4. Geolocalização de IP: pede IP.

5. Banner Grabbing: pede IP e porta.

6. WAFW00F Scan: pede domínio.

7. SSL/TLS Analysis: pede domínio e porta SSL (p.ádrão 443).
