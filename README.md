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
