# SOCEssentials
some summaries of SOC studies

# 1- LOGS

Fundamentos e Importância dos Logs
Os logs são registros históricos de eventos em sistemas, aplicações e redes. Eles funcionam como a "caixa-preta" de um sistema digital, permitindo:



Identificar atividades maliciosas e reconstruir táticas de invasores.



Resolução de problemas (Troubleshooting) técnicos e operacionais.



Conformidade (Compliance) com leis e regulamentos (como GDPR, PCI DSS e HIPAA).

Categorias e Formatos de Logs

Os logs podem ser originados de diversas fontes, incluindo dispositivos físicos (controlo de acesso), virtuais (roteadores, firewalls) e aplicações.


Tipos Comuns: Aplicação, Auditoria, Segurança, Servidor, Sistema, Rede, Banco de Dados e Web.

Formatos de Dados:


Estruturados: Seguem um padrão rígido (CSV, JSON, XML).




Semiestruturados: Combinam partes fixas com texto livre (Syslog, Windows Event Logs - .evtx).



Não Estruturados: Texto livre, como os logs padrão do Apache e Nginx.


Planejamento e Operações de Log

A configuração de logs deve ser estratégica para evitar o "ruído" (excesso de dados inúteis).



Objetivos de Configuração: Pode focar em Segurança (detecção de ameaças), Operacional (performance), Legal (conformidade) ou Debug (desenvolvimento).





Gerenciamento de Ciclo de Vida:


Retenção: Definida por categorias: Hot (acesso imediato, 3-6 meses), Warm (6 meses a 2 anos) e Cold (arquivado, 2-5 anos).



Ferramentas de automação: O rsyslog é usado para centralização e o logrotate para rotacionar, comprimir e deletar logs antigos.

Metodologia de Análise e Ferramentas

A análise transforma dados brutos em informações acionáveis através de processos como Normalização (padronização), Enriquecimento (adição de contexto) e Correlação (ligação entre eventos distintos).





Ferramentas de Linha de Comando (Linux): Comandos como cat, grep, awk, sed, cut, sort e uniq são essenciais para análise manual rápida.



Ferramentas Avançadas:


SIEM: Splunk e Elastic Stack (ELK) para monitoramento em tempo real e dashboards.



Análise Forense: Plaso para criação de "Super Timelines".


Padronização de Ameaças: Regras Sigma (para SIEM) e Yara (busca de padrões textuais/binários).


CyberChef: Conhecido como a "faca suíça" para decodificar e filtrar dados de logs.

Identificação de Ataques Comuns
Os documentos detalham assinaturas de ataques que podem ser encontradas nos logs:


SQL Injection: Consultas malformadas com termos como UNION SELECT.



XSS (Cross-Site Scripting): Presença de tags <script> em parâmetros de URL.



Path Traversal: Sequências de ../ para acessar arquivos sensíveis como /etc/passwd.



Ataques de Força Bruta: Múltiplas falhas de login em um curto período vindas de um mesmo IP.


# 1.1 - ELK

# 1.2 - SPLUNK 

# 2- Detection Engineering

# 3- Incident Response

# 4- Threat Hunting

# 5- Threat Emulation
