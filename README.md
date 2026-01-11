# SOCEssentials
some summaries of SOC studies

# 1- LOGS

<h1>Fundamentos e Importância dos Logs<br></h1>
Os logs são registros históricos de eventos em sistemas, aplicações e redes. Eles funcionam como a "caixa-preta" de um sistema digital, permitindo:

Identificar atividades maliciosas e reconstruir táticas de invasores.
Resolução de problemas (Troubleshooting) técnicos e operacionais.
Conformidade (Compliance) com leis e regulamentos (como GDPR, PCI DSS e HIPAA).

<h1>Categorias e Formatos de Logs<br></h1>

Os logs podem ser originados de diversas fontes, incluindo dispositivos físicos (controlo de acesso), virtuais (roteadores, firewalls) e aplicações.


Tipos Comuns: Aplicação, Auditoria, Segurança, Servidor, Sistema, Rede, Banco de Dados e Web.

Formatos de Dados:


Estruturados: Seguem um padrão rígido (CSV, JSON, XML).




Semiestruturados: Combinam partes fixas com texto livre (Syslog, Windows Event Logs - .evtx).



Não Estruturados: Texto livre, como os logs padrão do Apache e Nginx.


<h1>Planejamento e Operações de Log<br></h1>

A configuração de logs deve ser estratégica para evitar o "ruído" (excesso de dados inúteis).



Objetivos de Configuração: Pode focar em Segurança (detecção de ameaças), Operacional (performance), Legal (conformidade) ou Debug (desenvolvimento).





Gerenciamento de Ciclo de Vida:
Retenção: Definida por categorias: Hot (acesso imediato, 3-6 meses), Warm (6 meses a 2 anos) e Cold (arquivado, 2-5 anos).
Ferramentas de automação: O rsyslog é usado para centralização e o logrotate para rotacionar, comprimir e deletar logs antigos.

<h1>Metodologia de Análise e Ferramentas<br></h1>

A análise transforma dados brutos em informações acionáveis através de processos como Normalização (padronização), Enriquecimento (adição de contexto) e Correlação (ligação entre eventos distintos).

Ferramentas de Linha de Comando (Linux): Comandos como cat, grep, awk, sed, cut, sort e uniq são essenciais para análise manual rápida.

Ferramentas Avançadas:

SIEM: Splunk e Elastic Stack (ELK) para monitoramento em tempo real e dashboards.
Análise Forense: Plaso para criação de "Super Timelines".
Padronização de Ameaças: Regras Sigma (para SIEM) e Yara (busca de padrões textuais/binários).
CyberChef: Conhecido como a "faca suíça" para decodificar e filtrar dados de logs.

<h1>Identificação de Ataques Comuns<br></h1>

Os documentos detalham assinaturas de ataques que podem ser encontradas nos logs:
SQL Injection: Consultas malformadas com termos como UNION SELECT.
XSS (Cross-Site Scripting): Presença de tags <script> em parâmetros de URL.
Path Traversal: Sequências de ../ para acessar arquivos sensíveis como /etc/passwd.
Ataques de Força Bruta: Múltiplas falhas de login em um curto período vindas de um mesmo IP.


# 1.1 - ELK

<h1>Consultas Avançadas no ELK:<br></h1> Este documento foca no uso avançado do Kibana para analisar grandes volumes de dados. Ele ensina a utilizar linguagens de consulta como KQL (simples e intuitiva) e Lucene (mais poderosa e complexa). Aborda técnicas como o uso de caracteres especiais, wildcards (* e ?), consultas aninhadas em JSON, pesquisas por intervalos, buscas difusas (fuzzy) para capturar erros de digitação e expressões regulares (regex).

<h1>Regras de Alerta Personalizadas no Wazuh:<br></h1> O guia explica como expandir a deteção de ameaças no Wazuh através de regras customizadas. O processo baseia-se em dois pilares: Decodificadores, que utilizam regex para extrair dados relevantes dos logs, e Regras, que definem condições específicas para gerar alertas. O documento detalha como testar estas regras e como a ordem de processamento (relação pai-filho) é crucial para a eficácia do sistema.

<h1>Logstash: Unidade de Processamento de Dados:<br></h1> Foca no Logstash como o motor central de coleta e transformação de dados da stack ELK. O documento descreve a estrutura fundamental de um ficheiro de configuração do Logstash, dividida em três partes: Input (receção de dados de várias fontes), Filter (normalização e enriquecimento de dados através de plugins como Grok e Mutate) e Output (envio dos dados processados para destinos como o Elasticsearch).

<h1>Slingshot (Investigação de Logs):<br></h1> Caso prático de investigação de um ataque real a um servidor web. Utilizando o Kibana, o analista deve reconstruir os passos do invasor, identificando o seu IP, as ferramentas de digitalização utilizadas (como Nmap e Gobuster), o método de acesso (brute-force com Hydra), a exfiltração de base de dados e a inserção de códigos maliciosos.
# 1.2 - SPLUNK 

# 2- Detection Engineering

# 3- Incident Response

# 4- Threat Hunting

# 5- Threat Emulation
