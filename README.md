CYMAG – Continuous Automated Red Teaming (SIMOC Cyber Range)

Projeto académico desenvolvido no curso de Tecnologia em Segurança Cibernética – SENAI / Faculdade de Tecnologia Paulo Antonio Skaf.

Sobre o Projeto

Este repositório contém o código-fonte, resultados e documentações do CYMAG, um protótipo de SaaS focado em testes contínuos de segurança (CART). O projeto foi desenvolvido com base na análise de um ambiente corporativo simulado na plataforma SIMOC Cyber Range (Indra Brasil).

A nossa solução evoluiu de testes manuais para um fluxo automatizado que utiliza Inteligência Artificial para não apenas encontrar vulnerabilidades, mas também traduzir riscos técnicos (como SQL Injection e falhas OT) em impacto financeiro e operacional para executivos.

O projeto segue as premissas de uma abordagem:

Blackbox

Automação de Red Team (CART)

Integração com IA (LLM via Function Calling)

Não destrutiva e com foco educacional

Ambiente Analisado (Laboratório SIMOC)

A infraestrutura alvo consistia numa rede /24 contendo sistemas Windows (Active Directory) e serviços OT/IoT. A equipa operou a partir de 5 máquinas de análise simultâneas.

IP / Host

Função no Ambiente

10.10.100.1

Gateway / Roteador de Borda

10.10.100.2

Domain Controller (Windows Server / Active Directory)

10.10.100.3

Host Windows Cliente (RPC)

10.10.100.100

Servidor Principal (Web, Banco de Dados, Node-RED OT e MQTT)

10.10.100.4 a .8

Máquinas de Análise / Atacantes (Kali Linux - Equipa CYMAG)

Ferramentas e Tecnologias Utilizadas

Motor de Varredura e Scripts:

Python3 (Motor Agente)

Nmap & arp-scan (Discovery)

CrackMapExec / Impacket (Enumeração SMB/RPC e NTLM Relay)

SQLMap (Validação de injeção em base de dados)

Bibliotecas: requests, paho-mqtt, python-nmap

Inteligência Artificial e Frontend:

Integração com IA (Groq API / Modelos LLM)

HTML5/CSS3 e JavaScript (Dashboard Web SaaS Master-Detail)

Objetivos e Resultados

Mapeamento silencioso de ativos na rede interna.

Enumeração de portas e serviços críticos (SMB, RPC, HTTP, Node-RED, MQTT).

Identificação de Cadeias de Ataque (Attack Paths), incluindo a transição da rede Web para a planta industrial (OT).

Desenvolvimento de um Agente Python Local que envia logs estruturados (JSON).

Criação de um Painel de Triagem Web (SaaS) com Role-Based Access Control (RBAC), separando a visão técnica (SOC) da visão de negócios (C-Level).

Estrutura do Repositório

/F08_Web_100       # Evidências e outputs brutos da exploração do alvo .100
/F09_Automacao     # Scripts do Agente CYMAG (Python) e payloads (JSON/JS)
/relatorios        # Dashboards gerados e exportações em PDF


Observações Legais e Éticas

Este projeto é estritamente académico. Todas as atividades, automações e varreduras foram realizadas exclusivamente dentro do ambiente autorizado e isolado do SIMOC Cyber Range.

Nenhuma técnica destrutiva, exploit ativo que comprometa a disponibilidade dos serviços reais, ou atividade ofensiva fora do escopo educacional foi utilizada no desenvolvimento deste projeto.

Equipa CYMAG

Alef Kaue

Carla Santos

Gustavo Lopreto

Matheus Sousa

Yuri Siqueira

Projeto Integrador Interdisciplinar I – 2026
