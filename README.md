# CYMAG – Active Directory Security Analysis (SIMOC Cyber Range)

Projeto acadêmico desenvolvido no curso de Tecnologia em Segurança Cibernética – SENAI.

## Sobre o Projeto

Este repositório contém os resultados, documentações e evidências técnicas coletadas durante a análise de segurança de um ambiente Active Directory existente na plataforma SIMOC Cyber Range (Indra Brasil).

O projeto segue uma abordagem:

* Blackbox
* Defensiva
* Acadêmica
* Não destrutiva

O foco principal é realizar:

* reconhecimento de rede;
* enumeração de serviços;
* análise de Active Directory;
* identificação de superfícies de ataque;
* correlação de riscos e vulnerabilidades;
* documentação técnica.

---

## Ambiente

Infraestrutura analisada:

| Host        | Função               |
| ----------- | -------------------- |
| 10.10.100.1 | Gateway / MikroTik   |
| 10.10.100.2 | Domain Controller    |
| 10.10.100.3 | Cliente Windows      |
| 10.10.100.4 | Dispositivo IoT      |
| 10.10.100.5 | Servidor Linux       |
| 10.10.100.8 | Kali Linux (Análise) |

---

## Ferramentas Utilizadas

* Nmap
* arp-scan
* smbclient
* enum4linux
* rpcclient
* ldapsearch
* BloodHound
* CrackMapExec / NetExec
* Python3

---

## Objetivos

* Mapear ativos da rede
* Enumerar serviços SMB/LDAP/Kerberos
* Identificar configurações inseguras
* Analisar exposição de serviços
* Correlacionar achados com CVEs
* Produzir documentação técnica defensiva

---

## Estrutura do Projeto

```text
/resultados
/documentacao
/scripts
/evidencias
```

---

## Observações

Este projeto é exclusivamente acadêmico e todas as atividades foram realizadas apenas dentro do ambiente autorizado do SIMOC Cyber Range.

Nenhuma técnica destrutiva, exploit ativo ou atividade ofensiva fora do escopo educacional foi utilizada.

---

## Equipe CYMAG

* Alef Kaue
* Carla Santos
* Gustavo Lopreto
* Matheus Sousa
* Yuri Siqueira

SENAI – Segurança Cibernética
Projeto Integrador Interdisciplinar I – 2026
