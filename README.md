# 🖨️ Printer Network Scanner

Um projeto desenvolvido em **Python** que realiza a **descoberta e o monitoramento de impressoras em rede**.  
Utiliza os protocolos **SNMP** e **WSD** para coletar informações como nome do dispositivo, contador de páginas, status e nível de suprimentos.

---

## 🚀 Funcionalidades

- 🔍 Varredura de rede IPv4 e IPv6  
- 🧠 Descoberta automática via **WSD (Web Services for Devices)**  
- 📡 Coleta de dados via **SNMP (Simple Network Management Protocol)**  
- ⚡ Execução **multithread** para maior desempenho  
- 📊 Exibição organizada dos resultados  

---

## 🧰 Tecnologias Utilizadas

- **Python 3**
- **pysnmp** → Coleta de dados SNMP  
- **wsdiscovery** → Descoberta de impressoras via WSD  
- **concurrent.futures** → Execução em threads paralelas  

---

## 💡 Desafios e Aprendizados

Este projeto foi um dos mais **desafiadores** que já desenvolvi.  
Trabalhar com protocolos de rede e multithreading exigiu bastante estudo e prática,  
mas o resultado foi extremamente gratificante.  

Durante o processo, aprimorei meus conhecimentos sobre:
- Comunicação em rede (TCP/IP)  
- Automação e coleta de dados remotos  
- Estrutura e desempenho de sistemas em Python  

---

## ⚙️ Como Executar

```bash
# Clone o repositório
git clone https://github.com/seuusuario/printer-network-scanner.git

# Acesse o diretório
cd printer-network-scanner

# Instale as dependências
pip install -r requirements.txt

# Execute o script
python main.py
