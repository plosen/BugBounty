# Pentest Project

🚀 **Welcome to the Pentesting Automation Project!** This tool helps you conduct security analysis of web applications using best practices and popular tools.

---

## 🔥 Features

- **Tool Availability Checks**: 🛠️ Automatically verifies the presence and functionality of tools like Amass, Nmap, Nikto, FFUF, SQLMap, Bandit, WFuzz, and BurpSuite.
- **BurpSuite Integration**: 🤖 Fully automated scanning using BurpSuite API, including progress tracking and report generation.
- **ChatGPT for Analysis**: 💡 Leverages OpenAI to generate test plans, analyze vulnerabilities, and provide remediation suggestions.
- **HTTP Testing**: 🔍 Sends GET and POST requests to analyze the behavior of target subdomains.
- **Scanning and Fuzzing**: 📂
  - Subdomain enumeration with Amass.
  - Network and application scanning with Nmap and Nikto.
  - Hidden resource discovery with FFUF and WFuzz.
  - SQL injection detection with SQLMap.
  - Python code vulnerability analysis with Bandit.
- **Flexibility**: 🕹️ Supports scanning specific directories and entire websites.
- **Logs and Reports**: 📋 All results are saved for review.

---

## 📂 Project Structure

```plaintext
├── check_tools.py       # Verifies tool availability.
├── burpsuite_api.py     # Manages BurpSuite API integration.
├── api_integration.py   # Uses OpenAI for advanced analysis.
├── tester.py            # Performs HTTP testing.
├── tools.py             # Handles scanning and fuzzing.
├── config.py            # Centralized configuration.
├── logs/                # Stores tool and vulnerability logs.
├── reports/             # Saves generated reports.
├── wordlists/           # Contains wordlists for fuzzing.
└── README.md            # Project documentation.
```

---

## 🛠️ Requirements

- **Operating System**: Linux (Kali Linux recommended).
- **Python**: Version 3.8 or higher.
- **Dependencies**:
  - `openai`
  - `requests`
  - `python-dotenv`

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ⚙️ Quick Start

### 1. Check Tool Availability
Verify tools are available:
```bash
python check_tools.py
```

### 2. Perform Scanning and Fuzzing
Run analysis on the target domain:
```bash
python tools.py --domain example.com
```

### 3. HTTP Testing
Test subdomains with HTTP requests:
```bash
python tester.py --domain example.com
```

### 4. Generate Test Plans
Use ChatGPT to create testing plans:
```bash
python api_integration.py
```

### 5. BurpSuite Integration
Automate scanning and retrieve reports:
```bash
python burpsuite_api.py --domain example.com
```

---

## 📝 Configuration

Customize `config.py` to suit your needs:

- **Default Domain**: Set the target website.
- **Tool Paths**: Define paths to Amass, Nmap, Nikto, etc.
- **Wordlists**: Add custom wordlists for fuzzing.
- **API Keys**: Configure OpenAI and BurpSuite keys.

---

## 📊 Logs and Reports

- **Logs**: Saved in the `logs/` directory (tools, vulnerabilities).
- **Reports**: Generated in `reports/` for detailed analysis.
- **Wordlists**: Pre-configured wordlists are located in `wordlists/` (e.g., SecLists, DirBuster).

---

## 🤝 Contribution

1. Fork this repository.
2. Make your changes.
3. Open a Pull Request.

For significant changes, create an issue to discuss your ideas.

---

## ⚖️ License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## ⚠️ Disclaimer

This tool is for educational purposes only. Use it only with proper authorization. Misuse may result in legal consequences.

---

🎯 **Make your pentesting efficient, fast, and automated with this tool!**
