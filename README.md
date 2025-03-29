reputationchecker is a Python tool to check if an IP address or domain is listed in various DNS-based blacklists, whitelists, and abuse lists.

### Setup

```bash
git clone https://github.com/yourusername/reputationcheck.git
cd reputationcheck
pip install -r requirements.txt

```

### Usage

Check a ip:
```bash
python reputation_checker.py 1.2.3.4
```

Check a domain:
```bash
python reputation_checker.py example.com
```

Filter results by category:
```bash
python reputation_checker.py 1.2.3.4 --category botnet
```

The tool checks against services in the following categories:

- Spam/Abuse Lists
- Botnet Detection
- Botnet Command & Control Servers
- Phishing & Fraud Lists
- Threat Intelligence Aggregators
- Tor & Anonymization Networks
- Scanner/Probe Detection
- Brute Force Detection
