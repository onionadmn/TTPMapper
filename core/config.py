import os

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# File paths
MITRE_ATTACK_JSON = os.path.join(DATA_DIR, "enterprise-attack.json")
EMBEDDINGS_FILE = os.path.join(DATA_DIR, "mitre_mappings.json")

# DeepSeek API
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

try:
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
    if not DEEPSEEK_API_KEY:
        raise EnvironmentError("[!] DEEPSEEK_API_KEY not found in environment variables.")
except EnvironmentError as e:
    print(f"{e}")
    exit(1)

# Prompt used to extract structured threat intelligence
SYSTEM_PROMPT = """You are a cybersecurity analyst skilled in threat intelligence extraction.

Given a threat report, extract and return:
1. A list of MITRE ATT&CK techniques used:
  - technique_id
  - technique_name
  - procedure_description (must include observed tools, commands, CVEs or behaviors)

2. A list of real, observed Indicators of Compromise (IOCs) directly associated with the attacker’s activity.
   **Do NOT include IPs, domains, or hosts belonging to victims, internal infrastructure, or compromised systems.**
   Only include malicious infrastructure used by the threat actor (e.g., C2 servers, malware hosts, phishing domains).

   IOC types to extract:
   - IP addresses
   - Domains
   - URLs (used by malware/C2/hosting)
   - Hashes (MD5, SHA1, SHA256) of malicious files
   - CVEs (CVE IDs directly exploited or mentioned in the activity)

3. The name(s) of any identified threat actors or groups involved in the activity.

Return only a JSON object in this format:
{
  "techniques": [...],
  "iocs": {
    "ips": [...],
    "domains": [...],
    "urls": [...],
    "hashes": [...],
    "cves": [...]
  },
  "threat_actor": ["APT28", "LockBit", ...]   <-- if known or mentioned
}

Do not include any explanation or unrelated content.
"""