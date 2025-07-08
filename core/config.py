import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# File paths
MITRE_ATTACK_JSON = os.path.join(DATA_DIR, "enterprise-attack.json")
EMBEDDINGS_FILE = os.path.join(DATA_DIR, "mitre_mappings.json")

# DeepSeek API
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

# OpenAI API - URL can be set in .env, defaulting to official endpoint if not specified
OPENAI_API_URL = os.getenv("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Prompt used to extract structured threat intelligence
SYSTEM_PROMPT = """You are a cybersecurity analyst skilled in threat intelligence extraction.

Given a threat report, extract and return:
1. A list of MITRE ATT&CK techniques used:
   - technique_id
   - technique_name
   - tactic (array)
   - procedure_description
   - url
2. IOCs observed (with type: ip, domain, url, hash)
3. Threat actor names if mentioned

Output must be a JSON object with keys: techniques, iocs, threat_actor."""
