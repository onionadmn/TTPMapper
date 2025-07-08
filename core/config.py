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

# === Core Config ===
USE_LOCAL_LLM = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"

# === Local LLM Settings ===
LOCAL_LLM_API_URL = os.getenv("LOCAL_LLM_API_URL", "http://localhost:1234/v1/chat/completions")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "llama3")

# === OpenAI Cloud Settings ===
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

# === Validation ===
if not USE_LOCAL_LLM and not OPENAI_API_KEY:
    raise EnvironmentError("Missing required OPENAI_API_KEY for OpenAI cloud access.")

# Optional: enforce local model if local mode
if USE_LOCAL_LLM and not LOCAL_LLM_MODEL:
    raise EnvironmentError("Missing LOCAL_LLM_MODEL for LM Studio local mode.")

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
