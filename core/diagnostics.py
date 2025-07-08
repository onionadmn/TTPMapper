import requests
from .config import (
    USE_LOCAL_LLM,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_API_URL,
    OPENAI_API_KEY,
    OPENAI_MODEL,
    OPENAI_BACKUP_MODEL
)

def check_config():
    print("\n🔍 Configuration Check:")
    if USE_LOCAL_LLM:
        print("  ✅ Using LOCAL LLM mode (LM Studio)")
        print(f"  - Model: {LOCAL_LLM_MODEL}")
        print(f"  - API URL: {LOCAL_LLM_API_URL}")
    else:
        print("  ✅ Using OpenAI CLOUD mode")
        print(f"  - Model: {OPENAI_MODEL}")
        print(f"  - Backup Model: {OPENAI_BACKUP_MODEL}")
        if not OPENAI_API_KEY:
            print("  ❌ OPENAI_API_KEY is missing!")
            return False
    return True


def test_api_connection():
    print("\n🔌 API Connectivity Test:")

    payload = {
        "model": LOCAL_LLM_MODEL if USE_LOCAL_LLM else OPENAI_MODEL,
        "messages": [{"role": "user", "content": "Hello"}]
    }

    headers = {
        "Content-Type": "application/json"
    }

    if not USE_LOCAL_LLM:
        headers["Authorization"] = f"Bearer {OPENAI_API_KEY}"
        url = "https://api.openai.com/v1/chat/completions"
    else:
        url = LOCAL_LLM_API_URL

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        print("  ✅ API responded successfully")
        return True
    except requests.exceptions.RequestException as e:
        print(f"  ❌ Failed to connect to API: {e}")
        return False
