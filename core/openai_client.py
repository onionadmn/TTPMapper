import requests
from threading import Thread
from requests.exceptions import HTTPError, RequestException, Timeout

from .spinner import Spinner
from .config import (
    USE_LOCAL_LLM,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_API_URL,
    OPENAI_API_KEY,
    OPENAI_MODEL,
    OPENAI_BACKUP_MODEL,
    SYSTEM_PROMPT
)


class OpenAIClient:
    def __init__(self):
        if USE_LOCAL_LLM:
            self.api_url = LOCAL_LLM_API_URL
            self.model = LOCAL_LLM_MODEL
            self.headers = {
                "Content-Type": "application/json"
            }
        else:
            self.api_url = "https://api.openai.com/v1/chat/completions"
            self.model = OPENAI_MODEL
            self.headers = {
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            }

        self.backup_model = OPENAI_BACKUP_MODEL

    def _safe_thread_start(self, spinner, verbose=False):
        thread = Thread(target=spinner.start)
        try:
            thread.start()
        except Exception as e:
            if verbose:
                print(f"[!] Spinner failed to start: {e}")
        return thread

    def _validate_response_content(self, data, verbose=False):
        if not data or "choices" not in data or not data["choices"]:
            if verbose:
                print(f"[!] API response missing 'choices': {data}")
            return None
        message = data["choices"][0].get("message")
        if not message or not message.get("content"):
            if verbose:
                print(f"[!] API response missing 'message.content': {data}")
            return None
        return message["content"].strip()

    def _post_request(self, payload, spinner, verbose=False, fallback=False):
        try:
            response = requests.post(self.api_url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except HTTPError as http_err:
            if response.status_code == 401:
                raise Exception("[!] Unauthorized: Check your OpenAI API key.")
            if not USE_LOCAL_LLM and response.status_code == 400 and "model" in response.text and not fallback:
                if verbose:
                    print("[*] Falling back to backup model...")
                payload["model"] = self.backup_model
                return self._post_request(payload, spinner, verbose, fallback=True)
            raise Exception(f"[!] HTTP Error: {http_err}")
        except RequestException as req_err:
            raise Exception(f"[!] Request Error: {req_err}")
        except Exception as e:
            raise Exception(f"[!] Unexpected Error: {str(e)}")
        finally:
            spinner.stop()

    def query(self, report_text: str, verbose: bool = False) -> dict:
        prompt = f"Analyze the following threat report and return MITRE ATT&CK technique mappings and extracted IOCs:\n\n{report_text}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1
        }

        spinner = Spinner("[*] Analyzing threat report...")
        self._safe_thread_start(spinner, verbose)

        if verbose:
            print(f"[*] Sending request to {'LM Studio' if USE_LOCAL_LLM else 'OpenAI'} API...")

        return self._post_request(payload, spinner, verbose)

    def generate_title(self, full_text: str, verbose: bool = False) -> str:
        prompt = f"""
        Write a concise threat intelligence report title (maximum 15 words) in English based on the following content.

        The title must reflect:
        - Initial access vector (e.g., exploit, phishing)
        - Key tools or malware (e.g., Cobalt Strike, Mimikatz, ransomware)
        - Final impact (e.g., lateral movement, data encryption)

        Use a professional, CTI-style tone. Do not use quotation marks, markdown, or headings.

        Report content:
        {full_text[:8000]}
        """

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst skilled in writing concise threat report titles."},
                {"role": "user", "content": prompt.strip()}
            ],
            "temperature": 0.3
        }

        spinner = Spinner("[*] Generating report title...")
        self._safe_thread_start(spinner, verbose)

        try:
            response = self._post_request(payload, spinner, verbose)
            content = self._validate_response_content(response, verbose)
            return content or "Untitled Threat Report"
        except Exception as e:
            if verbose:
                print(f"[!] Title generation failed: {e}")
            return "Untitled Threat Report"

    def summarize(self, full_text: str, verbose: bool = False) -> str:
        prompt = f"""
        Summarize the following threat report into 1–2 sentences (maximum 1000 characters). 
        The summary must include:
        - Initial access vector (e.g., phishing, RDP, exploit)
        - Key tools or malware (e.g., Cobalt Strike, Mimikatz, ransomware)
        - Lateral movement or privilege escalation tactics
        - Final impact or objective (e.g., data exfiltration, encryption, persistence)

        Only return the summary. Do not add any heading or markdown formatting.

        Report content:
        {full_text[:8000]}
        """

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst experienced in summarizing threat intelligence reports."},
                {"role": "user", "content": prompt.strip()}
            ],
            "temperature": 0.2
        }

        spinner = Spinner("[*] Generating summary...")
        self._safe_thread_start(spinner, verbose)

        if verbose:
            print(f"[*] Sending summarization request to {'LM Studio' if USE_LOCAL_LLM else 'OpenAI'}...")

        try:
            response = self._post_request(payload, spinner, verbose)
            content = self._validate_response_content(response, verbose)
            if not content or len(content.split()) < 10:
                return "Summary not available or incomplete."
            return content
        except Exception as e:
            if verbose:
                print(f"[!] Summary generation failed: {e}")
            return "Summary not available due to error."
