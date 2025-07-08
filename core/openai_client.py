import requests
from threading import Thread
from .spinner import Spinner
from .config import OPENAI_API_URL, OPENAI_API_KEY, SYSTEM_PROMPT
from requests.exceptions import HTTPError, RequestException

class OpenAIClient:
    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }

    def query(self, report_text: str, verbose: bool = False) -> dict:
        prompt = f"""Analyze the following threat report and return MITRE ATT&CK technique mappings and extracted IOCs:\n\n{report_text}"""

        payload = {
            "model": "gpt-4o",  # or "gpt-4", "gpt-3.5-turbo"
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        spinner = Spinner("[*] Analyzing with OpenAI...")
        thread = Thread(target=spinner.start)

        if verbose:
            print("[*] Sending request to OpenAI API...")

        try:
            thread.start()
            response = requests.post(OPENAI_API_URL, headers=self.headers, json=payload)
            response.raise_for_status()
            return response.json()
        except HTTPError as http_err:
            if response.status_code == 401:
                raise Exception("[!] Unauthorized: Your OpenAI API key is missing or invalid.")
            else:
                raise Exception(f"[!] OpenAI API HTTP error: {http_err}")

        except RequestException as req_err:
            raise Exception(f"[!] OpenAI API request failed: {req_err}")

        except Exception as e:
            raise Exception(f"[!] Unexpected error during OpenAI query: {str(e)}")

        finally:
            spinner.stop()

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
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst skilled in writing concise threat report titles."},
                {"role": "user", "content": prompt.strip()}
            ],
            "temperature": 0.3
        }

        spinner = Spinner("[*] Generating report title...")
        thread = Thread(target=spinner.start)

        try:
            thread.start()
            response = requests.post(OPENAI_API_URL, headers=self.headers, json=payload)
            response.raise_for_status()
            data = response.json()
            if "choices" not in data:
                if verbose:
                    print(f"[!] Unexpected response for title generation: {data}")
                return "Untitled Threat Report"
            return data['choices'][0]['message']['content'].strip() or "Untitled Threat Report"
        except Exception as e:
            if verbose:
                print(f"[!] Title generation failed: {e}")
            return "Untitled Threat Report"
        finally:
            spinner.stop()

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
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst experienced in summarizing threat intelligence reports."},
                {"role": "user", "content": prompt.strip()}
            ],
            "temperature": 0.2
        }

        spinner = Spinner("[*] Generating summary...")
        thread = Thread(target=spinner.start)

        if verbose:
            print("[*] Sending summarization request...")

        try:
            thread.start()
            response = requests.post(OPENAI_API_URL, headers=self.headers, json=payload)
            response.raise_for_status()
            data = response.json()
            if "choices" not in data:
                if verbose:
                    print(f"[!] API response did not contain 'choices': {data}")
                return "Summary not available due to unexpected API response."
            content = data['choices'][0]['message']['content']
            summary = content.strip()

            if not summary or len(summary.split()) < 10:
                if verbose:
                    print("[!] Warning: Summary too short or malformed.")
                return "Summary not available or incomplete."
            return summary

        except HTTPError as http_err:
            if response.status_code == 401:
                return "[!] Summary failed: Invalid OpenAI API key."
            return f"[!] Summary failed with HTTP error: {http_err}"

        except RequestException as req_err:
            return f"[!] Summary failed: Network/API error: {req_err}"

        except Exception as e:
            if verbose:
                print(f"[!] Exception in summarize: {e}")
            return f"[!] Summary not available due to unexpected error: {str(e)}"

        finally:
            spinner.stop()
