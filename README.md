TTPMapper_OAI is an AI-driven threat intelligence parser that converts unstructured reports whether from web URLs or PDF files into structured intelligence. Using a large language model (DeepSeek, OpenAI, or LM Studio), it extracts MITRE ATT&CK techniques, IOCs, threat actors, and generates contextual summaries. Results can be exported in JSON or STIX 2.1 formats for analysis or integration.

---

## Key Features

1. **MITRE ATT&CK techniques**  
   Full mapping with:
   - `technique_id`
   - `technique_name`
   - `tactics`
   - `procedure_description`
   - `url`

2. **Indicators of Compromise (IOCs)**  
   Real observed:
   - IP addresses  
   - Domains  
   - URLs (C2, malware hosting, etc.)  
   - Hashes (MD5, SHA1, SHA256)  
   - CVEs

3. **Threat actor names**  
   Extracts the actors behind the activity (e.g., `APT28`, `LockBit`, etc.)

4. **Auto-generated summary**  
   Auto-generated summaries highlighting threat context, attacker methods, and key findings from the report.

---

## Output Formats

| Format     | Description                             |
|------------|-----------------------------------------|
| `json`     | Default format with extracted structure |
| `stix21`   | STIX 2.1 Bundle (for CTI platforms)     |

---

## Supported LLM Providers

- **DeepSeek** (cloud)
- **OpenAI** (cloud, e.g., GPT-4, GPT-3.5-turbo, GPT-4o)
- **LM Studio** (local, OpenAI-compatible endpoint)

You can choose your provider by editing the relevant lines in `core/ttp_mapper.py` and setting the appropriate API key in your `.env` file.

---

## Setup

### 1. Python Environment

- Python 3.11 or newer is required.

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. API Keys & Configuration

TTPMapper uses API keys for the LLM provider.  
**All configuration is now handled via a `.env` file at the project root.**

#### a. Create your `.env` file

Copy the example file and fill in your API keys:

```bash
cp .env.example .env
# Edit .env and add your OpenAI, DeepSeek, or LM Studio keys as needed
```

Example `.env`:
```
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=your_deepseek_key
# For LM Studio, set the endpoint and (if required) key
```

#### b. Provider selection

By default, the code will use the client you instantiate in `core/ttp_mapper.py` (OpenAIClient, DeepSeekClient, LMStudioClient, etc.).  
Edit the import and initialization to switch providers.

---

## Sample Usage

```bash
# Analyze PDF threat report and get output in JSON format
python3 main.py --pdf "lockbit-report.pdf" --output json --verbose

# Analyze a web-based threat report and export as STIX 2.1
python3 main.py --url https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/ --output stix21

# Minimal command (default output is JSON)
python3 main.py --pdf "sample.pdf"
```

---

## Requirements

- Python 3.11+
- `python-dotenv` (for .env support)
- Other dependencies listed in `requirements.txt`

Install via:

```bash
pip install -r requirements.txt
```

---

## Notes

- If you are using LM Studio, ensure its local API server is running and update your `.env` and client code as needed.
- Only one LLM provider is used at a time.
- If you do not provide the required API key for your selected provider in `.env`, the app will raise an error when you run it.

---

## Credits

- **Original Author:** [@carlospolop](https://github.com/carlospolop)
- **Original Repository:** [onionadmn/TTPMapper](https://github.com/onionadmn/TTPMapper)
- **This Fork:** [TTPMapper_OAI](https://github.com/onionadmn/TTPMapper_OAI)

---

## License

This project is licensed under the GNU General Public License. For more details, please refer to the LICENSE file.
