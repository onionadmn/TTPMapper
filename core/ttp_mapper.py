# OLD:
# from .deepseek_client import DeepSeekClient
# self.deepseek = DeepSeekClient()

# NEW:
from .openai_client import OpenAIClient

class TTPMapper:
    def __init__(self):
        self.llm_client = OpenAIClient()
