# OLD:
# from .deepseek_client import DeepSeekClient
# self.deepseek = DeepSeekClient()

# NEW:
from .openai_client import OpenAIClient
self.llm_client = OpenAIClient()