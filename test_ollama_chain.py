import os, json
os.environ['OLLAMA_MODEL'] = 'llama3.2:3b'
os.environ['OLLAMA_BASE_URL'] = 'http://localhost:11434'

import sys
sys.path.insert(0, 'backend')
from app.guide.llm import LLMProviderChain

chain = LLMProviderChain(provider_order=['ollama'])
res = chain.call(
    question='Say hello in three words.',
    audience='simple',
    conversation_history=[],
    db=None,
    beginner_mode=True,
)
print('LLM response:', json.dumps(res, indent=2))
