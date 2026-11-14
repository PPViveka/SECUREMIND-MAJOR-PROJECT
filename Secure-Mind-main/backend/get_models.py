import os, requests, json
from dotenv import load_dotenv

load_dotenv()
key = os.getenv('GEMINI_API_KEY')
r = requests.get(f'https://generativelanguage.googleapis.com/v1beta/models?key={key}')
with open('models.json', 'w') as f:
    json.dump(r.json(), f, indent=2)
