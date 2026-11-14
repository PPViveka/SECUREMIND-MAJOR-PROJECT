import os, requests
from dotenv import load_dotenv

load_dotenv()
key = os.getenv('GEMINI_API_KEY')

models_to_test = [
    'gemini-2.0-flash',
    'gemini-2.5-flash',
    'gemini-flash-latest',
    'gemma-3-4b-it'
]

payload = {"contents": [{"parts": [{"text": "Say hi."}]}]}
headers = {"Content-Type": "application/json"}

for model in models_to_test:
    res = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}", json=payload, headers=headers)
    print(f"Model: {model} => Status: {res.status_code}")
