import json
import os
from flask import Flask, request, Response
from flask_cors import CORS
from dotenv import load_dotenv

# Import handlers directly
from src.handler import (
    repo_scan_start,
    repo_scan_status,
    repo_autofix_start,
    repo_autofix_status,
    review_code,
    copilot_chat,
    simulate,
    attack_path,
    risk_score
)

# Initialize
load_dotenv()
app = Flask(__name__)
# Enable CORS for all routes to match serverless-offline behavior
CORS(app)

def lambda_bridge(handler_fn, request):
    """
    Simulates AWS Lambda event/context bridge.
    """
    # 1. Build Event
    event = {
        'body': request.get_data().decode('utf-8'),
        'queryStringParameters': request.args.to_dict(),
        'pathParameters': {},
        'requestContext': {'http': {'method': request.method}},
        'headers': dict(request.headers)
    }
    
    # 2. Call Handler
    # Note: Using None for context as your handlers don't seem to use it
    result = handler_fn(event, None)
    
    # 3. Process Response
    status = result.get('statusCode', 200)
    body = result.get('body', '')
    headers = result.get('headers', {})
    
    return Response(
        response=body,
        status=status,
        headers=headers,
        mimetype='application/json'
    )

@app.route('/review', methods=['POST'])
def review(): return lambda_bridge(review_code, request)

@app.route('/repo-scan/start', methods=['POST'])
def scan_start(): return lambda_bridge(repo_scan_start, request)

@app.route('/repo-scan/status', methods=['GET'])
def scan_status(): return lambda_bridge(repo_scan_status, request)

@app.route('/repo-autofix/start', methods=['POST'])
def autofix_start(): return lambda_bridge(repo_autofix_start, request)

@app.route('/repo-autofix/status', methods=['GET'])
def autofix_status(): return lambda_bridge(repo_autofix_status, request)

@app.route('/copilot', methods=['POST'])
def copilot(): return lambda_bridge(copilot_chat, request)

@app.route('/simulate', methods=['POST'])
def simulate_bridge(): return lambda_bridge(simulate, request)

@app.route('/attack-path', methods=['POST'])
def attack(): return lambda_bridge(attack_path, request)

@app.route('/risk-score', methods=['POST'])
def risk(): return lambda_bridge(risk_score, request)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 6060))
    print(f"✅ SageArmor Native Dev Server (Flask) running on http://localhost:{port}")
    print(f"🚀 Bypassing serverless-offline space-in-path bugs natively.")
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
