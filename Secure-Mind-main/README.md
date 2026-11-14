# SageArmor AI Security Agent

SageArmor is an autonomous AI-powered security review agent that performs deep scans on source code, identifies vulnerabilities, suggests remediations, and can automatically create Pull Requests for security fixes.

## 🚀 Key Features
- **Progressive Repo Scan**: Real-time streaming analysis of entire GitHub repositories.
- **NVIDIA Llama 3 Engine**: Powered by Meta Llama 3-8B Instruct via NVIDIA NIM.
- **Interactive Security Copilot**: Context-aware security consultations.
- **AutoFix AI**: Automated vulnerability remediation and PR generation.
- **Attack View & Breach Sim**: Visualizes attack chains and potential business impact.

## ⚙️ Setup & Configuration

### Prerequisites
- **Python 3.11+**
- **Node.js 18+**
- **NVIDIA API Key** (from integrate.api.nvidia.com)
- **GitHub Token** (for repository scanning and PR creation)

### 1. Backend Configuration
Navigate to the `backend` folder and create a `.env` file from the example:
```bash
cd backend
cp .env.example .env
```
Edit `.env` and provide:
- `NVIDIA_API_KEY`: Your NVIDIA API key (Meta Llama 3).
- `GITHUB_TOKEN`: Your GitHub personal access token (with repo scope).

### 2. Frontend Configuration
Navigate to the `frontend` folder and create a `.env` file:
```bash
cd frontend
cp .env.example .env
```
Ensure `VITE_API_BASE_URL` points to your backend (default for local dev is `http://localhost:6060`).

## 🛠️ Local Development

### Run Backend
SageArmor uses a native Flask server to ensure full compatibility with complex paths and background jobs.
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
PORT=6060 python3 dev_server.py
```

### Run Frontend
```bash
cd frontend
npm install
npm run dev
```
The application will be available at `http://localhost:5173`.

## 📦 Deployment to AWS

The backend is fully ready for deployment via the Serverless Framework.
```bash
cd backend
npm install -g serverless
serverless deploy
```
After deployment, update the `VITE_API_BASE_URL` in the frontend `.env` to your new AWS API Gateway URL.

---
**Disclaimer**: This is a security analysis tool. Always verify AI-generated fixes before applying them to production code.
