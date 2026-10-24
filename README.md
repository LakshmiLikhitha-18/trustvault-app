# TrustVault — Secure Document Sharing Platform

TrustVault is a secure document-sharing platform built around one strict principle:
> A document must never be readable, downloadable, or accessible unless the server verifies active permissions at the exact millisecond of the request.

## Tech Stack
- **Backend:** Python (FastAPI, SQLAlchemy, SQLite/PostgreSQL)
- **Frontend:** React, TypeScript, Tailwind CSS
- **Security Engine:** SHA-256 Tamper-evident Audit Trail, Dynamic Object-Level Authorization, Immediate Revocation, Private Storage Abstraction

## How to Run Locally

### 1. Backend Server
```bash
# In project root
python -m venv venv
.\venv\Scripts\activate
pip install fastapi uvicorn sqlalchemy pydantic python-multipart
uvicorn main:app --reload