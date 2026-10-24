# AI Collaboration & Debugging Log (PROMPTS.md)

### Entry 1: Environment & Dependency Setup
- **Prompt:** How to setup dependencies on Windows PowerShell.
- **Issue:** Permission denied error due to `requirements.txt` being created as a folder.
- **Fix:** Switched to direct package installation via `pip install fastapi uvicorn sqlalchemy pydantic python-multipart`.

### Entry 2: CORS Middleware Setup
- **Prompt:** Connect React frontend to FastAPI backend.
- **Issue:** Cross-Origin Request Blocked (CORS error) in browser console.
- **Fix:** Injected `CORSMiddleware` in `main.py` allowing all origins and credentials.

### Entry 3: Authorization & Duplicate Grant Bug
- **Prompt:** In step 6, even after clicking revoke, userB could still download.
- **Investigation:** Discovered that duplicate active grant rows were created on multiple grant clicks, and `.first()` only revoked one row while leaving others active.
- **Fix:** Updated `revoke_permission` to cancel all active rows and added unique permission checks.

### Entry 4: Browser Caching Bypass
- **Prompt:** Immediate revocation verification.
- **Issue:** Browser cached the successful 200 GET download response.
- **Fix:** Enforced `no-store` Cache-Control headers on both FastAPI FileResponse and frontend fetch API.

### Entry 5: Python Syntax & React Code Separation
- **Prompt:** SyntaxError on invalid characters in `main.py`.
- **Issue:** React TypeScript code was accidentally pasted into Python file.
- **Fix:** Separated `main.py` (FastAPI backend) and `frontend/src/App.tsx` (React frontend).
