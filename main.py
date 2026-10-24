import os
import uuid
import hashlib
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, DateTime, Integer
from sqlalchemy.orm import declarative_base, sessionmaker, Session

STORAGE_DIR = "./private_storage/documents"
os.makedirs(STORAGE_DIR, exist_ok=True)

DATABASE_URL = "sqlite:///./trustvault.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="TrustVault")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = Column(String, nullable=False)
    storage_path = Column(String, nullable=False)
    content_type = Column(String, nullable=False)
    owner_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    document_id = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    permission_type = Column(String, default="READ")
    revoked_at = Column(DateTime, nullable=True)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor_user_id = Column(String, nullable=False)
    document_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    result = Column(String, nullable=False)
    previous_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

class AuditService:
    @staticmethod
    def log(db: Session, actor_id: str, doc_id: Optional[str], action: str, result: str):
        last_event = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        prev_hash = last_event.event_hash if last_event else "GENESIS_HASH"
        
        now = datetime.utcnow()
        raw_string = f"{now.isoformat()}|{actor_id}|{doc_id}|{action}|{result}|{prev_hash}"
        event_hash = hashlib.sha256(raw_string.encode('utf-8')).hexdigest()
        
        entry = AuditEvent(
            timestamp=now,
            actor_user_id=actor_id,
            document_id=doc_id,
            action=action,
            result=result,
            previous_hash=prev_hash,
            event_hash=event_hash
        )
        db.add(entry)
        db.commit()

# UI DASHBOARD HTML (లైవ్ లింక్ ఓపెన్ చేయగానే కనిపించే వెబ్‌సైట్ డిజైన్)
HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>TrustVault - Secure Document Sharing Platform</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-900 text-slate-100 p-6 md:p-10 font-sans">
  <div class="max-w-5xl mx-auto space-y-6">
    
    <!-- Header -->
    <div class="flex flex-col md:flex-row justify-between items-start md:items-center bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg gap-4">
      <div>
        <h1 class="text-3xl font-bold tracking-tight text-blue-400 flex items-center gap-2">
          🛡️ TrustVault
        </h1>
        <p class="text-slate-400 text-sm mt-1">Secure Document Sharing Platform with Immediate Revocation</p>
      </div>

      <!-- User Switcher -->
      <div class="flex items-center gap-2 bg-slate-900 p-2 rounded-lg border border-slate-700">
        <span class="text-xs text-slate-400 font-medium">Current User:</span>
        <button id="btnUserA" onclick="setUser('userA')" class="px-3 py-1.5 rounded-md font-semibold text-xs transition bg-blue-600 text-white shadow">
          userA (Owner)
        </button>
        <button id="btnUserB" onclick="setUser('userB')" class="px-3 py-1.5 rounded-md font-semibold text-xs transition bg-slate-800 text-slate-300 hover:bg-slate-700">
          userB (Viewer)
        </button>
      </div>
    </div>

    <!-- Alert Message -->
    <div id="alertBox" class="hidden p-4 rounded-xl border font-medium flex justify-between items-center transition">
      <span id="alertText"></span>
      <button onclick="hideAlert()" class="text-xs opacity-75 hover:opacity-100 font-bold ml-4">Dismiss</button>
    </div>

    <!-- Upload Box -->
    <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-md">
      <h2 class="text-base font-semibold text-slate-200 mb-3">
        Upload Document <span id="uploadLabel" class="text-xs font-normal text-blue-400">(as userA)</span>
      </h2>
      <form id="uploadForm" class="flex flex-wrap gap-4 items-center">
        <input type="file" id="fileInput" class="file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700 text-xs text-slate-400 cursor-pointer" required />
        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg text-xs font-semibold transition">
          Upload Securely
        </button>
      </form>
    </div>

    <!-- Documents Vault -->
    <div class="bg-slate-800 rounded-xl border border-slate-700 shadow-md overflow-hidden">
      <div class="p-5 border-b border-slate-700 flex justify-between items-center">
        <h2 class="text-base font-semibold text-slate-200">Documents Vault</h2>
        <button onclick="loadDocs()" class="text-xs text-blue-400 hover:underline">Refresh List</button>
      </div>
      <div id="docsList" class="divide-y divide-slate-700">
        <p class="p-8 text-center text-slate-500 text-sm">Loading documents...</p>
      </div>
    </div>

  </div>

  <script>
    let currentUser = "userA";

    function setUser(user) {
      currentUser = user;
      document.getElementById("btnUserA").className = user === "userA" ? "px-3 py-1.5 rounded-md font-semibold text-xs transition bg-blue-600 text-white shadow" : "px-3 py-1.5 rounded-md font-semibold text-xs transition bg-slate-800 text-slate-300 hover:bg-slate-700";
      document.getElementById("btnUserB").className = user === "userB" ? "px-3 py-1.5 rounded-md font-semibold text-xs transition bg-purple-600 text-white shadow" : "px-3 py-1.5 rounded-md font-semibold text-xs transition bg-slate-800 text-slate-300 hover:bg-slate-700";
      document.getElementById("uploadLabel").innerText = `(as ${user})`;
      loadDocs();
    }

    function showAlert(text, type) {
      const box = document.getElementById("alertBox");
      const txt = document.getElementById("alertText");
      txt.innerText = text;
      box.className = type === "success" 
        ? "p-4 rounded-xl border font-medium flex justify-between items-center transition bg-emerald-950/70 border-emerald-500 text-emerald-200"
        : "p-4 rounded-xl border font-medium flex justify-between items-center transition bg-rose-950/70 border-rose-500 text-rose-200";
      box.classList.remove("hidden");
    }

    function hideAlert() {
      document.getElementById("alertBox").classList.add("hidden");
    }

    async function loadDocs() {
      try {
        const res = await fetch("/api/documents");
        const docs = await res.json();
        const list = document.getElementById("docsList");
        if (!docs || docs.length === 0) {
          list.innerHTML = `<p class="p-8 text-center text-slate-500 text-sm">No documents found. Upload a file above!</p>`;
          return;
        }
        list.innerHTML = docs.map(doc => `
          <div class="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-750 transition">
            <div>
              <h3 class="font-semibold text-slate-100 text-sm">📄 ${doc.filename}</h3>
              <p class="text-xs text-slate-400 mt-1">Owner: <span class="text-blue-400 font-medium">${doc.owner_id}</span> | ID: ${doc.document_id.slice(0, 8)}...</p>
            </div>
            <div class="flex flex-wrap items-center gap-3">
              <button onclick="downloadDoc('${doc.document_id}', '${doc.filename}')" class="bg-emerald-600 hover:bg-emerald-700 text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold transition">
                ⬇ Download (as ${currentUser})
              </button>
              ${currentUser === doc.owner_id ? `
                <div class="flex items-center gap-2 bg-slate-900 p-1.5 rounded-lg border border-slate-700">
                  <input type="text" id="target_${doc.document_id}" value="userB" class="bg-transparent border-0 text-xs w-16 px-1 text-slate-200 focus:outline-none" />
                  <button onclick="grantAccess('${doc.document_id}')" class="bg-blue-600 hover:bg-blue-500 text-white px-2.5 py-1 rounded text-xs font-medium transition">Grant</button>
                  <button onclick="revokeAccess('${doc.document_id}')" class="bg-rose-600 hover:bg-rose-500 text-white px-2.5 py-1 rounded text-xs font-medium transition">Revoke</button>
                </div>
              ` : ''}
            </div>
          </div>
        `).join("");
      } catch (e) {
        showAlert("Failed to load documents", "error");
      }
    }

    document.getElementById("uploadForm").onsubmit = async (e) => {
      e.preventDefault();
      const file = document.getElementById("fileInput").files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("file", file);
      try {
        const res = await fetch(`/api/documents/upload?owner_id=${currentUser}`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
          showAlert(`File uploaded successfully! ID: ${data.document_id}`, "success");
          document.getElementById("fileInput").value = "";
          loadDocs();
        } else {
          showAlert(data.detail || "Upload failed", "error");
        }
      } catch {
        showAlert("Upload request failed", "error");
      }
    };

    async function downloadDoc(docId, filename) {
      try {
        const res = await fetch(`/api/documents/${docId}/download?current_user_id=${currentUser}`, { cache: "no-store" });
        if (res.ok) {
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = filename;
          a.click();
          showAlert(`Downloaded "${filename}" successfully as ${currentUser}`, "success");
        } else {
          const err = await res.json();
          showAlert(`🚫 403 FORBIDDEN: ${err.detail}`, "error");
        }
      } catch {
        showAlert("Download failed", "error");
      }
    }

    async function grantAccess(docId) {
      const target = document.getElementById(`target_${docId}`).value;
      try {
        const res = await fetch(`/api/documents/${docId}/permissions/grant?owner_id=${currentUser}&target_user_id=${target}`, { method: "POST" });
        const data = await res.json();
        if (res.ok) {
          showAlert(data.message || `Permission GRANTED to ${target}`, "success");
        } else {
          showAlert(data.detail || "Failed to grant", "error");
        }
      } catch {
        showAlert("Grant failed", "error");
      }
    }

    async function revokeAccess(docId) {
      const target = document.getElementById(`target_${docId}`).value;
      try {
        const res = await fetch(`/api/documents/${docId}/permissions/revoke?owner_id=${currentUser}&target_user_id=${target}`, { method: "POST" });
        const data = await res.json();
        if (res.ok) {
          showAlert(data.message || `Access REVOKED for ${target} immediately`, "success");
        } else {
          showAlert(data.detail || "Failed to revoke", "error");
        }
      } catch {
        showAlert("Revoke failed", "error");
      }
    }

    loadDocs();
  </script>
</body>
</html>
"""

# లింక్ ఓపెన్ చేయగానే డాష్‌బోర్డ్ వెబ్‌సైట్ ప్రత్యక్షమవుతుంది!
@app.get("/", response_class=HTMLResponse)
def home():
    return HTML_DASHBOARD

@app.get("/api/documents")
def list_documents(db: Session = Depends(get_db)):
    docs = db.query(Document).order_by(Document.created_at.desc()).all()
    return [{"document_id": d.id, "filename": d.original_filename, "owner_id": d.owner_id} for d in docs]

@app.post("/api/documents/upload")
def upload_document(owner_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    secret_storage_name = f"{uuid.uuid4().hex}.dat"
    file_disk_path = os.path.join(STORAGE_DIR, secret_storage_name)

    with open(file_disk_path, "wb") as buffer:
        buffer.write(file.file.read())

    new_doc = Document(
        original_filename=file.filename,
        storage_path=secret_storage_name,
        content_type=file.content_type or "application/octet-stream",
        owner_id=owner_id.strip()
    )
    db.add(new_doc)
    db.commit()
    db.refresh(new_doc)

    AuditService.log(db, owner_id.strip(), new_doc.id, "UPLOAD", "ALLOWED")
    return {
        "status": "SUCCESS",
        "message": "File uploaded securely!",
        "document_id": new_doc.id,
        "owner_id": new_doc.owner_id
    }

@app.get("/api/documents/{doc_id}/download")
def download_document(doc_id: str, current_user_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id.strip()).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found!")

    user = current_user_id.strip()
    is_owner = (doc.owner_id == user)

    has_active_grant = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == user,
        DocumentPermission.revoked_at == None
    ).first() is not None

    if not is_owner and not has_active_grant:
        AuditService.log(db, user, doc.id, "DOWNLOAD", "DENIED")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=f"Access Denied: User '{user}' does not have permission."
        )

    file_disk_path = os.path.join(STORAGE_DIR, doc.storage_path)
    if not os.path.exists(file_disk_path):
        raise HTTPException(status_code=404, detail="Physical file missing from storage.")

    AuditService.log(db, user, doc.id, "DOWNLOAD", "ALLOWED")
    return FileResponse(
        path=file_disk_path, 
        filename=doc.original_filename, 
        media_type=doc.content_type,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache"
        }
    )

@app.post("/api/documents/{doc_id}/permissions/grant")
def grant_permission(doc_id: str, owner_id: str, target_user_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id.strip()).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    if doc.owner_id != owner_id.strip():
        raise HTTPException(status_code=403, detail="Only owner can grant permissions.")

    target = target_user_id.strip()
    existing = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == target,
        DocumentPermission.revoked_at == None
    ).first()

    if existing:
        return {"status": "SUCCESS", "message": f"User '{target}' already has active permission."}

    permission = DocumentPermission(document_id=doc.id, user_id=target)
    db.add(permission)
    db.commit()

    AuditService.log(db, owner_id.strip(), doc.id, f"GRANT_TO_{target}", "ALLOWED")
    return {"status": "SUCCESS", "message": f"Permission successfully granted to '{target}'!"}

@app.post("/api/documents/{doc_id}/permissions/revoke")
def revoke_permission(doc_id: str, owner_id: str, target_user_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id.strip()).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    if doc.owner_id != owner_id.strip():
        raise HTTPException(status_code=403, detail="Only owner can revoke access.")

    target = target_user_id.strip()
    active_permissions = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == target,
        DocumentPermission.revoked_at == None
    ).all()

    if active_permissions:
        now = datetime.utcnow()
        for perm in active_permissions:
            perm.revoked_at = now
        db.commit()
        AuditService.log(db, owner_id.strip(), doc.id, f"REVOKE_{target}", "ALLOWED")
        return {"status": "SUCCESS", "message": f"All access revoked for '{target}' immediately!"}

    return {"status": "NOTICE", "message": f"No active permission found for '{target}'."}
