import os
import uuid
import hashlib
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.responses import FileResponse
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

@app.get("/")
def home():
    return {"message": "TrustVault API is running"}

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
        media_type=doc.content_type
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