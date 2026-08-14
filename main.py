"""
SuperAdmin Security Gateway - single-file FastAPI server
Designed for Railway + PostgreSQL + Firebase Realtime Database.

IMPORTANT:
- This server is a gateway. Legitimate User/Admin app Firebase operations must
  go through this server if you want the server to enforce authorization.
- Do NOT put Firebase service-account credentials in an APK.
- Direct Firebase traffic cannot be intercepted by this Python process.
  To prevent direct client access, configure Firebase Rules to deny clients and
  let this server use the Firebase Admin SDK.
- Set all secrets through Railway environment variables.

Required environment variables:
  DATABASE_URL=postgresql://...
  SUPERADMIN_USERNAME=admin
  SUPERADMIN_PASSWORD=change-this
  JWT_SECRET=long-random-secret
  FIREBASE_CREDENTIALS_JSON={"type":"service_account",...}   # optional until
                                                            # an app is added

Optional:
  PORT=8000
  TOKEN_EXPIRE_MINUTES=1440

Install:
  pip install fastapi uvicorn[standard] sqlalchemy psycopg[binary] PyJWT
              python-multipart firebase-admin

Run:
  uvicorn main:app --host 0.0.0.0 --port $PORT

Railway:
  Railway supplies PORT automatically.
"""

import os
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text, Boolean,
    ForeignKey, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

try:
    import firebase_admin
    from firebase_admin import credentials, db as firebase_db
    FIREBASE_AVAILABLE = True
except Exception:
    FIREBASE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SUPERADMIN_USERNAME = os.getenv("SUPERADMIN_USERNAME", "admin")
SUPERADMIN_PASSWORD = os.getenv("SUPERADMIN_PASSWORD", "change-this")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(48))
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "1440"))
PORT = int(os.getenv("PORT", "8000"))

if not DATABASE_URL:
    # Useful for local development only. Railway should use DATABASE_URL.
    DATABASE_URL = "sqlite:///./superadmin_local.db"

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------

class AppProject(Base):
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True)
    app_name = Column(String(150), nullable=False)
    app_key = Column(String(100), unique=True, nullable=False, index=True)
    firebase_project_id = Column(String(200), nullable=False)
    firebase_database_url = Column(String(500), nullable=False)
    firebase_credentials_json = Column(Text, nullable=True)
    status = Column(String(30), default="ACTIVE", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    requests = relationship("AdminRequest", back_populates="app", cascade="all, delete-orphan")
    alerts = relationship("SecurityAlert", back_populates="app", cascade="all, delete-orphan")


class AdminRequest(Base):
    __tablename__ = "admin_requests"

    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=False, index=True)
    device_name = Column(String(200), nullable=False)
    device_id = Column(String(300), nullable=False, index=True)
    battery = Column(String(30), nullable=True)
    ip_address = Column(String(100), nullable=True)
    request_status = Column(String(30), default="PENDING", nullable=False, index=True)
    approved_days = Column(Integer, nullable=True)
    approved_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    app = relationship("AppProject", back_populates="requests")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=True, index=True)
    alert_type = Column(String(120), nullable=False)
    device_name = Column(String(200), nullable=True)
    ip_address = Column(String(100), nullable=True)
    reason = Column(Text, nullable=True)
    status = Column(String(30), default="BLOCKED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    app = relationship("AppProject", back_populates="alerts")


class AppCredential(Base):
    __tablename__ = "app_credentials"

    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=False, index=True)
    client_type = Column(String(30), nullable=False)  # ADMIN / USER
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    device_id = Column(String(300), nullable=True)
    status = Column(String(30), default="ACTIVE", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)


Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# App / auth helpers
# ---------------------------------------------------------------------------

app = FastAPI(title="SuperAdmin Security Gateway", version="1.0.0")
bearer = HTTPBearer(auto_error=False)


def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def now():
    return datetime.now(timezone.utc)


def make_jwt(subject: str):
    payload = {
        "sub": subject,
        "exp": now() + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_superadmin(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(bearer),
):
    token = creds.credentials if creds else request.cookies.get("sa_token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = verify_jwt(token)
    if payload.get("sub") != "superadmin":
        raise HTTPException(status_code=403, detail="SuperAdmin only")
    return payload


def hash_token(value: str):
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()


def create_security_alert(
    session: Session,
    app_id: Optional[int],
    alert_type: str,
    device_name: Optional[str],
    ip_address: Optional[str],
    reason: str,
):
    alert = SecurityAlert(
        app_id=app_id,
        alert_type=alert_type,
        device_name=device_name,
        ip_address=ip_address,
        reason=reason,
        status="BLOCKED",
    )
    session.add(alert)
    session.commit()
    return alert


# ---------------------------------------------------------------------------
# Firebase helpers
# ---------------------------------------------------------------------------

_firebase_apps = {}


def firebase_for(project: AppProject):
    """
    Initialize one Firebase Admin SDK app per configured project.
    Credentials are stored server-side in PostgreSQL in this prototype.
    For production, consider moving credentials to a dedicated secret store.
    """
    if not FIREBASE_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="firebase-admin is not installed on the server"
        )

    if project.id in _firebase_apps:
        return _firebase_apps[project.id]

    if not project.firebase_credentials_json:
        raise HTTPException(status_code=400, detail="Firebase credentials not configured")

    try:
        cred_data = json.loads(project.firebase_credentials_json)
        cred = credentials.Certificate(cred_data)
        fb_app = firebase_admin.initialize_app(
            cred,
            {
                "databaseURL": project.firebase_database_url,
            },
            name=f"superadmin-{project.id}",
        )
        _firebase_apps[project.id] = fb_app
        return fb_app
    except ValueError:
        # Already initialized under the same name in some reload scenarios.
        try:
            fb_app = firebase_admin.get_app(f"superadmin-{project.id}")
            _firebase_apps[project.id] = fb_app
            return fb_app
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Firebase initialization failed: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Firebase initialization failed: {exc}")


def firebase_ref(project: AppProject, path: str):
    fb_app = firebase_for(project)
    clean = "/" + path.strip("/")
    return firebase_db.reference(clean, app=fb_app)


# ---------------------------------------------------------------------------
# Public API: health
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "service": "SuperAdmin Security Gateway",
        "status": "online",
        "time": now().isoformat(),
    }


@app.get("/health")
def health():
    return {"ok": True, "database": "configured", "time": now().isoformat()}


# ---------------------------------------------------------------------------
# App / client authentication
# ---------------------------------------------------------------------------

@app.post("/api/client/request-admin-approval")
async def request_admin_approval(request: Request, session: Session = Depends(db)):
    """
    Admin APK sends JSON:
    {
      "app_key": "...",
      "device_name": "...",
      "device_id": "...",
      "battery": "78%",
      "ip_address": "optional"
    }

    The server records a PENDING request. SuperAdmin later approves/rejects/blocks.
    """
    body = await request.json()
    app_key = str(body.get("app_key", "")).strip()
    device_name = str(body.get("device_name", "Unknown Device")).strip()
    device_id = str(body.get("device_id", "")).strip()
    battery = str(body.get("battery", "")).strip()

    if not app_key or not device_id:
        raise HTTPException(status_code=400, detail="app_key and device_id are required")

    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project or project.status != "ACTIVE":
        create_security_alert(
            session, project.id if project else None,
            "UNKNOWN_APP_REQUEST", device_name, request.client.host if request.client else None,
            "Unknown or inactive app key"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    ip = request.client.host if request.client else None

    existing = (
        session.query(AdminRequest)
        .filter(
            AdminRequest.app_id == project.id,
            AdminRequest.device_id == device_id,
            AdminRequest.request_status == "PENDING",
        )
        .first()
    )
    if existing:
        return {
            "ok": True,
            "request_id": existing.id,
            "status": existing.request_status,
        }

    item = AdminRequest(
        app_id=project.id,
        device_name=device_name[:200],
        device_id=device_id[:300],
        battery=battery[:30],
        ip_address=ip,
        request_status="PENDING",
    )
    session.add(item)
    session.commit()

    return {"ok": True, "request_id": item.id, "status": "PENDING"}


@app.post("/api/client/status")
async def client_status(request: Request, session: Session = Depends(db)):
    """
    Client can poll its approval status using:
    {
      "app_key": "...",
      "device_id": "..."
    }
    """
    body = await request.json()
    app_key = str(body.get("app_key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()

    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project:
        create_security_alert(
            session, None, "UNKNOWN_APP", "Unknown Device",
            request.client.host if request.client else None,
            "Invalid app key"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    item = (
        session.query(AdminRequest)
        .filter_by(app_id=project.id, device_id=device_id)
        .order_by(AdminRequest.id.desc())
        .first()
    )

    if not item:
        return {"status": "NOT_FOUND"}

    if item.request_status == "APPROVED" and item.approved_until:
        if item.approved_until < now():
            item.request_status = "EXPIRED"
            session.commit()

    return {
        "status": item.request_status,
        "approved_until": item.approved_until.isoformat() if item.approved_until else None,
    }


@app.post("/api/client/credential")
async def client_credential(request: Request, session: Session = Depends(db)):
    """
    Returns a short-lived gateway token only to an APPROVED Admin device.
    """
    body = await request.json()
    app_key = str(body.get("app_key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()

    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project:
        create_security_alert(
            session, None, "UNKNOWN_APP_CREDENTIAL_ATTEMPT", "Unknown Device",
            request.client.host if request.client else None,
            "Invalid app key"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    item = (
        session.query(AdminRequest)
        .filter_by(app_id=project.id, device_id=device_id)
        .order_by(AdminRequest.id.desc())
        .first()
    )

    if not item or item.request_status != "APPROVED":
        create_security_alert(
            session, project.id, "UNAPPROVED_ADMIN_ACCESS",
            item.device_name if item else "Unknown Device",
            request.client.host if request.client else None,
            "Device is not approved"
        )
        raise HTTPException(status_code=403, detail="Not approved")

    if item.approved_until and item.approved_until < now():
        item.request_status = "EXPIRED"
        session.commit()
        raise HTTPException(status_code=403, detail="Approval expired")

    raw = secrets.token_urlsafe(48)
    record = AppCredential(
        app_id=project.id,
        client_type="ADMIN",
        token_hash=hash_token(raw),
        device_id=device_id,
        status="ACTIVE",
        expires_at=item.approved_until,
    )
    session.add(record)
    session.commit()

    return {
        "token": raw,
        "expires_at": item.approved_until.isoformat() if item.approved_until else None
    }


def require_gateway_token(
    request: Request,
    session: Session = Depends(db),
):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        create_security_alert(
            session, None, "MISSING_GATEWAY_AUTH",
            request.headers.get("X-Device-Name", "Unknown Device"),
            request.client.host if request.client else None,
            "Missing gateway token"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    raw = header[7:].strip()
    record = session.query(AppCredential).filter_by(token_hash=hash_token(raw)).first()

    if not record or record.status != "ACTIVE":
        create_security_alert(
            session, record.app_id if record else None,
            "INVALID_GATEWAY_TOKEN",
            request.headers.get("X-Device-Name", "Unknown Device"),
            request.client.host if request.client else None,
            "Invalid gateway token"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    if record.expires_at and record.expires_at < now():
        record.status = "EXPIRED"
        session.commit()
        raise HTTPException(status_code=403, detail="Token expired")

    return record


# ---------------------------------------------------------------------------
# Firebase gateway endpoints
# ---------------------------------------------------------------------------

@app.get("/api/firebase/{app_key}/{path:path}")
def firebase_read(
    app_key: str,
    path: str,
    request: Request,
    session: Session = Depends(db),
    credential: AppCredential = Depends(require_gateway_token),
):
    """
    Read Firebase data through the gateway.
    """
    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project or project.status != "ACTIVE" or credential.app_id != project.id:
        create_security_alert(
            session, project.id if project else None,
            "FIREBASE_GATEWAY_DENIED",
            request.headers.get("X-Device-Name", "Unknown Device"),
            request.client.host if request.client else None,
            "Invalid app/credential combination"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    try:
        value = firebase_ref(project, path).get()
        return JSONResponse(content=value)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Firebase read failed: {exc}")


@app.put("/api/firebase/{app_key}/{path:path}")
async def firebase_write(
    app_key: str,
    path: str,
    request: Request,
    session: Session = Depends(db),
    credential: AppCredential = Depends(require_gateway_token),
):
    """
    Write Firebase data through the gateway.
    """
    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project or project.status != "ACTIVE" or credential.app_id != project.id:
        create_security_alert(
            session, project.id if project else None,
            "FIREBASE_GATEWAY_DENIED",
            request.headers.get("X-Device-Name", "Unknown Device"),
            request.client.host if request.client else None,
            "Invalid app/credential combination"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    try:
        payload = await request.json()
        firebase_ref(project, path).set(payload)
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Firebase write failed: {exc}")


@app.patch("/api/firebase/{app_key}/{path:path}")
async def firebase_update(
    app_key: str,
    path: str,
    request: Request,
    session: Session = Depends(db),
    credential: AppCredential = Depends(require_gateway_token),
):
    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project or project.status != "ACTIVE" or credential.app_id != project.id:
        create_security_alert(
            session, project.id if project else None,
            "FIREBASE_GATEWAY_DENIED",
            request.headers.get("X-Device-Name", "Unknown Device"),
            request.client.host if request.client else None,
            "Invalid app/credential combination"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    try:
        payload = await request.json()
        firebase_ref(project, path).update(payload)
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Firebase update failed: {exc}")


@app.delete("/api/firebase/{app_key}/{path:path}")
def firebase_delete(
    app_key: str,
    path: str,
    request: Request,
    session: Session = Depends(db),
    credential: AppCredential = Depends(require_gateway_token),
):
    project = session.query(AppProject).filter_by(app_key=app_key).first()
    if not project or project.status != "ACTIVE" or credential.app_id != project.id:
        create_security_alert(
            session, project.id if project else None,
            "FIREBASE_GATEWAY_DENIED",
            request.headers.get("X-Device-Name", "Unknown Device"),
            request.client.host if request.client else None,
            "Invalid app/credential combination"
        )
        raise HTTPException(status_code=403, detail="Blocked")

    try:
        firebase_ref(project, path).delete()
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Firebase delete failed: {exc}")


# ---------------------------------------------------------------------------
# SuperAdmin API
# ---------------------------------------------------------------------------

@app.post("/api/superadmin/login")
def superadmin_login(username: str = Form(...), password: str = Form(...)):
    if not secrets.compare_digest(username, SUPERADMIN_USERNAME):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not secrets.compare_digest(password, SUPERADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"token": make_jwt("superadmin")}


@app.post("/api/superadmin/apps")
async def create_app(
    request: Request,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    body = await request.json()
    name = str(body.get("app_name", "")).strip()
    project_id = str(body.get("firebase_project_id", "")).strip()
    database_url = str(body.get("firebase_database_url", "")).strip()
    credentials_json = body.get("firebase_credentials_json")

    if not name or not project_id or not database_url or not credentials_json:
        raise HTTPException(
            status_code=400,
            detail="app_name, firebase_project_id, firebase_database_url and firebase_credentials_json are required",
        )

    try:
        if isinstance(credentials_json, dict):
            credentials_json = json.dumps(credentials_json)
        else:
            json.loads(credentials_json)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Firebase credentials JSON")

    item = AppProject(
        app_name=name[:150],
        app_key=secrets.token_urlsafe(18),
        firebase_project_id=project_id[:200],
        firebase_database_url=database_url[:500],
        firebase_credentials_json=credentials_json,
        status="ACTIVE",
    )
    session.add(item)
    session.commit()

    return {
        "id": item.id,
        "app_name": item.app_name,
        "app_key": item.app_key,
        "status": item.status,
    }


@app.get("/api/superadmin/apps")
def list_apps(
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    items = session.query(AppProject).order_by(AppProject.id.desc()).all()
    return [
        {
            "id": x.id,
            "app_name": x.app_name,
            "app_key": x.app_key,
            "firebase_project_id": x.firebase_project_id,
            "status": x.status,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in items
    ]


@app.get("/api/superadmin/apps/{app_id}/requests")
def app_requests(
    app_id: int,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    items = (
        session.query(AdminRequest)
        .filter_by(app_id=app_id)
        .order_by(AdminRequest.id.desc())
        .all()
    )
    return [
        {
            "id": x.id,
            "device_name": x.device_name,
            "device_id": x.device_id,
            "battery": x.battery,
            "ip_address": x.ip_address,
            "status": x.request_status,
            "approved_days": x.approved_days,
            "approved_until": x.approved_until.isoformat() if x.approved_until else None,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in items
    ]


@app.post("/api/superadmin/requests/{request_id}/approve")
async def approve_request(
    request_id: int,
    request: Request,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    body = await request.json()
    days = int(body.get("approved_days", 1))
    if days < 1 or days > 3650:
        raise HTTPException(status_code=400, detail="approved_days must be 1..3650")

    item = session.get(AdminRequest, request_id)
    if not item:
        raise HTTPException(status_code=404, detail="Request not found")

    item.request_status = "APPROVED"
    item.approved_days = days
    item.approved_until = now() + timedelta(days=days)
    item.updated_at = now()
    session.commit()

    return {
        "ok": True,
        "status": item.request_status,
        "approved_until": item.approved_until.isoformat(),
    }


@app.post("/api/superadmin/requests/{request_id}/reject")
def reject_request(
    request_id: int,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    item = session.get(AdminRequest, request_id)
    if not item:
        raise HTTPException(status_code=404, detail="Request not found")

    item.request_status = "REJECTED"
    item.updated_at = now()
    session.commit()
    return {"ok": True, "status": "REJECTED"}


@app.post("/api/superadmin/requests/{request_id}/block")
def block_request(
    request_id: int,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    item = session.get(AdminRequest, request_id)
    if not item:
        raise HTTPException(status_code=404, detail="Request not found")

    item.request_status = "BLOCKED"
    item.updated_at = now()

    # Invalidate existing credentials for this device/app.
    session.query(AppCredential).filter(
        AppCredential.app_id == item.app_id,
        AppCredential.device_id == item.device_id,
        AppCredential.status == "ACTIVE",
    ).update({"status": "BLOCKED"})

    session.commit()
    return {"ok": True, "status": "BLOCKED"}


@app.get("/api/superadmin/apps/{app_id}/alerts")
def app_alerts(
    app_id: int,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    items = (
        session.query(SecurityAlert)
        .filter_by(app_id=app_id)
        .order_by(SecurityAlert.id.desc())
        .limit(500)
        .all()
    )
    return [
        {
            "id": x.id,
            "alert_type": x.alert_type,
            "device_name": x.device_name,
            "ip_address": x.ip_address,
            "reason": x.reason,
            "status": x.status,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in items
    ]


@app.get("/api/superadmin/apps/{app_id}")
def app_details(
    app_id: int,
    session: Session = Depends(db),
    _: dict = Depends(require_superadmin),
):
    item = session.get(AppProject, app_id)
    if not item:
        raise HTTPException(status_code=404, detail="App not found")

    return {
        "id": item.id,
        "app_name": item.app_name,
        "app_key": item.app_key,
        "firebase_project_id": item.firebase_project_id,
        "firebase_database_url": item.firebase_database_url,
        "status": item.status,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


# ---------------------------------------------------------------------------
# Minimal SuperAdmin web UI
# ---------------------------------------------------------------------------

LOGIN_HTML = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SuperAdmin Login</title>
<style>
body{margin:0;background:#0b0d12;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh}
.card{width:min(420px,90%);background:#151922;border:1px solid #293041;border-radius:18px;padding:28px;box-sizing:border-box}
input,button{width:100%;padding:13px;margin-top:10px;border-radius:10px;border:1px solid #303848;box-sizing:border-box}
input{background:#0d1118;color:#fff}button{background:#fff;color:#111;font-weight:700;cursor:pointer}
h1{margin-top:0}
</style>
</head>
<body>
<div class="card">
<h1>SuperAdmin</h1>
<form method="post" action="/web/login">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>LOGIN</button>
</form>
</div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SuperAdmin Dashboard</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#090b10;color:#eef2f7;font-family:Arial,sans-serif}
header{padding:18px 20px;border-bottom:1px solid #202633;display:flex;justify-content:space-between;align-items:center}
main{max-width:1100px;margin:auto;padding:20px}
button{border:0;border-radius:9px;padding:10px 14px;font-weight:700;cursor:pointer}
.add{background:#fff;color:#111}.danger{background:#3a1720;color:#ff9dab}.ok{background:#123c28;color:#8df0b2}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:18px}
.card{background:#11151d;border:1px solid #252c39;border-radius:16px;padding:18px}
.muted{color:#8f99a9;font-size:13px}
.badge{display:inline-block;padding:5px 8px;border-radius:999px;background:#123c28;color:#8df0b2;font-size:12px}
#panel{display:none;position:fixed;inset:0;background:#090b10;overflow:auto;padding:20px}
.panel-inner{max-width:1000px;margin:auto}
.row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
table{width:100%;border-collapse:collapse;margin-top:12px}
td,th{text-align:left;padding:10px;border-bottom:1px solid #252c39;font-size:13px}
input,textarea{width:100%;background:#0c1017;color:#fff;border:1px solid #303848;border-radius:9px;padding:10px;margin-top:6px}
.modal{background:#11151d;border:1px solid #303848;border-radius:16px;padding:20px;max-width:600px;margin:40px auto}
</style>
</head>
<body>
<header><b>SUPERADMIN</b><button class="add" onclick="showAdd()">+ ADD APP</button></header>
<main>
<h2>All Apps</h2>
<div id="apps" class="grid"></div>
</main>

<div id="panel">
<div class="panel-inner">
<button onclick="closePanel()">← BACK</button>
<div id="detail"></div>
</div>
</div>

<script>
async function api(url,opt={}){
  opt.credentials='same-origin';
  opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});
  let r=await fetch(url,opt);
  if(r.status===401||r.status===403){location.href="/web/login";throw new Error("Unauthorized");}
  return r.json();
}
async function loadApps(){
  let data=await api('/api/superadmin/apps');
  document.getElementById('apps').innerHTML=data.map(a=>`
    <div class="card">
      <h3>${esc(a.app_name)}</h3>
      <div class="muted">Firebase: ${esc(a.firebase_project_id)}</div>
      <p><span class="badge">${esc(a.status)}</span></p>
      <button onclick="openApp(${a.id})">OPEN APP</button>
    </div>`).join('');
}
function esc(x){return String(x??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}

async function openApp(id){
  document.getElementById('panel').style.display='block';
  let [a,req,alerts]=await Promise.all([
    api('/api/superadmin/apps/'+id),
    api('/api/superadmin/apps/'+id+'/requests'),
    api('/api/superadmin/apps/'+id+'/alerts')
  ]);
  document.getElementById('detail').innerHTML=`
    <h1>${esc(a.app_name)}</h1>
    <p class="muted">Firebase: ${esc(a.firebase_project_id)} · Status: ${esc(a.status)}</p>
    <h2>ADMIN REQUESTS</h2>
    <table><tr><th>Device</th><th>Battery</th><th>IP</th><th>Status</th><th>Action</th></tr>
    ${req.map(x=>`<tr>
      <td>${esc(x.device_name)}<br><span class="muted">${esc(x.device_id)}</span></td>
      <td>${esc(x.battery)}</td><td>${esc(x.ip_address)}</td><td>${esc(x.status)}</td>
      <td>${x.status==='PENDING'?`<button class="ok" onclick="approve(${x.id},${id})">APPROVE</button>
      <button onclick="reject(${x.id},${id})">REJECT</button>
      <button class="danger" onclick="block(${x.id},${id})">BLOCK</button>`:'-'}</td>
    </tr>`).join('')}</table>
    <h2>SECURITY ALERTS</h2>
    <table><tr><th>Type</th><th>Device</th><th>IP</th><th>Status</th><th>Time</th></tr>
    ${alerts.map(x=>`<tr><td>${esc(x.alert_type)}</td><td>${esc(x.device_name)}</td><td>${esc(x.ip_address)}</td><td>${esc(x.status)}</td><td>${esc(x.created_at)}</td></tr>`).join('')}</table>`;
}
async function approve(rid,aid){
  let d=prompt('Approved days:', '30'); if(!d)return;
  await api('/api/superadmin/requests/'+rid+'/approve',{method:'POST',body:JSON.stringify({approved_days:Number(d)})});
  openApp(aid);
}
async function reject(rid,aid){await api('/api/superadmin/requests/'+rid+'/reject',{method:'POST'});openApp(aid);}
async function block(rid,aid){if(confirm('Block this device?')){await api('/api/superadmin/requests/'+rid+'/block',{method:'POST'});openApp(aid);}}
function closePanel(){document.getElementById('panel').style.display='none';loadApps();}
function showAdd(){
  document.getElementById('panel').style.display='block';
  document.getElementById('detail').innerHTML=`
  <div class="modal"><h2>ADD NEW APP</h2>
  <input id="n" placeholder="App Name">
  <input id="p" placeholder="Firebase Project ID">
  <input id="u" placeholder="Firebase Database URL">
  <textarea id="c" rows="8" placeholder="Firebase service-account JSON"></textarea>
  <div class="row"><button class="add" onclick="addApp()">ADD APP</button></div>
  <p class="muted">Never put this service-account JSON inside an APK.</p></div>`;
}
async function addApp(){
  let body={app_name:n.value,firebase_project_id:p.value,firebase_database_url:u.value,firebase_credentials_json:c.value};
  let r=await api('/api/superadmin/apps',{method:'POST',body:JSON.stringify(body)});
  if(r.detail){alert(r.detail);return;}
  alert('App added. App Key: '+r.app_key);
  closePanel();
}
loadApps();
</script>
</body>
</html>
"""

@app.get("/web/login", response_class=HTMLResponse)
def web_login():
    return LOGIN_HTML


@app.post("/web/login")
def web_login_post(username: str = Form(...), password: str = Form(...)):
    if (
        secrets.compare_digest(username, SUPERADMIN_USERNAME)
        and secrets.compare_digest(password, SUPERADMIN_PASSWORD)
    ):
        token = make_jwt("superadmin")
        response = RedirectResponse("/web", status_code=303)
        response.set_cookie(
            "sa_token",
            token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=TOKEN_EXPIRE_MINUTES * 60,
        )
        return response
    return HTMLResponse("<h3>Invalid credentials</h3><a href='/web/login'>Back</a>", status_code=401)


@app.get("/web/logout")
def web_logout():
    response = RedirectResponse("/web/login", status_code=303)
    response.delete_cookie("sa_token")
    return response


@app.get("/web", response_class=HTMLResponse)
def web_home(request: Request):
    token = request.cookies.get("sa_token")
    if not token:
        return RedirectResponse("/web/login")
    try:
        verify_jwt(token)
    except HTTPException:
        return RedirectResponse("/web/login")
    return DASHBOARD_HTML


# ---------------------------------------------------------------------------
# Local startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
