import json, secrets
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .config import settings
from .db import Base, engine, get_db, SessionLocal
from .models import User, Scan
from .schemas import RegisterIn, LoginIn, URLIn, EmailIn, NetworkIn
from .security import hash_password, verify_password, create_token, decode_token
from . import analyzers

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title=settings.app_name, version="1.0.0", docs_url="/docs" if settings.environment != "production" else None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["Authorization","Content-Type"])
if settings.environment == "production": app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"strict-origin-when-cross-origin","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Cache-Control":"no-store"})
    return response

Base.metadata.create_all(bind=engine)
# Optional one-time local admin bootstrap. Remove the env var immediately after promotion.
if settings.bootstrap_admin_email:
    with SessionLocal() as db:
        user=db.query(User).filter(func.lower(User.email)==settings.bootstrap_admin_email.lower()).first()
        if user: user.role="admin"; db.commit()

bearer = HTTPBearer(auto_error=False)
def current_user(creds: HTTPAuthorizationCredentials|None=Depends(bearer), db: Session=Depends(get_db)):
    if not creds: raise HTTPException(401,"Authentication required")
    payload=decode_token(creds.credentials)
    try: user_id=int(payload["sub"])
    except (KeyError, TypeError, ValueError): raise HTTPException(401,"Invalid session")
    user=db.get(User,user_id)
    if not user: raise HTTPException(401,"Account no longer exists")
    return user
def admin_user(user: User=Depends(current_user)):
    if user.role != "admin": raise HTTPException(403,"Administrator access required")
    return user

def save_scan(db,user,data):
    scan=Scan(user_id=user.id,scan_type=data["type"],subject=data["subject"],risk=data["risk"],score=data["score"],findings_json=json.dumps(data))
    db.add(scan); db.commit(); db.refresh(scan)
    data["id"]=scan.id; data["created_at"]=scan.created_at.isoformat(); return data

@app.get("/api/health")
def health(): return {"status":"ok","app":settings.app_name}

@app.post("/api/auth/register")
@limiter.limit("5/minute")
def register(request:Request, payload:RegisterIn, db:Session=Depends(get_db)):
    email=str(payload.email).lower().strip()
    if db.query(User).filter(User.email==email).first(): raise HTTPException(409,"Email is already registered")
    user=User(email=email,name=payload.name.strip(),password_hash=hash_password(payload.password),role="user")
    db.add(user); db.commit(); db.refresh(user)
    return {"access_token":create_token(user.id,user.role),"token_type":"bearer","user":{"id":user.id,"email":user.email,"name":user.name,"role":user.role}}

@app.post("/api/auth/login")
@limiter.limit("8/minute")
def login(request:Request,payload:LoginIn,db:Session=Depends(get_db)):
    user=db.query(User).filter(User.email==str(payload.email).lower().strip()).first()
    if not user or not verify_password(payload.password,user.password_hash): raise HTTPException(401,"Incorrect email or password")
    return {"access_token":create_token(user.id,user.role),"token_type":"bearer","user":{"id":user.id,"email":user.email,"name":user.name,"role":user.role}}

@app.get("/api/auth/me")
def me(user:User=Depends(current_user)):
    return {"id":user.id,"email":user.email,"name":user.name,"role":user.role}

@app.get("/api/dashboard")
def dashboard(user:User=Depends(current_user),db:Session=Depends(get_db)):
    total=db.query(Scan).filter(Scan.user_id==user.id).count()
    high=db.query(Scan).filter(Scan.user_id==user.id,Scan.risk=="HIGH").count()
    recent=db.query(Scan).filter(Scan.user_id==user.id).order_by(Scan.created_at.desc()).limit(5).all()
    return {"total_scans":total,"high_risk":high,"low_risk":db.query(Scan).filter(Scan.user_id==user.id,Scan.risk=="LOW").count(),"recent":[scan_out(x) for x in recent]}

def scan_out(s): return {"id":s.id,"type":s.scan_type,"subject":s.subject,"risk":s.risk,"score":s.score,"created_at":s.created_at.isoformat() if s.created_at else None}

@app.post("/api/scans/url")
@limiter.limit("20/minute")
def scan_url(request:Request,payload:URLIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    try: data=analyzers.url_analysis(payload.url)
    except ValueError as e: raise HTTPException(422,str(e))
    return save_scan(db,user,data)

@app.post("/api/scans/email")
@limiter.limit("15/minute")
def scan_email(request:Request,payload:EmailIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    return save_scan(db,user,analyzers.email_analysis(payload.content))

@app.post("/api/scans/network")
@limiter.limit("10/minute")
def scan_network(request:Request,payload:NetworkIn,user:User=Depends(current_user),db:Session=Depends(get_db)):
    try: data=analyzers.network_analysis(payload.scope)
    except ValueError as e: raise HTTPException(422,str(e))
    return save_scan(db,user,data)

@app.post("/api/scans/file")
@limiter.limit("10/minute")
async def scan_file(request:Request,file:UploadFile=File(...),user:User=Depends(current_user),db:Session=Depends(get_db)):
    if not file.filename or len(file.filename)>200: raise HTTPException(400,"Invalid filename")
    data=await file.read(settings.max_upload_bytes+1)
    if len(data)>settings.max_upload_bytes: raise HTTPException(413,"File exceeds configured upload limit")
    if not data: raise HTTPException(400,"Empty file")
    safe_name = file.filename.replace(chr(92), "/").split("/")[-1]
    return save_scan(db,user,analyzers.file_analysis(data,safe_name))

@app.get("/api/scans")
def scans(user:User=Depends(current_user),db:Session=Depends(get_db)):
    rows=db.query(Scan).filter(Scan.user_id==user.id).order_by(Scan.created_at.desc()).limit(100).all()
    return [scan_out(x) for x in rows]

@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    s=db.query(Scan).filter(Scan.id==scan_id,Scan.user_id==user.id).first()
    if not s: raise HTTPException(404,"Report not found")
    return json.loads(s.findings_json) | scan_out(s)

@app.get("/api/admin/overview")
def admin_overview(admin:User=Depends(admin_user),db:Session=Depends(get_db)):
    return {"users":db.query(User).count(),"scans":db.query(Scan).count(),"high_risk_scans":db.query(Scan).filter(Scan.risk=="HIGH").count(),"accounts":[{"id":u.id,"email":u.email,"name":u.name,"role":u.role,"created_at":u.created_at.isoformat()} for u in db.query(User).order_by(User.id.desc()).limit(50).all()]}
