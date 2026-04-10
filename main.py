import os
import uvicorn
import logging
import base64
import random
import urllib.parse
from datetime import datetime # Muhimu kwa audit logs
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
import gridfs
from bson import ObjectId

# --- 1. LOAD ENVIRONMENT VARIABLES ---
load_dotenv()

# --- IMPORTING CORE MODULES ---
from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.signatures import SignatureEngine
from core.anti_forensics import AntiForensics

# CONFIGURATION
API_SECRET = os.getenv("API_SECRET_KEY", "Default_Secret_Change_Me")
RAW_MONGO_URL = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "ultimate_crypto"

# --- 2. SAFE DATABASE CONNECTION ---
db = None
license_collection = None

try:
    if "@" in RAW_MONGO_URL:
        prefix, rest = RAW_MONGO_URL.split("://", 1)
        auth, host_part = rest.split("@", 1)
        if ":" in auth:
            user, pwd = auth.split(":", 1)
            safe_pwd = urllib.parse.quote_plus(pwd)
            clean_url = f"{prefix}://{user}:{safe_pwd}@{host_part}"
            client = AsyncIOMotorClient(clean_url)
        else:
            client = AsyncIOMotorClient(RAW_MONGO_URL)
    else:
        client = AsyncIOMotorClient(RAW_MONGO_URL)

    db = client[DB_NAME]
    license_collection = db["licenses"]
    print("✅ [DB] MongoDB Atlas Connected Successfully")
except Exception as e:
    print(f"❌ [DB] Connection Error: {e}")

# --- 3. EMAIL CONFIG ---
conf = ConnectionConfig(
    MAIL_USERNAME = os.getenv("MAIL_USERNAME") or "example@gmail.com",
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD") or "",
    MAIL_FROM = os.getenv("MAIL_USERNAME") or "example@gmail.com",
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

app = FastAPI(title="UC-Suite PRO", version="20.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class CryptoPayload(BaseModel):
    data: Optional[str] = None
    key: Optional[str] = None
    shift: Optional[int] = 3
    to: Optional[str] = None
    content: Optional[str] = None
    file_path: Optional[str] = None
    otp: Optional[str] = None
    image_data: Optional[str] = None 
    operator_id: Optional[str] = "UC-PRO-71468B1B" # Default ID yako
    action: Optional[str] = None
    module: Optional[str] = None

# --- INTEGRATED ROUTES ---

@app.post("/encrypt")
async def encrypt_route(payload: CryptoPayload):
    try:
        derived_key = KeyManager.derive_key(payload.key)
        result = CryptoEngine.encrypt(payload.data, derived_key)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption Failure: {str(e)}")

@app.post("/decrypt")
async def decrypt_route(payload: CryptoPayload):
    try:
        derived_key = KeyManager.derive_key(payload.key)
        result = CryptoEngine.decrypt(payload.data, derived_key)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption Failed")

# --- MPYA: FORENSIC AUDIT LOGGING ---
@app.post("/audit-log")
async def create_audit_log(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized Audit Access")
    
    try:
        log_entry = {
            "operator_id": payload.operator_id,
            "action": payload.action or "UNDEFINED_ACTION",
            "module": payload.module or "CORE_SYSTEM",
            "timestamp": datetime.now(),
            "status": "SECURE_LOG"
        }
        await db["forensic_logs"].insert_one(log_entry)
        return {"status": "success", "message": "Forensic Trace Archived"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit Failure: {str(e)}")

# --- VERIFY OTP & SYNC DATA (Updated with Audit) ---
@app.post("/verify-otp")
async def verify_otp(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
         raise HTTPException(status_code=401, detail="Unauthorized Access")
    
    if payload.otp and payload.data:
        sync_log = {
            "operator_data": payload.data,
            "otp_used": payload.otp,
            "timestamp": datetime.now(),
            "status": "SECURE_SYNC"
        }
        await db["stego_syncs"].insert_one(sync_log)
        
        # Auto-log forensic trace
        audit = {
            "operator_id": payload.operator_id,
            "action": "CLOUD_SYNC_SUCCESS",
            "module": "STEGANOGRAPHY_GATE",
            "timestamp": datetime.now()
        }
        await db["forensic_logs"].insert_one(audit)
        
        return {"status": "success", "message": "Handshake Verified & Data Synced"}
    
    raise HTTPException(status_code=400, detail="Missing OTP or Data")

@app.get("/get-audit-logs")
async def get_audit_logs(x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        # Tunachukua logs 50 za mwisho, kuanzia mpya zaidi
        cursor = db["forensic_logs"].find().sort("timestamp", -1).limit(50)
        logs = []
        async for doc in cursor:
            logs.append({
                "operator_id": doc.get("operator_id"),
                "action": doc.get("action"),
                "module": doc.get("module"),
                "timestamp": str(doc.get("timestamp")),
                "status": doc.get("status", "AUDITED")
            })
        return {"status": "success", "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- RSA SIGNING ---
@app.post("/sign")
async def sign_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized Access")
    
    if not payload.data:
        raise HTTPException(status_code=400, detail="No data to sign")
        
    signature = SignatureEngine.sign(payload.data) 
    return {"status": "success", "signature": signature}

# --- SAVE STEGO IMAGE TO CLOUD ---
@app.post("/save-image")
async def save_image_cloud(payload: CryptoPayload):
    if not payload.image_data:
         raise HTTPException(status_code=400, detail="No image data found")
    
    img_entry = {
        "filename": f"stego_{random.randint(100,999)}.png",
        "data": payload.image_data,
        "created_at": datetime.now()
    }
    await db["secure_images"].insert_one(img_entry)
    return {"status": "success", "message": "Image Archived in MongoDB Atlas"}

@app.post("/send-secure-email")
async def send_email_route(payload: CryptoPayload):
    if not payload.to or not payload.content:
        raise HTTPException(status_code=400, detail="Missing Recipient or Content")
    
    message = MessageSchema(
        subject="UC-Suite: Secure Encrypted Packet",
        recipients=[payload.to],
        body=f"UC-PRO SECURE DISPATCH:\n\n{payload.content}\n\n---\nIntegrity Verified.",
        subtype=MessageType.plain
    )
    fm = FastMail(conf)
    try:
        await fm.send_message(message)
        return {"status": "success", "message": "Email dispatched"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mail failed: {str(e)}")

@app.post("/send-verification")
async def send_verification(payload: CryptoPayload):
    if not payload.to:
        raise HTTPException(status_code=400, detail="Email recipient is required")
    
    otp_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
    message = MessageSchema(
        subject="UC-Suite: Human Verification Required",
        recipients=[payload.to],
        body=f"Kodi yako ya uhakiki ni: {otp_code}",
        subtype=MessageType.plain
    )
    
    fm = FastMail(conf)
    try:
        await fm.send_message(message)
        return {"status": "sent", "otp": otp_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification email failed: {str(e)}")

@app.post("/verify-license")
async def verify_license(request: Request, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized Access")
    
    if license_collection is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        body = await request.json()
        license_key = body.get("license_key")
        entry = await license_collection.find_one({"license_key": license_key})
        if entry:
            return {"status": "success", "message": "Access Granted"}
        raise HTTPException(status_code=404, detail="Invalid License")
    except Exception:
        raise HTTPException(status_code=500, detail="Server Error")

@app.post("/caesar")
async def caesar_cipher(request: dict, x_api_key: str = Header(None)):
    # Verify the security key from Java
    if x_api_key != "Emily_Crypto_Secure_2026_KIU":
        raise HTTPException(status_code=401, detail="Unauthorized")

    text = request.get("data", "")
    s = request.get("shift", 3)
    result = ""

    for char in text:
        if char.isupper():
            result += chr((ord(char) + s - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + s - 97) % 26 + 97)
        else:
            result += char

    return {"status": "success", "result": result}


@app.post("/legacy-cipher")
async def legacy_cipher(request: dict, x_api_key: str = Header(None)):
    if x_api_key != "Emily_Crypto_Secure_2026_KIU":
        raise HTTPException(status_code=401)

    text = request.get("data", "")
    shift = request.get("shift", 3)
    c_type = request.get("type", "caesar_shift")
    result = ""

    if "atbash" in c_type:
        # Atbash Mirror Logic
        for char in text:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                result += chr(base + (25 - (ord(char) - base)))
            else: result += char
    else:
        # Caesar / Rot13 Logic (Shift base)
        # Shift ya -shift inafanya decryption moja kwa moja
        for char in text:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                result += chr((ord(char) - base + shift) % 26 + base)
            else: result += char

    return {"status": "success", "result": result}
@app.post("/legacy-cipher")
async def legacy_cipher(request: Request, x_api_key: str = Header(None, alias="X-API-KEY")):
    # 1. Uhakiki wa Key toka Java
    if x_api_key != "Emily_Crypto_Secure_2026_KIU":
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    text = body.get("data", "")
    shift = body.get("shift", 3)
    c_type = body.get("type", "caesar_shift")
    key = body.get("key", "SECRET").upper()
    result = ""

    if "vigenere" in c_type:
        key_idx = 0
        is_encrypt = shift >= 0
        for char in text:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                k = ord(key[key_idx % len(key)]) - 65
                k = k if is_encrypt else -k
                result += chr((ord(char) - base + k) % 26 + base)
                key_idx += 1
            else: result += char

    elif "atbash" in c_type:
        # ATBASH LOGIC - Badala ya 'pass', sasa inafanya kazi
        for char in text:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                result += chr(base + (25 - (ord(char) - base)))
            else: result += char

    else:
        # CAESAR/ROT13 LOGIC - Badala ya 'pass', sasa inafanya kazi
        for char in text:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                result += chr((ord(char) - base + shift) % 26 + base)
            else: result += char

    return {"status": "success", "result": result}
@app.get("/get-audit-logs")
async def get_audit_logs():
    try:
        # Inatafuta logs 50 za mwisho
        cursor = db["stego_syncs"].find().sort("timestamp", -1).limit(50)
        logs = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"]) # Inabadilisha ObjectId kuwa string
            logs.append(doc)
        return logs # Hii inarudi kama JSONArray kule Java
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return []

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)