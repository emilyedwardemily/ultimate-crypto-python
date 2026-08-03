import os
import json
import hmac
import hashlib
import uvicorn
import logging
import secrets
import httpx
import urllib.parse
from datetime import datetime # Muhimu kwa audit logs
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType

# --- 1. LOAD ENVIRONMENT VARIABLES ---
load_dotenv()

# --- IMPORTING CORE MODULES ---
from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.signatures import SignatureEngine
from core.anti_forensics import AntiForensics
from core.secret_sharing import split_secret, reconstruct_secret
from core.rsa_engine import RSAEngine, PGPEngine, IdentityEngine

# CONFIGURATION
API_SECRET = os.getenv("API_SECRET_KEY", "Default_Secret_Change_Me")
RAW_MONGO_URL = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "ultimate_crypto"

# --- CONSTANTS (ili kuepuka kurudia literals, sonar S1192) ---
MSG_UNAUTHORIZED = "Unauthorized Access"
CERT_SIGNING_SECRET = "Emily_Crypto_Secure_2026_KIU"

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
    logging.info("[DB] MongoDB Atlas Connected Successfully")
except Exception as e:
    logging.exception(f"[DB] Connection Error: {e}")

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


@app.get("/")
async def root_route():
    """Root route: Inarudisha message ya kirafiki badala ya {'detail': 'Not Found'}."""
    return {
        "message": "API is running successfully",
        "service": "UC-BACKEND",
        "status": "online",
        "version": "20.4.0",
        "endpoints": [
            "GET /", "GET /health", "POST /encrypt", "POST /decrypt",
            "POST /sign", "POST /verify-signature", "POST /rsa-keygen",
            "POST /rsa-encrypt", "POST /rsa-decrypt", "POST /pgp-encrypt",
            "POST /pgp-decrypt", "POST /smime-gen", "POST /split",
            "POST /reconstruct", "POST /caesar", "POST /legacy-cipher",
            "POST /secure-wipe", "POST /audit-log", "GET /get-audit-logs",
            "POST /verify-otp", "POST /save-image", "POST /send-secure-email",
            "POST /send-verification", "POST /verify-license",
            "POST /labs/provision", "GET /labs/list", "POST /labs/terminate",
            "GET /ctf/challenges", "POST /ctf/submit", "GET /leaderboard",
            "GET /profile", "GET /dashboard/stats",
        ],
    }


@app.get("/health")
async def health_check():
    db_status = "connected" if db is not None else "disconnected"
    return {"status": "ok", "service": "UC-BACKEND", "version": "20.4.0", "database": db_status}


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
    signature: Optional[str] = None

class SplitPayload(BaseModel):
    secret: str
    n: int
    k: int

class ReconstructPayload(BaseModel):
    shares: list[dict]

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
    except Exception:
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
         raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    
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

# --- SECURE WIPE (Anti-Forensics) ---
@app.post("/secure-wipe")
async def secure_wipe_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)

    if not payload.file_path:
        raise HTTPException(status_code=400, detail="No file path provided")

    from core.anti_forensics import AntiForensics
    wiped = AntiForensics.secure_wipe(payload.file_path)
    if not wiped:
        raise HTTPException(status_code=500, detail="Wipe failed: file not found or inaccessible")

    audit = {
        "operator_id": payload.operator_id,
        "action": "SECURE_WIPE",
        "module": "FORENSICS",
        "timestamp": datetime.now(),
        "status": "VAPORIZED",
        "detail": f"File wiped: {payload.file_path}"
    }
    if db is not None:
        await db["forensic_logs"].insert_one(audit)
    return {"status": "success", "message": "File securely wiped (DoD 3-pass)"}

# --- RSA SIGNING ---
@app.post("/sign")
async def sign_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    
    if not payload.data:
        raise HTTPException(status_code=400, detail="No data to sign")
        
    signature = SignatureEngine.sign(payload.data) 
    return {"status": "success", "signature": signature}

# --- VERIFY RSA SIGNATURE ---
@app.post("/verify-signature")
async def verify_signature_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)

    if not payload.data or not payload.signature:
        raise HTTPException(status_code=400, detail="Data and signature are required")

    result = SignatureEngine.verify_local(payload.data, payload.signature)
    return {"status": "success", "valid": result.get("valid", False), "error": result.get("error")}

# --- RSA ASYMMETRIC ENGINE (inapatana na RSAUtil.java ya frontend) ---
class RSAPayload(BaseModel):
    data: Optional[str] = None
    public_key: Optional[str] = None
    private_key: Optional[str] = None


@app.post("/rsa-keygen")
async def rsa_keygen_route(payload: RSAPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        private_pem, public_pem = RSAEngine.generate_keypair(2048)
        return {"status": "success", "public_key": public_pem, "private_key": private_pem,
                "result": f"RSA-2048 keypair generated.\n\nPUBLIC KEY:\n{public_pem}\n\nPRIVATE KEY:\n{private_pem}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RSA keygen failed: {str(e)}")


@app.post("/rsa-encrypt")
async def rsa_encrypt_route(payload: RSAPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        if not payload.data or not payload.public_key:
            raise HTTPException(status_code=400, detail="data and public_key are required")
        cipher = RSAEngine.encrypt(payload.data, payload.public_key)
        return {"status": "success", "result": cipher}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RSA encryption failed: {str(e)}")


@app.post("/rsa-decrypt")
async def rsa_decrypt_route(payload: RSAPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        if not payload.data or not payload.private_key:
            raise HTTPException(status_code=400, detail="data and private_key are required")
        plain = RSAEngine.decrypt(payload.data, payload.private_key)
        return {"status": "success", "result": plain}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RSA decryption failed: {str(e)}")


@app.post("/pgp-encrypt")
async def pgp_encrypt_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        if not payload.data:
            raise HTTPException(status_code=400, detail="data is required")
        armored = PGPEngine.encrypt(payload.data, payload.key or "default_secure_key")
        return {"status": "success", "result": armored}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PGP encryption failed: {str(e)}")


@app.post("/pgp-decrypt")
async def pgp_decrypt_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        if not payload.data:
            raise HTTPException(status_code=400, detail="data is required")
        plain = PGPEngine.decrypt(payload.data, payload.key or "default_secure_key")
        return {"status": "success", "result": plain}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PGP decryption failed: {str(e)}")


@app.post("/smime-gen")
async def smime_gen_route(payload: CryptoPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        cert_pem, key_pem = IdentityEngine.generate_cert()
        return {"status": "success",
                "certificate": cert_pem,
                "private_key": key_pem,
                "result": f"X.509 S/MIME certificate generated (valid 10 years).\n\nCERTIFICATE:\n{cert_pem}\n\nPRIVATE KEY:\n{key_pem}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Certificate generation failed: {str(e)}")

# --- SAVE STEGO IMAGE TO CLOUD ---
@app.post("/save-image")
async def save_image_cloud(payload: CryptoPayload):
    if not payload.image_data:
         raise HTTPException(status_code=400, detail="No image data found")
    
    img_entry = {
        "filename": f"stego_{secrets.randbelow(900) + 100}.png",
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
    
    otp_code = "".join(str(secrets.randbelow(10)) for _ in range(6))
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
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    
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


@app.get("/verify-cert")
async def verify_cert(vid: str, sig: str):
    """Public certificate-verification endpoint for the PDF QR codes.
    Recomputed HMAC-SHA256(vid) must match the signed sig to be valid."""
    expected = hmac.new(
        CERT_SIGNING_SECRET.encode("utf-8"), vid.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=400, detail="Invalid certificate signature")
    return {
        "valid": True,
        "vid": vid,
        "message": "Certificate verified by the UC-Fortress Academy verification registry.",
    }


def _shift_char(char: str, offset: int) -> str:
    if not char.isalpha():
        return char
    base = 65 if char.isupper() else 97
    return chr((ord(char) - base + offset) % 26 + base)


def _cipher_vigenere(text: str, key: str, is_encrypt: bool) -> str:
    key_idx = 0
    result = []
    for char in text:
        if not char.isalpha():
            result.append(char)
            continue
        k = ord(key[key_idx % len(key)]) - 65
        k = k if is_encrypt else -k
        result.append(_shift_char(char, k))
        key_idx += 1
    return "".join(result)


def _cipher_atbash(text: str) -> str:
    return "".join(
        chr(65 + (25 - (ord(c) - 65))) if c.isupper() else
        chr(97 + (25 - (ord(c) - 97))) if c.islower() else c
        for c in text
    )


def _cipher_shift(text: str, shift: int) -> str:
    return "".join(_shift_char(c, shift) for c in text)


@app.post("/legacy-cipher")
async def legacy_cipher(request: Request, x_api_key: str = Header(None, alias="X-API-KEY")):
    if x_api_key != "Emily_Crypto_Secure_2026_KIU":
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    text = body.get("data", "")
    shift = body.get("shift", 3)
    c_type = body.get("type", "caesar_shift")
    key = body.get("key", "SECRET").upper()

    if "vigenere" in c_type:
        result = _cipher_vigenere(text, key, shift >= 0)
    elif "atbash" in c_type:
        result = _cipher_atbash(text)
    else:
        result = _cipher_shift(text, shift)

    return {"status": "success", "result": result}

@app.post("/split")
async def split_secret_route(payload: SplitPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        if payload.k < 2:
            raise HTTPException(status_code=400, detail="Threshold k must be at least 2")
        if payload.n < payload.k:
            raise HTTPException(status_code=400, detail="n must be >= k")
        if not payload.secret:
            raise HTTPException(status_code=400, detail="Secret cannot be empty")

        shares = split_secret(payload.secret, payload.n, payload.k)
        return {
            "status": "success",
            "threshold": payload.k,
            "total_shares": payload.n,
            "shares": shares
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Split failed: {str(e)}")


@app.post("/reconstruct")
async def reconstruct_secret_route(payload: ReconstructPayload, x_api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail=MSG_UNAUTHORIZED)
    try:
        if not payload.shares or len(payload.shares) < 2:
            raise HTTPException(status_code=400, detail="At least 2 shares are required")

        secret = reconstruct_secret(payload.shares)
        return {
            "status": "success",
            "secret": secret,
            "shares_used": len(payload.shares)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reconstruction failed: {str(e)}")


# --- AZAMPAY PAYMENT INTEGRATION ---

AZAMPAY_APP_NAME = os.getenv("AZAMPAY_APP_NAME", "UltimateCryptoSuite")
AZAMPAY_CLIENT_ID = os.getenv("AZAMPAY_CLIENT_ID", "")
AZAMPAY_CLIENT_SECRET = os.getenv("AZAMPAY_CLIENT_SECRET", "")
AZAMPAY_X_API_KEY = os.getenv("AZAMPAY_X_API_KEY", "")
AZAMPAY_AUTH_URL = "https://authenticator-sandbox.azampay.co.tz/AppRegistration/GenerateToken"
AZAMPAY_CHECKOUT_URL = "https://sandbox.azampay.co.tz/api/v1/checkout/trigger"


class PaymentPayload(BaseModel):
    phoneNumber: str
    amount: str
    email: Optional[str] = None


async def get_azampay_token() -> str:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(AZAMPAY_AUTH_URL, json={
            "appName": AZAMPAY_APP_NAME,
            "clientId": AZAMPAY_CLIENT_ID,
            "clientSecret": AZAMPAY_CLIENT_SECRET
        })
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", {}).get("accessToken") or data.get("accessToken")


@app.post("/api/v1/payments/stk-push")
async def stk_push(
    payload: PaymentPayload,
    x_api_key: Optional[str] = Header(None, alias="X-API-KEY")
):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not payload.phoneNumber or not payload.amount:
        raise HTTPException(status_code=400, detail="Phone number and amount required")

    try:
        logging.info(f"[AZAMPAY] Initiating payment: {payload.phoneNumber} TZS {payload.amount}")
        token = await get_azampay_token()
        external_id = f"UC-{int(datetime.now().timestamp() * 1000)}"

        checkout_body = {
            "amount": str(payload.amount),
            "currency": "TZS",
            "mobile": payload.phoneNumber,
            "externalId": external_id,
            "provider": "AzamPesa"
        }

        async with httpx.AsyncClient(timeout=30) as client:
            checkout_resp = await client.post(
                AZAMPAY_CHECKOUT_URL,
                json=checkout_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "X-API-Key": AZAMPAY_X_API_KEY
                }
            )
            checkout_resp.raise_for_status()
            checkout_data = checkout_resp.json()

        # Record payment in MongoDB
        if db is not None:
            await db["payments"].insert_one({
                "externalId": external_id,
                "phoneNumber": payload.phoneNumber,
                "amount": payload.amount,
                "email": payload.email or None,
                "status": "PENDING",
                "response": checkout_data,
                "createdAt": datetime.now()
            })

        logging.info(f"[AZAMPAY] Payment initiated: {external_id}")
        return {
            "success": True,
            "message": "Payment request sent. Confirm on your phone.",
            "externalId": external_id,
            "data": checkout_data
        }

    except httpx.HTTPStatusError as e:
        logging.exception(f"[AZAMPAY] HTTP error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=502, detail=f"AzamPay gateway error: {e.response.text}")
    except Exception as e:
        logging.exception(f"[AZAMPAY] STK Push failed: {e}")
        raise HTTPException(status_code=500, detail=f"Payment gateway error: {str(e)}")


async def _process_successful_payment(db, body: dict, reference: str, msisdn: str, amount: str):
    """Inasasisha payment kuwa SUCCESS, inamupandisha mtumiaji PREMIUM na kurekodi audit."""
    await db["payments"].update_one(
        {"externalId": reference},
        {"$set": {"status": "SUCCESS", "completedAt": datetime.now(), "webhookData": body}}
    )

    user_query = {"$or": [{"phone": msisdn}]}
    payment = await db["payments"].find_one({"externalId": reference})
    if payment and payment.get("email"):
        user_query["$or"].append({"email": payment["email"]})

    update_result = await db["users"].update_many(
        user_query,
        {"$set": {"role": "PREMIUM", "is_premium": True, "upgradedAt": datetime.now()}}
    )
    logging.info(f"[AZAMPAY] Premium upgrade: {update_result.modified_count} user(s) for {msisdn}")

    await db["forensic_logs"].insert_one({
        "operator_id": "SYSTEM",
        "action": "PAYMENT_SUCCESS",
        "module": "AZAMPAY_GATEWAY",
        "detail": f"Phone: {msisdn}, Amount: {amount}, Ref: {reference}",
        "timestamp": datetime.now(),
        "status": "PREMIUM_UPGRADE"
    })


@app.post("/api/v1/payments/webhook")
async def payment_webhook(request: Request):
    try:
        body = await request.json()
        logging.info(f"[AZAMPAY] Webhook received: {json.dumps(body)}")

        transaction_status = (body.get("transactionstatus") or body.get("status") or "").lower()
        msisdn = body.get("msisdn") or body.get("mobile") or ""
        amount = body.get("amount") or ""
        reference = body.get("reference") or body.get("externalId") or body.get("utilityref") or ""

        # Record raw webhook
        if db is not None:
            await db["payment_webhooks"].insert_one({
                "payload": body,
                "receivedAt": datetime.now()
            })

        if transaction_status == "success":
            if db is not None:
                await _process_successful_payment(db, body, reference, msisdn, amount)
            return {"status": "received", "message": "Payment processed successfully"}

        if db is not None:
            await db["payments"].update_one(
                {"externalId": reference},
                {"$set": {"status": "FAILED", "completedAt": datetime.now(), "webhookData": body}}
            )
        logging.info(f"[AZAMPAY] Payment failed: {reference} - {transaction_status}")
        return {"status": "received", "message": "Payment failed recorded"}

    except Exception as e:
        logging.exception(f"[AZAMPAY] Webhook error: {e}")
        return {"status": "error", "message": str(e)}


# --- ON-DEMAND CTF LABS ---

class LabRequest(BaseModel):
    operator_id: str
    challenge_id: str
    timeout_minutes: Optional[int] = 30


@app.post("/labs/provision")
async def provision_lab_route(
    payload: LabRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-KEY"),
):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from core.lab_manager import provision_lab
    result = await provision_lab(payload.operator_id, payload.challenge_id, payload.timeout_minutes)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"status": "success", "lab": result}


@app.get("/labs/list")
async def list_labs_route(
    operator_id: Optional[str] = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-KEY"),
):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from core.lab_manager import list_labs
    return {"status": "success", "labs": list_labs(operator_id)}


class LabTerminate(BaseModel):
    lab_id: str
    operator_id: str


@app.post("/labs/terminate")
async def terminate_lab_route(
    payload: LabTerminate,
    x_api_key: Optional[str] = Header(None, alias="X-API-KEY"),
):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from core.lab_manager import terminate_lab
    result = await terminate_lab(payload.lab_id, payload.operator_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"status": "success", "result": result}


# --- CTF ACADEMY, LEADERBOARD & GAMIFICATION ---

CHALLENGES = [
    {"id": "c1", "title": "Caesar Cipher Breaker", "category": "Cryptography",
     "difficulty": "easy", "points": 50, "flag": "flag{caesar_br0ken}"},
    {"id": "c2", "title": "XOR Decryption", "category": "Cryptography",
     "difficulty": "easy", "points": 75, "flag": "flag{xor_master}"},
    {"id": "c3", "title": "Atbash Cipher", "category": "Cryptography",
     "difficulty": "easy", "points": 50, "flag": "flag{atbash_m1rr0r}"},
    {"id": "c4", "title": "Vigenere Cipher", "category": "Cryptography",
     "difficulty": "medium", "points": 100, "flag": "flag{vigenere_k3y}"},
    {"id": "c5", "title": "Base64 Decode", "category": "Cryptography",
     "difficulty": "easy", "points": 30, "flag": "flag{b64_d3c0d3r}"},
    {"id": "c6", "title": "Binary to Text", "category": "Cryptography",
     "difficulty": "easy", "points": 30, "flag": "flag{b1nary_w1zard}"},
    {"id": "c7", "title": "RSA Decryption", "category": "Cryptography",
     "difficulty": "hard", "points": 200, "flag": "flag{rsa_pr1me}"},
    {"id": "c8", "title": "Hash Cracking (MD5)", "category": "Cryptography",
     "difficulty": "medium", "points": 100, "flag": "flag{md5_cr4ck3d}"},
    {"id": "c9", "title": "Steganography Hidden Data", "category": "Forensics",
     "difficulty": "medium", "points": 150, "flag": "flag{st3g0_h1dd3n}"},
    {"id": "c10", "title": "Digital Signature Forge", "category": "Cryptography",
     "difficulty": "hard", "points": 250, "flag": "flag{s1gn4tur3_f0rg3}"},
    {"id": "c11", "title": "Shamir Secret Share", "category": "Cryptography",
     "difficulty": "hard", "points": 300, "flag": "flag{sham1r_shar3}"},
    {"id": "c12", "title": "PGP Key Pair", "category": "Cryptography",
     "difficulty": "insane", "points": 400, "flag": "flag{pgp_k3yp41r}"},
    {"id": "c13", "title": "Network Traffic Analysis", "category": "Forensics",
     "difficulty": "medium", "points": 150, "flag": "flag{n3tw0rk_4nal}"},
    {"id": "c14", "title": "Memory Forensics", "category": "Forensics",
     "difficulty": "hard", "points": 250, "flag": "flag{m3m0ry_f0r3ns1cs}"},
]

RANKS = [
    (0, "Script Kiddie"), (100, "Cipher Punk"), (300, "Code Breaker"),
    (600, "Crypto Analyst"), (1000, "Cipher Specialist"),
    (1600, "Cryptographer General"), (2700, "Military-Grade Specialist"),
]

BADGES = [
    {"id": "b1", "name": "First Blood", "icon": "zap",
     "desc": "Solve your first challenge", "unlock_xp": 30},
    {"id": "b2", "name": "Caesar Slayer", "icon": "award",
     "desc": "Solve Caesar Cipher", "unlock_xp": 50},
    {"id": "b3", "name": "XOR Master", "icon": "star",
     "desc": "Solve XOR Decryption", "unlock_xp": 75},
    {"id": "b4", "name": "Cipher Apprentice", "icon": "shield",
     "desc": "Reach 200 XP", "unlock_xp": 200},
    {"id": "b5", "name": "Cipher Expert", "icon": "shield",
     "desc": "Reach 500 XP", "unlock_xp": 500},
    {"id": "b6", "name": "Cipher Master", "icon": "shield",
     "desc": "Reach 1000 XP", "unlock_xp": 1000},
    {"id": "b7", "name": "Level 5", "icon": "award",
     "desc": "Reach Level 5", "unlock_xp": 600},
    {"id": "b8", "name": "Century", "icon": "star",
     "desc": "Solve 5 challenges", "unlock_xp": 250},
    {"id": "b9", "name": "Completionist", "icon": "trophy",
     "desc": "Solve all challenges", "unlock_xp": 2700},
]

leaderboard: dict[str, int] = {}


def get_rank_for_xp(xp: int) -> str:
    for threshold, name in reversed(RANKS):
        if xp >= threshold:
            return name
    return RANKS[0][1]


def get_level(xp: int) -> int:
    return xp // 100 + 1


def get_xp_progress(xp: int) -> dict:
    for i, (threshold, name) in enumerate(RANKS):
        if xp < threshold:
            prev = RANKS[i - 1][0] if i > 0 else 0
            return {"current": name, "xp": xp - prev, "needed": threshold - prev, "next": name}
    return {"current": RANKS[-1][1], "xp": 0, "needed": 0, "next": None}


def compute_badges(xp: int, solved_count: int) -> list[dict]:
    result = []
    for badge in BADGES:
        unlocked = False
        if badge["id"] == "b1":
            unlocked = xp >= 30
        elif badge["id"] == "b8":
            unlocked = solved_count >= 5
        elif badge["id"] == "b9":
            unlocked = solved_count >= 14
        elif badge["id"] in ("b2",):
            unlocked = xp >= badge["unlock_xp"]
        elif badge["id"] in ("b3",):
            unlocked = xp >= badge["unlock_xp"]
        else:
            unlocked = xp >= badge["unlock_xp"]
        result.append({**badge, "unlocked": unlocked})
    return result


@app.get("/ctf/challenges")
async def get_ctf_challenges(operator_id: Optional[str] = None):
    solved = set()
    if operator_id:
        solved = {k.split("_")[1] for k in leaderboard if k.startswith(f"{operator_id}_")}
    return {
        "status": "success",
        "challenges": [
            {**ch, "solved": ch["id"] in solved}
            for ch in CHALLENGES
        ],
    }


class FlagSubmission(BaseModel):
    operator_id: str
    challenge_id: str
    flag: str


@app.post("/ctf/submit")
async def submit_ctf_flag(
    payload: FlagSubmission,
    x_api_key: Optional[str] = Header(None, alias="X-API-KEY"),
):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

    challenge = next((c for c in CHALLENGES if c["id"] == payload.challenge_id), None)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    key = f"{payload.operator_id}_{payload.challenge_id}"
    if key in leaderboard:
        return {"status": "error", "message": "Already solved"}

    if payload.flag.strip() != challenge["flag"]:
        return {"status": "error", "message": "Wrong flag"}

    leaderboard[key] = challenge["points"]
    total_xp = sum(v for k, v in leaderboard.items() if k.startswith(payload.operator_id))
    rank = get_rank_for_xp(total_xp)
    badges = compute_badges(total_xp, sum(1 for k in leaderboard if k.startswith(payload.operator_id)))

    return {
        "status": "success",
        "message": f"Correct! +{challenge['points']} XP",
        "xp_awarded": challenge["points"],
        "total_xp": total_xp,
        "rank": rank,
        "badges": badges,
    }


@app.get("/leaderboard")
async def get_global_leaderboard():
    user_xp: dict[str, int] = {}
    for k, v in leaderboard.items():
        uid = k.split("_")[0]
        user_xp[uid] = user_xp.get(uid, 0) + v

    ranked = sorted(user_xp.items(), key=lambda x: -x[1])
    entries = []
    for i, (uid, xp) in enumerate(ranked, 1):
        solved = sum(1 for k in leaderboard if k.startswith(uid))
        entries.append({
            "rank": i,
            "username": uid,
            "xp": xp,
            "level": get_level(xp),
            "badges": sum(1 for b in compute_badges(xp, solved) if b["unlocked"]),
            "challengesSolved": solved,
        })
    return {"status": "success", "entries": entries}


@app.get("/profile")
async def get_profile(operator_id: str = "UC-PRO-71468B1B"):
    total_xp = sum(v for k, v in leaderboard.items() if k.startswith(operator_id))
    solved_count = sum(1 for k in leaderboard if k.startswith(operator_id))
    badges = compute_badges(total_xp, solved_count)
    progress = get_xp_progress(total_xp)

    rank_num = sum(1 for k, v in leaderboard.items() if v > total_xp) + 1

    return {
        "status": "success",
        "username": operator_id,
        "email": f"{operator_id.lower()}@ultracrypto.io",
        "rank": rank_num,
        "level": get_level(total_xp),
        "xp": total_xp,
        "xpToNextLevel": progress.get("needed", 1000),
        "rankTitle": progress["current"],
        "nextRank": progress.get("next"),
        "badges": badges,
        "joinDate": "2025-01-01",
    }


@app.get("/dashboard/stats")
async def get_dashboard_stats():
    solved_all = len(leaderboard)
    unique_users = len({k.split("_")[0] for k in leaderboard}) if leaderboard else 0

    db_users = 0
    db_logs = 0
    db_payments = 0
    db_syncs = 0
    db_images = 0
    try:
        if db is not None:
            db_users = await db["users"].count_documents({})
            db_logs = await db["forensic_logs"].count_documents({})
            db_payments = await db["payments"].count_documents({})
            db_syncs = await db["stego_syncs"].count_documents({})
            db_images = await db["secure_images"].count_documents({})
    except Exception:
        pass

    return {
        "status": "success",
        "totalUsers": max(unique_users, db_users),
        "activeSessions": unique_users,
        "ctfChallengesSolved": solved_all,
        "totalEncryptions": solved_all * 3 + db_syncs + db_images,
        "totalAuditLogs": db_logs,
        "totalPayments": db_payments,
        "totalSyncs": db_syncs,
        "uptime": "99.9%",
        "activeSubscriptions": 1,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)