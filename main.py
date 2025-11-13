import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI(title="Medi-Friend API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Helpers ----------
SALT = os.getenv("AUTH_SALT", "medi-friend-demo-salt")

def hash_password(password: str) -> str:
    return hashlib.sha256((password + SALT).encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ist_now() -> datetime:
    # IST is UTC+5:30
    return utc_now() + timedelta(hours=5, minutes=30)


def require_db():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")


def get_user_by_email(email: str):
    require_db()
    return db["user"].find_one({"email": email})


# ---------- Auth Models ----------
class SignupIn(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    token: str
    name: str
    email: EmailStr
    notifications_enabled: bool

class SettingsIn(BaseModel):
    notifications_enabled: Optional[bool] = None

class ForgotIn(BaseModel):
    email: EmailStr

class ResetIn(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str


# ---------- Medication Models ----------
class MedicationIn(BaseModel):
    name: str
    dosage: str
    time_12h: str  # e.g., 08:30 PM
    frequency: str  # daily | alternate | weekly
    notes: Optional[str] = None

class MedicationOut(BaseModel):
    id: str
    name: str
    dosage: str
    time_12h: str
    frequency: str
    notes: Optional[str] = None
    last_taken_at: Optional[datetime] = None
    snooze_until_utc: Optional[datetime] = None


# ---------- Auth Dependency ----------
async def get_current_user(authorization: Optional[str] = Header(None)):
    require_db()
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    sess = db["session"].find_one({"token": token})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["user"].find_one({"_id": ObjectId(sess["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # expire check
    if sess.get("expires_at") and sess["expires_at"] < utc_now():
        db["session"].delete_one({"_id": sess["_id"]})
        raise HTTPException(status_code=401, detail="Session expired")
    return {"_id": str(user["_id"]), "name": user["name"], "email": user["email"], "notifications_enabled": user.get("notifications_enabled", True)}


# ---------- Routes ----------
@app.get("/")
def read_root():
    return {"message": "Medi-Friend API is running"}


@app.post("/auth/signup", response_model=TokenOut)
def signup(payload: SignupIn):
    require_db()
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "notifications_enabled": True,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    user_id = db["user"].insert_one(user_doc).inserted_id
    token = secrets.token_urlsafe(32)
    db["session"].insert_one({
        "user_id": str(user_id),
        "token": token,
        "created_at": utc_now(),
        "expires_at": utc_now() + timedelta(days=7)
    })
    return TokenOut(token=token, name=payload.name, email=payload.email, notifications_enabled=True)


@app.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn):
    require_db()
    user = get_user_by_email(payload.email)
    if not user or user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    db["session"].insert_one({
        "user_id": str(user["_id"]),
        "token": token,
        "created_at": utc_now(),
        "expires_at": utc_now() + timedelta(days=7)
    })
    return TokenOut(token=token, name=user["name"], email=user["email"], notifications_enabled=user.get("notifications_enabled", True))


@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    require_db()
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        db["session"].delete_one({"token": token})
    return {"ok": True}


@app.post("/auth/forgot")
def forgot(payload: ForgotIn):
    require_db()
    user = get_user_by_email(payload.email)
    if not user:
        # Don't reveal
        return {"ok": True}
    reset_token = secrets.token_urlsafe(8)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"reset_token": reset_token, "reset_token_expires": utc_now() + timedelta(hours=1)}})
    # In real app, email this. For demo, return it.
    return {"ok": True, "reset_token": reset_token}


@app.post("/auth/reset")
def reset(payload: ResetIn):
    require_db()
    user = get_user_by_email(payload.email)
    if not user or user.get("reset_token") != payload.reset_token or user.get("reset_token_expires") < utc_now():
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": hash_password(payload.new_password)}, "$unset": {"reset_token": "", "reset_token_expires": ""}})
    return {"ok": True}


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user


@app.put("/me/settings")
def update_settings(settings: SettingsIn, user=Depends(get_current_user)):
    require_db()
    updates = {}
    if settings.notifications_enabled is not None:
        updates["notifications_enabled"] = settings.notifications_enabled
    if not updates:
        return user
    db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$set": updates})
    return {**user, **updates}


# ---- Medications ----
@app.get("/medications", response_model=List[MedicationOut])
def list_meds(user=Depends(get_current_user)):
    require_db()
    meds = list(db["medication"].find({"user_id": user["_id"]}).sort("created_at", 1))
    result = []
    for m in meds:
        result.append({
            "id": str(m["_id"]),
            "name": m["name"],
            "dosage": m["dosage"],
            "time_12h": m["time_12h"],
            "frequency": m["frequency"],
            "notes": m.get("notes"),
            "last_taken_at": m.get("last_taken_at"),
            "snooze_until_utc": m.get("snooze_until_utc"),
        })
    return result


@app.post("/medications", response_model=MedicationOut)
def create_med(med: MedicationIn, user=Depends(get_current_user)):
    require_db()
    doc = {
        "user_id": user["_id"],
        "name": med.name,
        "dosage": med.dosage,
        "time_12h": med.time_12h.upper(),
        "frequency": med.frequency,
        "notes": med.notes,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    _id = db["medication"].insert_one(doc).inserted_id
    return {
        "id": str(_id),
        "name": doc["name"],
        "dosage": doc["dosage"],
        "time_12h": doc["time_12h"],
        "frequency": doc["frequency"],
        "notes": doc.get("notes"),
        "last_taken_at": None,
        "snooze_until_utc": None,
    }


@app.put("/medications/{med_id}", response_model=MedicationOut)
def update_med(med_id: str, med: MedicationIn, user=Depends(get_current_user)):
    require_db()
    m = db["medication"].find_one({"_id": ObjectId(med_id), "user_id": user["_id"]})
    if not m:
        raise HTTPException(status_code=404, detail="Not found")
    updates = {
        "name": med.name,
        "dosage": med.dosage,
        "time_12h": med.time_12h.upper(),
        "frequency": med.frequency,
        "notes": med.notes,
        "updated_at": utc_now(),
    }
    db["medication"].update_one({"_id": m["_id"]}, {"$set": updates})
    m.update(updates)
    return {
        "id": str(m["_id"]),
        "name": m["name"],
        "dosage": m["dosage"],
        "time_12h": m["time_12h"],
        "frequency": m["frequency"],
        "notes": m.get("notes"),
        "last_taken_at": m.get("last_taken_at"),
        "snooze_until_utc": m.get("snooze_until_utc"),
    }


@app.delete("/medications/{med_id}")
def delete_med(med_id: str, user=Depends(get_current_user)):
    require_db()
    db["medication"].delete_one({"_id": ObjectId(med_id), "user_id": user["_id"]})
    return {"ok": True}


@app.post("/medications/{med_id}/taken")
def mark_taken(med_id: str, user=Depends(get_current_user)):
    require_db()
    m = db["medication"].find_one({"_id": ObjectId(med_id), "user_id": user["_id"]})
    if not m:
        raise HTTPException(status_code=404, detail="Not found")
    db["medication"].update_one({"_id": m["_id"]}, {"$set": {"last_taken_at": utc_now(), "snooze_until_utc": None, "updated_at": utc_now()}})
    return {"ok": True}


@app.post("/medications/{med_id}/snooze")
def snooze(med_id: str, user=Depends(get_current_user)):
    require_db()
    m = db["medication"].find_one({"_id": ObjectId(med_id), "user_id": user["_id"]})
    if not m:
        raise HTTPException(status_code=404, detail="Not found")
    db["medication"].update_one({"_id": m["_id"]}, {"$set": {"snooze_until_utc": utc_now() + timedelta(minutes=10), "updated_at": utc_now()}})
    return {"ok": True, "snooze_until_utc": (utc_now() + timedelta(minutes=10)).isoformat()}


# ---- Drug Info Proxy ----
import requests

@app.get("/drug-info")
def drug_info(q: str):
    # Proxy to OpenFDA label endpoint
    try:
        url = "https://api.fda.gov/drug/label.json"
        params = {"search": f"openfda.brand_name:{q}+openfda.generic_name:{q}", "limit": 1}
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        if not data.get("results"):
            return {"found": False}
        res = data["results"][0]
        return {
            "found": True,
            "purpose": (res.get("indications_and_usage") or [None])[0],
            "side_effects": (res.get("adverse_reactions") or [None])[0],
            "dosage": (res.get("dosage_and_administration") or [None])[0],
            "source": "OpenFDA"
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
