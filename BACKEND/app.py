import csv
import datetime as dt
import os
import re
import uuid
from functools import wraps

import jwt
import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from supabase import create_client
except Exception:  # pragma: no cover - optional dependency for local CSV fallback
    create_client = None


load_dotenv()

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
COUNTRIES_CSV = os.path.join(DATA_DIR, "countries.csv")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")

SECRET_KEY = os.getenv("SECRET_KEY", "amaan-app-secret")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "") or os.getenv("SUPABASE_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_STT_MODEL = os.getenv("GROQ_STT_MODEL", "whisper-large-v3-turbo")

app = Flask(__name__)
CORS(app, origins=os.getenv("CORS_ORIGINS", "*").split(","))

supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY and create_client:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

USERS = {}
COUNTRIES = []
APPLICATIONS = []
RATE_LIMIT = {}
POLICIES = [
    {"id": "budget", "name": "Budget Start", "price": 9, "currency": "BHD", "features": ["Basic medical support", "Trip interruption help", "Digital travel certificate"]},
    {"id": "essential", "name": "Essential Cover", "price": 12, "currency": "BHD", "features": ["Visa-ready certificate", "Emergency medical", "Trip delay"]},
    {"id": "smart", "name": "Smart Travel Plus", "price": 24, "currency": "BHD", "features": ["Higher medical limit", "Baggage delay", "Flight disruption"]},
    {"id": "explorer", "name": "Explorer Secure", "price": 31, "currency": "BHD", "features": ["Adventure activity support", "Higher baggage limit", "Emergency medical upgrade"]},
    {"id": "premium", "name": "Premium Shield", "price": 39, "currency": "BHD", "features": ["Medical evacuation", "High-risk destination support", "Priority support"]},
    {"id": "family", "name": "Family Comfort", "price": 45, "currency": "BHD", "features": ["Family-focused cover", "Child medical support", "Flexible trip changes"]},
]


def load_demo_data():
    USERS.clear()
    COUNTRIES.clear()

    load_users_from_csv()
    if not load_countries_from_supabase():
        load_countries_from_csv()


def load_users_from_csv():
    with open(USERS_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            full_name = row.get("full_name") or row.get("name") or ""
            USERS[row["email"].lower()] = {
                "id": str(uuid.uuid4()),
                "email": row["email"].lower(),
                "first_name": row.get("first_name") or (full_name.split(" ")[0] if full_name else ""),
                "last_name": row.get("last_name") or (" ".join(full_name.split(" ")[1:]) if full_name and len(full_name.split(" ")) > 1 else ""),
                "password_hash": generate_password_hash(row["password"]),
                "role": row.get("role", "user"),
                "mfa_enabled": True,
                "mfa_code": "123456",
                "consent": True,
            }


def persist_user_to_csv(email, password, role="user"):
    existing = set()
    if os.path.exists(USERS_CSV):
        with open(USERS_CSV, newline="", encoding="utf-8") as handle:
            existing = {row.get("email", "").lower() for row in csv.DictReader(handle)}
    if email.lower() in existing:
        return
    with open(USERS_CSV, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["email", "password", "role"])
        writer.writerow({"email": email.lower(), "password": password, "role": role})


def load_countries_from_csv():
    with open(COUNTRIES_CSV, newline="", encoding="utf-8") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=1):
            COUNTRIES.append(normalize_country(row, index))


def load_countries_from_supabase():
    if not supabase:
        return False
    for table in ("countries", "Countries"):
        try:
            response = supabase.table(table).select("*").execute()
            rows = getattr(response, "data", None) or []
            if not rows:
                continue
            COUNTRIES.extend(normalize_country(row, index) for index, row in enumerate(rows, start=1))
            return True
        except Exception:
            continue
    return False


def normalize_country(row, index):
    risk = row.get("risk") or row.get("Risk") or "Low"
    medical = int(row.get("medical") or row.get("Medical") or 3)
    safety = int(row.get("safety") or row.get("Safety") or 3)
    disaster = int(row.get("disaster") or row.get("Disaster") or 2)
    score = medical + safety + disaster
    return {
        "id": int(row.get("id") or index),
        "name": row.get("name") or row.get("Name") or "Unknown",
        "visa": row.get("visa") or row.get("Visa") or "Check required",
        "insurance": row.get("insurance") or row.get("Insurance") or "Recommended",
        "risk": risk,
        "medical": medical,
        "safety": safety,
        "disaster": disaster,
        "description": row.get("description") or row.get("Description") or "Travel information available in Amaan.",
        "recommendation": row.get("recommendation") or row.get("Recommendation") or recommendation_for(risk, score),
    }


def recommendation_for(risk, score):
    if risk == "High" or score >= 18:
        return "Choose Premium Shield with medical evacuation and disruption cover."
    if risk == "Medium" or score >= 12:
        return "Choose Smart Travel Plus with medical, baggage, and delay benefits."
    return "Choose Essential Cover for visa-ready medical and trip protection."


load_demo_data()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "form-action 'self'"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.before_request
def simple_rate_limit():
    key = request.headers.get("X-Forwarded-For", request.remote_addr or "local")
    minute = dt.datetime.utcnow().strftime("%Y%m%d%H%M")
    bucket = f"{key}:{minute}"
    RATE_LIMIT[bucket] = RATE_LIMIT.get(bucket, 0) + 1
    if RATE_LIMIT[bucket] > 120:
        return jsonify({"error": "Too many requests. Please try again soon."}), 429


def make_token(user):
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": dt.datetime.utcnow() + dt.timedelta(hours=8),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        payload = jwt.decode(auth.replace("Bearer ", ""), SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return USERS.get(payload.get("email", "").lower())


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        return fn(user, *args, **kwargs)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        if user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return fn(user, *args, **kwargs)
    return wrapper


def clean_text(value, max_len=500):
    value = str(value or "").strip()
    value = re.sub(r"[<>]", "", value)
    return value[:max_len]


@app.get("/health")
def health():
    return jsonify({"status": "ok", "supabase": bool(supabase)})


@app.post("/api/auth/signup")
def signup():
    body = request.get_json(force=True)
    email = clean_text(body.get("email"), 120).lower()
    first_name = clean_text(body.get("firstName"), 60)
    last_name = clean_text(body.get("lastName"), 80)
    password = str(body.get("password", ""))
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Valid email required"}), 400
    if not first_name:
        return jsonify({"error": "First name is required"}), 400
    if not last_name:
        return jsonify({"error": "Last name is required"}), 400
    if len(password) != 4 or not password.isdigit():
        return jsonify({"error": "Password must be exactly 4 digits"}), 400
    if email in USERS:
        return jsonify({"error": "Email already exists"}), 409
    USERS[email] = {
        "id": str(uuid.uuid4()),
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "password_hash": generate_password_hash(password),
        "role": "user",
        "mfa_enabled": True,
        "mfa_code": "123456",
        "consent": bool(body.get("consent", False)),
    }
    persist_user_to_csv(email, password)
    token = make_token(USERS[email])
    return jsonify({"token": token, "user": public_user(USERS[email]), "mfaRequired": True})


@app.post("/api/auth/login")
def login():
    body = request.get_json(force=True)
    email = clean_text(body.get("email"), 120).lower()
    password = str(body.get("password", ""))
    user = USERS.get(email)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401
    token = make_token(user)
    return jsonify({"token": token, "user": public_user(user), "mfaRequired": user["mfa_enabled"]})


@app.post("/api/auth/mfa/verify")
@require_auth
def verify_mfa(user):
    code = clean_text(request.get_json(force=True).get("code"), 10)
    if code != user["mfa_code"]:
        return jsonify({"error": "Invalid MFA code. Use 123456."}), 400
    return jsonify({"verified": True})


@app.get("/api/countries")
def list_countries():
    return jsonify(COUNTRIES)


@app.post("/api/countries")
@require_admin
def add_country(_user):
    body = request.get_json(force=True)
    country = {
        "id": max([c["id"] for c in COUNTRIES] or [0]) + 1,
        "name": clean_text(body.get("name"), 80),
        "visa": clean_text(body.get("visa"), 120),
        "insurance": clean_text(body.get("insurance"), 120),
        "risk": clean_text(body.get("risk"), 20) or "Low",
        "medical": int(body.get("medical", 3)),
        "safety": int(body.get("safety", 3)),
        "disaster": int(body.get("disaster", 2)),
        "description": clean_text(body.get("description"), 500),
    }
    country["recommendation"] = recommendation_for(country["risk"], country["medical"] + country["safety"] + country["disaster"])
    COUNTRIES.append(country)
    return jsonify(country), 201


@app.delete("/api/countries/<int:country_id>")
@require_admin
def delete_country(_user, country_id):
    global COUNTRIES
    COUNTRIES = [country for country in COUNTRIES if country["id"] != country_id]
    return jsonify({"deleted": True})


@app.put("/api/countries/<int:country_id>")
@require_admin
def update_country(_user, country_id):
    body = request.get_json(force=True)
    for country in COUNTRIES:
        if country["id"] == country_id:
            for field in ("name", "visa", "insurance", "risk", "description"):
                if field in body:
                    country[field] = clean_text(body.get(field), 500)
            for field in ("medical", "safety", "disaster"):
                if field in body:
                    country[field] = max(1, min(10, int(body.get(field) or 1)))
            country["recommendation"] = recommendation_for(country["risk"], country["medical"] + country["safety"] + country["disaster"])
            return jsonify(country)
    return jsonify({"error": "Country not found"}), 404


@app.get("/api/policies")
def policies():
    return jsonify(POLICIES)


@app.post("/api/policies")
@require_admin
def add_policy(_user):
    body = request.get_json(force=True)
    policy = normalize_policy(body)
    policy["id"] = clean_text(body.get("id"), 40) or uuid.uuid4().hex[:8]
    POLICIES.append(policy)
    return jsonify(policy), 201


@app.put("/api/policies/<policy_id>")
@require_admin
def update_policy(_user, policy_id):
    body = request.get_json(force=True)
    for index, policy in enumerate(POLICIES):
        if policy["id"] == policy_id:
            updated = normalize_policy({**policy, **body})
            updated["id"] = policy_id
            POLICIES[index] = updated
            return jsonify(updated)
    return jsonify({"error": "Policy not found"}), 404


@app.delete("/api/policies/<policy_id>")
@require_admin
def delete_policy(_user, policy_id):
    global POLICIES
    POLICIES = [policy for policy in POLICIES if policy["id"] != policy_id]
    return jsonify({"deleted": True})


def normalize_policy(row):
    features = row.get("features") or []
    if isinstance(features, str):
        features = [item.strip() for item in features.split(",") if item.strip()]
    return {
        "name": clean_text(row.get("name"), 100) or "Travel Policy",
        "price": float(row.get("price") or 0),
        "currency": clean_text(row.get("currency"), 8) or "BHD",
        "features": features[:8] or ["Medical cover", "Trip support"],
    }


@app.post("/api/applications")
@require_auth
def create_application(user):
    body = request.get_json(force=True)
    app_record = {
        "id": f"AMAAN-{uuid.uuid4().hex[:8].upper()}",
        "email": user["email"],
        "country": clean_text(body.get("country"), 80),
        "policy": clean_text(body.get("policy"), 80),
        "travelDate": clean_text(body.get("travelDate"), 40),
        "status": "Policy issued",
        "createdAt": dt.datetime.utcnow().isoformat() + "Z",
    }
    APPLICATIONS.append(app_record)
    return jsonify(app_record), 201


@app.post("/api/chatbot/recommend")
def chatbot_recommend():
    body = request.get_json(force=True)
    message = clean_text(body.get("message"), 600)
    destination = clean_text(body.get("destination"), 80)
    history = clean_chat_messages(body.get("messages"), latest_message=message)
    context = clean_chat_context(body.get("context"))
    match = resolve_chat_country(message, destination, context)

    ai_answer = groq_chatbot_answer(history, match, context)
    if ai_answer:
        return jsonify({"answer": ai_answer})

    return jsonify({"answer": fallback_chatbot_answer(message, match)})


@app.post("/api/chatbot/stream")
def chatbot_stream():
    body = request.get_json(force=True)
    message = clean_text(body.get("message"), 600)
    destination = clean_text(body.get("destination"), 80)
    history = clean_chat_messages(body.get("messages"), latest_message=message)
    context = clean_chat_context(body.get("context"))
    match = resolve_chat_country(message, destination, context)

    def event_stream():
        streamed = False
        for chunk in groq_chatbot_stream(history, match, context):
            streamed = True
            safe_chunk = chunk.replace("\r", " ").replace("\n", " ")
            yield f"data: {safe_chunk}\n\n"
        if streamed:
            yield "event: done\ndata: [DONE]\n\n"
            return
        fallback = fallback_chatbot_answer(message, match)
        for word in fallback.split(" "):
            yield f"data: {word} \n\n"
        yield "event: done\ndata: [DONE]\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@app.post("/api/chatbot/voice")
def chatbot_voice():
    audio = request.files.get("audio")
    if not audio:
        return jsonify({"error": "Audio file required"}), 400
    transcript = transcribe_chat_audio(audio)
    if not transcript:
        return jsonify({"error": "Could not transcribe voice message"}), 502
    return jsonify({"transcript": transcript})


def fallback_chatbot_answer(message, country):
    lower_message = (message or "").lower()
    if country and any(keyword in lower_message for keyword in ("best", "spot", "place", "visit", "cycling", "bike", "food", "beach", "family", "hotel", "activity", "things to do")):
        return (
            f"For {country['name']}, I would plan around well-connected, traveler-friendly areas and check local safety, weather, and transport before booking. "
            f"For cycling or outdoor plans, choose marked routes, avoid peak traffic, carry medical cover, and keep emergency hospital details saved in Amaan. "
            f"If you tell me the city and trip style, I can narrow it to specific routes or neighborhoods."
        )
    if country and any(keyword in lower_message for keyword in ("visa", "country", "destination", "policy", "travel", "trip", "cover", "hospital", "safe", "risk")):
        return (
            f"For {country['name']}, visa status is {country['visa']} and risk is {country['risk']}. "
            f"{country['recommendation']} Ask if you want policies, documents, claims, payment, or safety details."
        )
    if any(keyword in lower_message for keyword in ("write", "draft", "email", "message", "caption")):
        return (
            "I can help with general writing too. Tell me what you want to write and the tone you want, "
            "and I will draft it for you."
        )
    if any(keyword in lower_message for keyword in ("explain", "what is", "how does", "difference", "compare")):
        return (
            "I can answer general questions and Amaan travel questions. Ask directly and I will keep the answer clear, short, and useful."
        )
    if any(keyword in lower_message for keyword in ("price", "cost", "cheap", "budget", "policy", "cover")):
        return (
            "Amaan cover starts at 9 BHD for Budget Start, 12 BHD for Essential Cover, 24 BHD for Smart Travel Plus, "
            "31 BHD for Explorer Secure, 39 BHD for Premium Shield, and 45 BHD for Family Comfort. "
            "Tell me your destination, travelers, and dates if you want a tailored suggestion."
        )
    if any(keyword in lower_message for keyword in ("claim", "refund", "cancel", "delay", "baggage")):
        return (
            "I can help with claims, delays, baggage issues, cancellations, and what each plan includes. "
            "If you share the trip details, I can point you to the best cover quickly."
        )
    if any(keyword in lower_message for keyword in ("hello", "hi", "hey", "help")):
        return (
            "I can help with travel insurance, visas, destinations, policy comparison, payments, claims, "
            "documents, privacy, and how to use the app."
        )
    return (
        "Ask me anything. I can help with travel cover, visas, policy prices, documents, claims, payments, safety, "
        "trip planning, and general questions too. If you want a recommendation, share your destination, dates, and traveler count."
    )


def clean_chat_messages(raw_messages, latest_message=""):
    cleaned = []
    if isinstance(raw_messages, list):
        for item in raw_messages[-16:]:
            if not isinstance(item, dict):
                continue
            role = item.get("role")
            if role not in ("user", "assistant"):
                continue
            content = clean_text(item.get("content"), 2000)
            if not content:
                continue
            cleaned.append(
                {
                    "role": role,
                    "content": content,
                }
            )
    latest = clean_text(latest_message, 600)
    if latest and (not cleaned or cleaned[-1]["content"] != latest):
        cleaned.append(
            {
                "role": "user",
                "content": latest,
            }
        )
    return cleaned


def clean_chat_context(raw_context):
    if not isinstance(raw_context, dict):
        return {}
    return {
        "user": raw_context.get("user") if isinstance(raw_context.get("user"), dict) else {},
        "selectedCountry": raw_context.get("selectedCountry") if isinstance(raw_context.get("selectedCountry"), dict) else {},
        "selectedPolicy": raw_context.get("selectedPolicy") if isinstance(raw_context.get("selectedPolicy"), dict) else {},
    }


def resolve_chat_country(message, destination, context):
    selected_country = context.get("selectedCountry") if isinstance(context, dict) else {}
    context_destination = clean_text(selected_country.get("name") if isinstance(selected_country, dict) else "", 80)
    candidates = [destination, context_destination]
    lower_message = (message or "").lower()
    for candidate in candidates:
        if candidate:
            match = next((c for c in COUNTRIES if c["name"].lower() == candidate.lower()), None)
            if match:
                return match
    if message:
        return next((c for c in COUNTRIES if c["name"].lower() in lower_message), None)
    return None


def groq_messages(history, country, context, instructions):
    knowledge_base = {
        "countries": COUNTRIES[:80],
        "policies": POLICIES,
        "selectedCountry": country,
        "appContext": context,
    }
    messages = [
        {
            "role": "system",
            "content": instructions,
        },
        {
            "role": "system",
            "content": (
                "Use this Amaan app context as private grounding data. "
                "Do not dump it to the user; use it to answer specifically and avoid repeating canned country summaries. "
                f"{knowledge_base}"
            ),
        },
    ]
    messages.extend(history[-14:])
    return messages


def chat_provider():
    if GROQ_API_KEY:
        return {
            "url": "https://api.groq.com/openai/v1/chat/completions",
            "key": GROQ_API_KEY,
            "model": GROQ_MODEL,
            "timeout": 7,
        }
    return None


def groq_chatbot_answer(history, country, context):
    provider = chat_provider()
    if not provider:
        return None
    instructions = chatbot_instructions()
    try:
        response = requests.post(
            provider["url"],
            headers={
                "Authorization": f"Bearer {provider['key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": provider["model"],
                "messages": groq_messages(history, country, context, instructions),
                "temperature": 0.55,
                "max_tokens": 280,
            },
            timeout=provider["timeout"],
        )
        response.raise_for_status()
        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content")
    except requests.RequestException:
        return None
    return None


def groq_chatbot_stream(history, country, context):
    provider = chat_provider()
    if not provider:
        return
    instructions = chatbot_instructions()
    try:
        with requests.post(
            provider["url"],
            headers={
                "Authorization": f"Bearer {provider['key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": provider["model"],
                "messages": groq_messages(history, country, context, instructions),
                "temperature": 0.55,
                "max_tokens": 280,
                "stream": True,
            },
            timeout=provider["timeout"],
            stream=True,
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data: "):
                    continue
                payload = line[6:]
                if payload == "[DONE]":
                    break
                try:
                    event = json_loads(payload)
                except ValueError:
                    continue
                delta = event.get("choices", [{}])[0].get("delta", {}).get("content", "")
                if delta:
                    yield delta
    except requests.RequestException:
        return


def transcribe_chat_audio(audio_file):
    if not GROQ_API_KEY:
        return None
    url = "https://api.groq.com/openai/v1/audio/transcriptions"
    key = GROQ_API_KEY
    model = GROQ_STT_MODEL
    filename = audio_file.filename or "voice.m4a"
    content_type = audio_file.mimetype or "audio/mp4"
    try:
        response = requests.post(
            url,
            headers={"Authorization": f"Bearer {key}"},
            data={"model": model, "language": "en"},
            files={"file": (filename, audio_file.stream, content_type)},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        return clean_text(data.get("text"), 1200)
    except requests.RequestException:
        return None


def chatbot_instructions():
    return (
        "You are Amaan's AI assistant inside a travel insurance app, but behave like a fast, natural ChatGPT-style assistant. "
        "Use conversation memory, answer the exact user question, and avoid repeating the same country summary unless the user asks for it. "
        "If a selected country is provided, use it as context for travel, visa, risk, hospital, and policy questions. "
        "If the user changes topic or asks a general question, answer normally without forcing travel context. "
        "Be warm, direct, specific, and practical. Prefer concise answers, but explain when useful. "
        "Format most answers as short bullet points with a clear recommendation line when relevant. "
        "Recommend Amaan policies only when the user asks about cover, insurance, trip protection, claims, price, or policy choice. "
        "Never claim a real payment, policy issuance, visa approval, medical outcome, or legal result is guaranteed. "
        "Never ask for full card data, passwords, API keys, or sensitive secrets in chat. "
        "Respond in English unless the user asks for Arabic or writes Arabic."
    )


def json_loads(payload):
    import json

    return json.loads(payload)


@app.get("/api/admin/users")
@require_admin
def admin_users(_user):
    return jsonify([public_user(user) for user in USERS.values()])


@app.put("/api/admin/users/<email>")
@require_admin
def update_user(_user, email):
    target = USERS.get(email.lower())
    if not target:
        return jsonify({"error": "User not found"}), 404
    body = request.get_json(force=True)
    if "role" in body:
        target["role"] = clean_text(body.get("role"), 20)
    if "consent" in body:
        target["consent"] = bool(body.get("consent"))
    return jsonify(public_user(target))


@app.delete("/api/admin/users/<email>")
@require_admin
def delete_user(_user, email):
    USERS.pop(email.lower(), None)
    return jsonify({"deleted": True})


@app.delete("/api/me")
@require_auth
def delete_me(user):
    USERS.pop(user["email"], None)
    return jsonify({"deleted": True, "message": "Account deleted for privacy request."})


def public_user(user):
    first_name = user.get("first_name", "")
    last_name = user.get("last_name", "")
    full_name = f"{first_name} {last_name}".strip()
    if not full_name:
        full_name = user["email"].split("@")[0].replace(".", " ").title()
    return {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "consent": user.get("consent", False),
        "firstName": first_name,
        "lastName": last_name,
        "fullName": full_name,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
