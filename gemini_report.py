import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = "models/gemini-2.5-flash"

ENDPOINT = (
    f"https://generativelanguage.googleapis.com/v1/"
    f"{MODEL_NAME}:generateContent?key={API_KEY}"
)

# In-memory cache to avoid repeated API calls
REPORT_CACHE = {}
QA_CACHE = {}


def _call_gemini(payload):
    try:
        r = requests.post(ENDPOINT, json=payload, timeout=20)
        if r.status_code != 200:
            return None
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return None


def generate_url_report(url, label, score):
    # ✅ If already generated, return cached report
    if url in REPORT_CACHE:
        return REPORT_CACHE[url]

    status = "Phishing" if label == 1 else "Legitimate"

    payload = {
        "contents": [{
            "parts": [{
                "text": f"""
You are a cybersecurity expert.

Generate a short, simple security report.
Use plain text only.
Do NOT use symbols like # or *.

URL: {url}
ML Result: {status}
Confidence: {score}%

Format exactly like this:

Risk Level:
Low or High

Why:
(one short reason)

Possible Risks:
- one short point

Safety Tips:
- one short tip

Final Verdict:
(one short sentence)
"""
            }]
        }]
    }

    text = _call_gemini(payload)

    # ❌ Gemini unavailable (quota / rate limit)
    if not text:
        fallback = (
            "Risk Level:\n"
            "Unknown\n\n"
            "Why:\n"
            "AI analysis is temporarily unavailable.\n\n"
            "Possible Risks:\n"
            "- Cannot assess AI-based risks right now\n\n"
            "Safety Tips:\n"
            "- Be cautious before interacting with this site\n\n"
            "Final Verdict:\n"
            "Machine learning result shown above should be considered."
        )
        REPORT_CACHE[url] = fallback
        return fallback

    REPORT_CACHE[url] = text
    return text


def ask_gemini_about_url(url, label, score, question):
    cache_key = f"{url}:{question}"

    # ✅ Cache Q&A to avoid repeated calls
    if cache_key in QA_CACHE:
        return QA_CACHE[cache_key]

    status = "Phishing" if label == 1 else "Legitimate"

    payload = {
        "contents": [{
            "parts": [{
                "text": f"""
You are a cybersecurity assistant.

Context:
URL: {url}
ML Result: {status}
Confidence: {score}%

User Question:
{question}

Rules:
- Do NOT contradict the ML result shown in UI
- If ML says Legitimate, treat it as generally safe
- If ML says Phishing, warn user
- Give balanced, general advice
- Keep response short
"""
            }]
        }]
    }

    text = _call_gemini(payload)

    if not text:
        fallback = (
            "AI response is temporarily unavailable due to usage limits. "
            "Please rely on the ML result shown above and proceed carefully."
        )
        QA_CACHE[cache_key] = fallback
        return fallback

    QA_CACHE[cache_key] = text
    return text
