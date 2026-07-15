import base64
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

import dns.resolver
import requests
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from google import genai

from app.database import connect_to_mongo, close_mongo_connection, scans_collection, raw_collection
from app.logger import setup_logging, get_logger, new_correlation_id, StageTimer
from app.admin.routes import router as admin_router

load_dotenv()
setup_logging()
log = get_logger("phish_raksha")

VT_API_KEY = os.getenv("VT_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "dev-only-insecure-key")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]

if GEMINI_API_KEY:
    log.info("Initializing Gemini client", extra={"extra_fields": {"event": "startup.gemini_init"}})
    ai_client = genai.Client(api_key=GEMINI_API_KEY)
else:
    log.warning("GEMINI_API_KEY not set -- AI verdicts will be unavailable",
                extra={"extra_fields": {"event": "startup.gemini_missing_key"}})
    ai_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Connecting to MongoDB Atlas", extra={"extra_fields": {"event": "startup.mongo_connect"}})
    await connect_to_mongo()
    log.info("MongoDB connected", extra={"extra_fields": {"event": "startup.mongo_connected"}})
    yield
    await close_mongo_connection()


app = FastAPI(title="Phish Raksha Security Engine", lifespan=lifespan)

app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)


class EmailAnalysisRequest(BaseModel):
    sender_email: str
    headers: str
    urls: List[str]
    scanned_by: Optional[str] = None      # Office.js userProfile.emailAddress
    body_html: Optional[str] = ""         # raw email body, for the admin "Source" view only
    body_text: Optional[str] = ""


# ---------------------------------------------------------------------------
# Analysis functions (same logic as before; each now also returns the raw
# upstream payload so it can be persisted separately for the admin dashboard)
# ---------------------------------------------------------------------------

def parse_authentication_results(headers: str) -> dict:
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    if not headers or headers.strip() == "":
        log.warning("Empty headers block received from client",
                    extra={"extra_fields": {"event": "parse_auth.empty_headers"}})
        return results

    auth_lines = re.findall(
        r"Authentication-Results:[\s\S]*?(?=\r?\n[A-Za-z][^\s]|$)",
        headers,
        re.IGNORECASE
    )

    for block in auth_lines:
        if results["spf"] == "unknown":
            m = re.search(r"\bspf\s*=\s*([a-zA-Z]+)", block, re.IGNORECASE)
            if m:
                results["spf"] = m.group(1).lower()
        if results["dkim"] == "unknown":
            m = re.search(r"\bdkim\s*=\s*([a-zA-Z]+)", block, re.IGNORECASE)
            if m:
                results["dkim"] = m.group(1).lower()
        if results["dmarc"] == "unknown":
            m = re.search(r"\bdmarc\s*=\s*([a-zA-Z]+)", block, re.IGNORECASE)
            if m:
                results["dmarc"] = m.group(1).lower()

    log.info("Parsed authentication results", extra={"extra_fields": {
        "event": "parse_auth.completed", "auth_blocks_found": len(auth_lines), "result": results
    }})
    return results


def check_domain_dns_policy(domain: str) -> tuple[dict, dict]:
    policies = {"has_spf": False, "has_dmarc": False, "spf_policy": "none", "dmarc_policy": "none"}
    raw = {"spf_txt_records": [], "dmarc_txt_records": [], "errors": []}

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = "".join(b.decode('utf-8') for b in rdata.strings)
            raw["spf_txt_records"].append(txt_record)
            if "v=spf1" in txt_record:
                policies["has_spf"] = True
                if "-all" in txt_record:
                    policies["spf_policy"] = "strict"
                elif "~all" in txt_record:
                    policies["spf_policy"] = "softfail"
                else:
                    policies["spf_policy"] = "permissive"
    except Exception as e:
        raw["errors"].append(f"SPF lookup failed: {e}")

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt_record = "".join(b.decode('utf-8') for b in rdata.strings)
            raw["dmarc_txt_records"].append(txt_record)
            if "v=DMARC1" in txt_record:
                policies["has_dmarc"] = True
                p_m = re.search(r"\bp\s*=\s*([a-zA-Z]+)", txt_record)
                policies["dmarc_policy"] = p_m.group(1).lower() if p_m else "none"
    except Exception as e:
        raw["errors"].append(f"DMARC lookup failed: {e}")

    log.info("DNS policy check completed", extra={"extra_fields": {
        "event": "dns_check.completed", "domain": domain, "policies": policies
    }})
    return policies, raw


def base64_url_encode(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def analyze_url_with_virustotal(url: str) -> tuple[dict, dict]:
    if not VT_API_KEY:
        log.warning("VT_API_KEY missing -- skipping URL scan",
                    extra={"extra_fields": {"event": "vt.missing_key", "url": url}})
        return {"status": "unscanned", "malicious_count": 0}, {}

    url_id = base64_url_encode(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        res = requests.get(vt_url, headers=headers, timeout=8)
        if res.status_code == 200:
            raw_json = res.json()
            stats = raw_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            summary = {
                "status": "analyzed",
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
            }
            log.info("VirusTotal scan completed", extra={"extra_fields": {
                "event": "vt.completed", "url": url, "stats": stats
            }})
            return summary, raw_json
        else:
            log.warning("VirusTotal returned non-200", extra={"extra_fields": {
                "event": "vt.error_status", "url": url, "status_code": res.status_code
            }})
            return {"status": f"error_{res.status_code}", "malicious_count": 0}, {"status_code": res.status_code}
    except Exception as e:
        log.error("VirusTotal request failed", extra={"extra_fields": {
            "event": "vt.exception", "url": url, "error": str(e)
        }})
        return {"status": "exception_failed", "malicious_count": 0}, {"error": str(e)}


def generate_gemini_verdict(sender: str, auth: dict, dns_p: dict, score: int, reasons: list) -> tuple[str, str]:
    if not ai_client:
        return "Gemini pipeline unavailable: API key not configured.", ""

    prompt = f"""
    Analyze this email threat telemetry profile as a security intelligence engine:
    - Target Sender Address: {sender}
    - Calculated Aggregated Threat Risk Metric: {score}/100
    - Flagged Engine Reason Codes: {", ".join(reasons)}
    - Email Transit Validation: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}
    - DNS Domain Policies: SPF configuration type={dns_p.get('spf_policy')}, DMARC baseline constraint={dns_p.get('dmarc_policy')}

    Provide a summary of up to 3 sentences telling an office employee whether this email is safe to open and why. Be direct.
    """

    try:
        response = ai_client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
        log.info("Gemini verdict generated", extra={"extra_fields": {"event": "gemini.completed"}})
        return response.text, prompt
    except Exception as e:
        log.error("Gemini request failed", extra={"extra_fields": {"event": "gemini.exception", "error": str(e)}})
        return f"AI analysis failed: {e}", prompt


def compute_risk(auth: dict, dns_p: dict, url_r: dict) -> tuple:
    score = 0
    reasons = []

    if auth.get("spf") != "pass":
        score += 15
        reasons.append("SPF result could not be read or verified from email headers.")
    if auth.get("dkim") != "pass":
        score += 15
        reasons.append("DKIM result could not be read or verified from email headers.")
    if auth.get("dmarc") != "pass":
        score += 15
        reasons.append("DMARC result could not be read or verified from email headers.")

    if dns_p.get("spf_policy") == "permissive":
        score += 10
        reasons.append("Sender domain SPF policy is configured to be highly permissive.")
    if dns_p.get("dmarc_policy") == "none":
        score += 10
        reasons.append("Sender domain DMARC policy is 'none' -- no enforcement configured.")

    for url, report in url_r.items():
        malicious = report.get("malicious_count", 0)
        if malicious > 0:
            score += 40
            reasons.append(f"VirusTotal flagged URL ({malicious} engine hits): {url}")

    return min(score, 100), reasons


@app.get("/")
def root():
    return {"status": "running"}


@app.post("/api/analyze")
async def analyze_endpoint(payload: EmailAnalysisRequest):
    scan_id = str(uuid.uuid4())
    correlation_id = new_correlation_id()
    timer = StageTimer()

    log.info("Scan started", extra={"extra_fields": {
        "event": "scan.started", "scan_id": scan_id,
        "scanned_by": payload.scanned_by, "sender_email": payload.sender_email,
        "url_count": len(payload.urls or []),
    }})

    sender = (payload.sender_email or "").strip() or "unknown@unknown"
    domain_match = re.search(r"@([\w.\-]+)", sender)
    domain = domain_match.group(1) if domain_match else ""

    with timer.stage("header_parse"):
        auth_results = parse_authentication_results(payload.headers or "")

    raw_dns = {}
    with timer.stage("dns_lookup"):
        dns_policies, raw_dns = check_domain_dns_policy(domain) if domain else ({}, {})

    url_reports = {}
    raw_vt = {}
    with timer.stage("virustotal"):
        for url in (payload.urls or [])[:5]:
            if url and url.startswith("http"):
                summary, raw_json = analyze_url_with_virustotal(url)
                url_reports[url] = summary
                raw_vt[url] = raw_json

    risk_score, reasons = compute_risk(auth_results, dns_policies, url_reports)
    verdict = "SAFE" if risk_score < 25 else "SUSPICIOUS" if risk_score < 60 else "PHISHING_DETECTED"

    with timer.stage("gemini"):
        ai_analysis, gemini_prompt = generate_gemini_verdict(sender, auth_results, dns_policies, risk_score, reasons)

    stage_latency_ms = timer.as_dict()

    now = datetime.now(timezone.utc)

    scan_doc = {
        "_id": scan_id,
        "correlation_id": correlation_id,
        "scanned_by": payload.scanned_by or "unknown_user",
        "scanned_at": now,
        "sender_email": sender,
        "sender_domain": domain,
        "verdict": verdict,
        "risk_score": risk_score,
        "reasons": reasons,
        "auth_results": auth_results,
        "dns_policies": dns_policies,
        "url_analysis": url_reports,
        "ai_analysis": ai_analysis,
        "stage_latency_ms": stage_latency_ms,
        "urls_extracted": len(payload.urls or []),
        "headers_received": bool(payload.headers and payload.headers.strip()),
    }

    raw_doc = {
        "_id": scan_id,
        "raw_headers": payload.headers or "",
        "raw_body_html": payload.body_html or "",
        "raw_body_text": payload.body_text or "",
        "raw_vt_responses": raw_vt,
        "raw_dns_answers": raw_dns,
        "raw_gemini_prompt": gemini_prompt,
        "raw_gemini_response": ai_analysis,
    }

    try:
        await scans_collection().insert_one(scan_doc)
        await raw_collection().insert_one(raw_doc)
        log.info("Scan persisted", extra={"extra_fields": {
            "event": "scan.persisted", "scan_id": scan_id, "verdict": verdict,
            "risk_score": risk_score, "stage_latency_ms": stage_latency_ms
        }})
    except Exception as e:
        # Never let a DB write failure break the analyst's result -- log it
        # loudly and still return the scan result.
        log.error("Failed to persist scan to MongoDB", extra={"extra_fields": {
            "event": "scan.persist_failed", "scan_id": scan_id, "error": str(e)
        }})

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "reasons": reasons,
        "ai_analysis": ai_analysis,
        "details": {
            "authentication_results": auth_results,
            "dns_policies": dns_policies,
            "url_analysis": url_reports,
            "sender_domain": domain,
            "urls_extracted": len(payload.urls or []),
            "headers_received": bool(payload.headers and payload.headers.strip()),
        },
        "scan_id": scan_id,
    }
