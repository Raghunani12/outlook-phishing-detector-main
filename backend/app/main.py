

import os
import re
import requests
import dns.resolver
from typing import List
from pydantic import BaseModel
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- [NEW] Import the official modern Google GenAI SDK ---
from google import genai

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# --- [NEW] Initialize the centralized client object ---
if GEMINI_API_KEY:
    print("[BACKEND INIT] Initializing official google-genai Client object with API key.")
    ai_client = genai.Client(api_key=GEMINI_API_KEY)
else:
    print("[BACKEND INIT] WARNING: GEMINI_API_KEY not found in environment settings.")
    ai_client = None

app = FastAPI(title="Phishing Shield Modern Security Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailAnalysisRequest(BaseModel):
    sender_email: str
    headers: str
    urls: List[str]

def parse_authentication_results(headers: str) -> dict:
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    print("\n" + "="*60)
    print(f"[BACKEND PARSER STEP] Starting headers text parse. Input string length: {len(headers)}")
    print("="*60)
    
    if not headers or headers.strip() == "":
        print("[BACKEND PARSER WARNING] The headers block passed from the client is empty.")
        return results

    auth_lines = re.findall(
        r"Authentication-Results:[\s\S]*?(?=\r?\n[A-Za-z][^\s]|$)",
        headers,
        re.IGNORECASE
    )
    
    print(f"[BACKEND PARSER STEP] Found {len(auth_lines)} 'Authentication-Results' regex blocks in header data stream.")
    for idx, block in enumerate(auth_lines):
        print(f" -> Analyzing regex matching block match target idx ({idx}):\n{block[:200]}...\n")
        
        # Check SPF
        if not results["spf"] or results["spf"] == "unknown":
            spf_m = re.search(r"\bspf\s*=\s*([a-zA-r]+)", block, re.IGNORECASE)
            if spf_m:
                results["spf"] = spf_m.group(1).lower()
                print(f"    [*] Found SPF state token match: {results['spf']}")

        # Check DKIM
        if not results["dkim"] or results["dkim"] == "unknown":
            dkim_m = re.search(r"\bdkim\s*=\s*([a-zA-r]+)", block, re.IGNORECASE)
            if dkim_m:
                results["dkim"] = dkim_m.group(1).lower()
                print(f"    [*] Found DKIM state token match: {results['dkim']}")

        # Check DMARC
        if not results["dmarc"] or results["dmarc"] == "unknown":
            dmarc_m = re.search(r"\bdmarc\s*=\s*([a-zA-r]+)", block, re.IGNORECASE)
            if dmarc_m:
                results["dmarc"] = dmarc_m.group(1).lower()
                print(f"    [*] Found DMARC state token match: {results['dmarc']}")

    print(f"[BACKEND PARSER COMPLETED] Extracted authentication metrics state results: {results}")
    return results

def check_domain_dns_policy(domain: str) -> dict:
    print(f"\n[BACKEND DNS STEP] Performing lookups on domain: {domain}")
    policies = {"has_spf": False, "has_dmarc": False, "spf_policy": "none", "dmarc_policy": "none"}
    
    # SPF check
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = "".join([b.decode('utf-8') for b in rdata.strings])
            if "v=spf1" in txt_record:
                policies["has_spf"] = True
                if "-all" in txt_record:
                    policies["spf_policy"] = "strict"
                elif "~all" in txt_record:
                    policies["spf_policy"] = "softfail"
                else:
                    policies["spf_policy"] = "permissive"
                print(f" -> Found valid SPF TXT configuration payload: {txt_record}")
    except Exception as e:
        print(f" -> Error resolving SPF policy parameters for domain: {str(e)}")

    # DMARC check
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt_record = "".join([b.decode('utf-8') for b in rdata.strings])
            if "v=DMARC1" in txt_record:
                policies["has_dmarc"] = True
                p_m = re.search(r"\bp\s*=\s*([a-zA-Z]+)", txt_record)
                policies["dmarc_policy"] = p_m.group(1).lower() if p_m else "none"
                print(f" -> Found valid DMARC configuration payload: {txt_record}")
    except Exception as e:
        print(f" -> Error resolving DMARC records context constraints: {str(e)}")

    print(f"[BACKEND DNS COMPLETED] Metrics generated: {policies}")
    return policies

def analyze_url_with_virustotal(url: str) -> dict:
    print(f"[BACKEND VIRUSTOTAL STEP] Querying payload signature for URL: {url}")
    if not VT_API_KEY:
        print(" -> Warning: VirusTotal API Key absent from configuration initialization.")
        return {"status": "unscanned", "malicious_count": 0}

    url_id = base64_url_encode(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        res = requests.get(vt_url, headers=headers, timeout=8)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print(f" -> VirusTotal analysis extraction metrics data returned: {stats}")
            return {
                "status": "analyzed",
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0)
            }
        else:
            print(f" -> VirusTotal endpoint server responded with warning error state status code: {res.status_code}")
            return {"status": f"error_{res.status_code}", "malicious_count": 0}
    except Exception as e:
        print(f" -> Failed to reach VirusTotal processing stack framework engine: {str(e)}")
        return {"status": "exception_failed", "malicious_count": 0}

def base64_url_encode(url: str) -> str:
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# --- [UPGRADED] Refactored to use official modern Google GenAI SDK syntax ---
def generate_gemini_verdict(sender: str, auth: dict, dns_p: dict, score: int, reasons: list) -> str:
    print("\n" + "="*60)
    print("[BACKEND GEMINI STEP] Triggering content analysis prompt generation...")
    print("="*60)
    
    if not ai_client:
        print("[BACKEND GEMINI ERROR] Google GenAI SDK Client object is uninitialized. Verify GEMINI_API_KEY.")
        return "Gemini pipeline engine key registration missing."

    prompt = f"""
    Analyze this email threat telemetry profile as a security intelligence engine:
    - Target Sender Address: {sender}
    - Calculated Aggregated Threat Risk Metric: {score}/100
    - Flagged Engine Reason Codes: {", ".join(reasons)}
    - Email Transit Validation: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}
    - DNS Domain Policies: SPF configuration type={dns_p.get('spf_policy')}, DMARC baseline constraint={dns_p.get('dmarc_policy')}

    Provide a summary of up to 3 sentences telling an office employee whether this email is safe to open and why. Be direct.
    """

    print(f" -> Dispatching payload contents via official client.models.generate_content architecture using model 'gemini-2.5-flash'...")

    try:
        # Executing the official modern SDK structure
        response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        
        # Accessing direct generated output text attribute
        analysis_text = response.text
        print(f" -> [SDK SUCCESS] Core text summary received perfectly:\n{analysis_text}\n")
        return analysis_text

    except Exception as e:
        print(f" -> [SDK CRITICAL RUNTIME ERROR] Failed to parse content using modern SDK engine: {str(e)}")
        return f"Google GenAI SDK engine execution failure: {str(e)}"

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
        reasons.append("Sender domain SPF policy is configured to be highly permissive (allows broad sending lists).")
    if dns_p.get("dmarc_policy") == "none":
        score += 10
        reasons.append("Sender domain DMARC configuration policy is 'none' — no explicit failure drops are configured.")

    for url, report in url_r.items():
        malicious = report.get("malicious_count", 0)
        if malicious > 0:
            score += 40
            reasons.append(f"VirusTotal Threat Engine Flagged URL: ({malicious} engine warnings matches) — {url}")

    final_score = min(score, 100)
    return final_score, reasons
@app.get("/")
def root():
    return {"status": "running"}
    
@app.post("/api/analyze")
async def analyze_endpoint(payload: EmailAnalysisRequest):
    print("\n" + "#"*70)
    print("[BACKEND HIGH TIER ROUTE TRIGGERED] /api/analyze execution pipeline running.")
    print(f" Inbound parameters context profile details: ")
    print(f"   Sender address parameter configuration input string: '{payload.sender_email}'")
    print(f"   Inbound context headers trace content byte string size: {len(payload.headers or '')} characters")
    print(f"   Extracted unique message body URL array length configuration count: {len(payload.urls or [])}")
    print("#"*70 + "\n")

    sender = (payload.sender_email or "").strip() or "unknown@unknown"
    domain_match = re.search(r"@([\w.\-]+)", sender)
    domain = domain_match.group(1) if domain_match else ""

    auth_results = parse_authentication_results(payload.headers or "")
    dns_policies = check_domain_dns_policy(domain) if domain else {}

    url_reports = {}
    for url in (payload.urls or [])[:5]:
        if url and url.startswith("http"):
            url_reports[url] = analyze_url_with_virustotal(url)

    risk_score, reasons = compute_risk(auth_results, dns_policies, url_reports)
    verdict = "SAFE" if risk_score < 25 else "SUSPICIOUS" if risk_score < 60 else "PHISHING_DETECTED"
    
    ai_analysis = generate_gemini_verdict(sender, auth_results, dns_policies, risk_score, reasons)

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
            "headers_received": bool(payload.headers and payload.headers.strip())
        }
    }