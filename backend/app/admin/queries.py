"""
All read/aggregation queries for the admin dashboard live here, kept
separate from routes.py so the page-rendering code stays readable and the
Mongo pipelines are easy to find/tune in one place.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from app.database import scans_collection, raw_collection

TRENDING_DAYS = 14


def _days_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=n)


def _start_of_today() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


async def get_overview_metrics() -> dict:
    col = scans_collection()

    total_scans = await col.count_documents({})
    scans_today = await col.count_documents({"scanned_at": {"$gte": _start_of_today()}})

    # Verdict breakdown
    verdict_cursor = col.aggregate([
        {"$group": {"_id": "$verdict", "count": {"$sum": 1}}}
    ])
    verdict_breakdown = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING_DETECTED": 0}
    async for doc in verdict_cursor:
        if doc["_id"] in verdict_breakdown:
            verdict_breakdown[doc["_id"]] = doc["count"]

    # Average risk score
    avg_cursor = col.aggregate([{"$group": {"_id": None, "avg": {"$avg": "$risk_score"}}}])
    avg_risk_score = 0.0
    async for doc in avg_cursor:
        avg_risk_score = round(doc["avg"] or 0, 1)

    # Auth failure rate (any of SPF/DKIM/DMARC not "pass")
    auth_fail_count = await col.count_documents({
        "$or": [
            {"auth_results.spf": {"$ne": "pass"}},
            {"auth_results.dkim": {"$ne": "pass"}},
            {"auth_results.dmarc": {"$ne": "pass"}},
        ]
    })
    auth_fail_rate = round((auth_fail_count / total_scans) * 100, 1) if total_scans else 0.0

    # Scan volume trend, last N days
    since = _days_ago(TRENDING_DAYS)
    volume_cursor = col.aggregate([
        {"$match": {"scanned_at": {"$gte": since}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$scanned_at"}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ])
    volume_trend = [{"date": d["_id"], "count": d["count"]} async for d in volume_cursor]

    # SPF/DKIM/DMARC pass-rate trend, last N days
    auth_trend_cursor = col.aggregate([
        {"$match": {"scanned_at": {"$gte": since}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$scanned_at"}},
            "total": {"$sum": 1},
            "spf_pass": {"$sum": {"$cond": [{"$eq": ["$auth_results.spf", "pass"]}, 1, 0]}},
            "dkim_pass": {"$sum": {"$cond": [{"$eq": ["$auth_results.dkim", "pass"]}, 1, 0]}},
            "dmarc_pass": {"$sum": {"$cond": [{"$eq": ["$auth_results.dmarc", "pass"]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ])
    auth_trend = []
    async for d in auth_trend_cursor:
        total = d["total"] or 1
        auth_trend.append({
            "date": d["_id"],
            "spf_pass_rate": round(d["spf_pass"] / total * 100, 1),
            "dkim_pass_rate": round(d["dkim_pass"] / total * 100, 1),
            "dmarc_pass_rate": round(d["dmarc_pass"] / total * 100, 1),
        })

    # Top targeted users -- employees receiving the most Suspicious/Phishing mail.
    # This is the "who's actually under attack" view, PhishER-style.
    targeted_cursor = col.aggregate([
        {"$match": {"verdict": {"$in": ["SUSPICIOUS", "PHISHING_DETECTED"]}}},
        {"$group": {"_id": "$scanned_by", "flagged_count": {"$sum": 1}}},
        {"$sort": {"flagged_count": -1}},
        {"$limit": 10},
    ])
    top_targeted_users = [{"email": d["_id"], "flagged_count": d["flagged_count"]} async for d in targeted_cursor]

    # Repeat offender senders/domains
    repeat_cursor = col.aggregate([
        {"$group": {"_id": "$sender_domain", "count": {"$sum": 1},
                     "max_risk": {"$max": "$risk_score"}}},
        {"$match": {"_id": {"$ne": ""}, "count": {"$gt": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ])
    repeat_offenders = [
        {"domain": d["_id"], "count": d["count"], "max_risk": d["max_risk"]}
        async for d in repeat_cursor
    ]

    # Malicious URL hit rate -- unwind url_analysis (stored as an object keyed
    # by URL) into individual entries to compute the percentage flagged.
    url_stats_cursor = col.aggregate([
        {"$project": {"urls": {"$objectToArray": "$url_analysis"}}},
        {"$unwind": {"path": "$urls", "preserveNullAndEmptyArrays": False}},
        {"$group": {
            "_id": None,
            "total_urls": {"$sum": 1},
            "malicious_urls": {"$sum": {"$cond": [{"$gt": ["$urls.v.malicious_count", 0]}, 1, 0]}},
        }},
    ])
    total_urls, malicious_urls = 0, 0
    async for d in url_stats_cursor:
        total_urls = d["total_urls"]
        malicious_urls = d["malicious_urls"]
    malicious_url_rate = round((malicious_urls / total_urls) * 100, 1) if total_urls else 0.0

    # External API health: average latency per stage + rough error rate
    latency_cursor = col.aggregate([
        {"$group": {
            "_id": None,
            "avg_dns_ms": {"$avg": "$stage_latency_ms.dns_lookup"},
            "avg_vt_ms": {"$avg": "$stage_latency_ms.virustotal"},
            "avg_gemini_ms": {"$avg": "$stage_latency_ms.gemini"},
            "avg_total_ms": {"$avg": "$stage_latency_ms.total"},
        }}
    ])
    latency = {"avg_dns_ms": 0, "avg_vt_ms": 0, "avg_gemini_ms": 0, "avg_total_ms": 0}
    async for d in latency_cursor:
        for k in latency:
            latency[k] = round(d.get(k) or 0, 1)

    gemini_error_count = await col.count_documents({"ai_analysis": {"$regex": "failed|unavailable", "$options": "i"}})

    return {
        "total_scans": total_scans,
        "scans_today": scans_today,
        "avg_risk_score": avg_risk_score,
        "auth_fail_rate": auth_fail_rate,
        "verdict_breakdown": verdict_breakdown,
        "volume_trend": volume_trend,
        "auth_trend": auth_trend,
        "top_targeted_users": top_targeted_users,
        "repeat_offenders": repeat_offenders,
        "malicious_url_rate": malicious_url_rate,
        "total_urls_scanned": total_urls,
        "latency": latency,
        "gemini_error_count": gemini_error_count,
    }


async def list_users(search: Optional[str] = None) -> list[dict]:
    match_stage = {}
    if search:
        match_stage = {"scanned_by": {"$regex": search, "$options": "i"}}

    pipeline = []
    if match_stage:
        pipeline.append({"$match": match_stage})

    pipeline += [
        {"$group": {
            "_id": "$scanned_by",
            "total_scans": {"$sum": 1},
            "high_risk_count": {"$sum": {"$cond": [{"$ne": ["$verdict", "SAFE"]}, 1, 0]}},
            "last_scan_at": {"$max": "$scanned_at"},
        }},
        {"$sort": {"total_scans": -1}},
    ]

    cursor = scans_collection().aggregate(pipeline)
    return [
        {
            "email": d["_id"],
            "total_scans": d["total_scans"],
            "high_risk_count": d["high_risk_count"],
            "last_scan_at": d["last_scan_at"],
        }
        async for d in cursor
    ]


async def get_user_detail(email: str) -> dict:
    col = scans_collection()
    scans = await col.find({"scanned_by": email}).sort("scanned_at", -1).to_list(length=500)

    total = len(scans)
    verdict_breakdown = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING_DETECTED": 0}
    domain_counts: dict[str, int] = {}
    for s in scans:
        if s["verdict"] in verdict_breakdown:
            verdict_breakdown[s["verdict"]] += 1
        domain_counts[s.get("sender_domain", "")] = domain_counts.get(s.get("sender_domain", ""), 0) + 1

    top_senders = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]

    return {
        "email": email,
        "total_scans": total,
        "verdict_breakdown": verdict_breakdown,
        "top_senders": [{"domain": d, "count": c} for d, c in top_senders if d],
        "scans": scans,
    }


async def get_scan_detail(scan_id: str) -> Optional[dict]:
    return await scans_collection().find_one({"_id": scan_id})


async def get_raw_scan_data(scan_id: str) -> Optional[dict]:
    return await raw_collection().find_one({"_id": scan_id})
