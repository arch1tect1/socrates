from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .enrichment import abuseipdb, otx, shodan, urlscan, virustotal
from .ai import claude, openai_fallback
from .cache import check_cache, save_results, get_history
from .models.schemas import (
    AnalyzeRequest,
    IOCType,
    SourceStatus,
)
from .skip_reasons import skip_reason_for_source

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("socrates")

app = FastAPI(title="SOCrates API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

IOC_PATTERNS = [
    (
        "ip",
        re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        ),
    ),
    ("ip", re.compile(r"^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$")),
    ("hash", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("hash", re.compile(r"^[0-9a-fA-F]{40}$")),
    ("hash", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("url", re.compile(r"^https?://", re.IGNORECASE)),
    (
        "domain",
        re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        ),
    ),
]


def refang(value: str) -> str:
    """Convert defanged IOCs back to their original form."""
    v = value.strip()
    v = v.replace("[.]", ".").replace("(dot)", ".").replace("[dot]", ".")
    v = re.sub(r"^hxxps?://", lambda m: m.group(0).replace("hxxp", "http"), v, flags=re.IGNORECASE)
    v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
    v = v.replace("[://]", "://").replace("[:]", ":")
    v = v.replace("[at]", "@").replace("[@]", "@")
    return v


def detect_ioc_type(value: str) -> IOCType | None:
    value = refang(value)
    for ioc_type, pattern in IOC_PATTERNS:
        if pattern.match(value):
            return IOCType(ioc_type)
    return None


ENRICHMENT_SOURCES = {
    "VirusTotal": virustotal,
    "Shodan": shodan,
    "AbuseIPDB": abuseipdb,
    "OTX AlienVault": otx,
    "URLScan.io": urlscan,
}


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _sanitize_error(msg: str) -> str:
    """Strip API keys and sensitive tokens from error messages."""
    sanitized = msg
    for key_env in (
        "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY",
        "OTX_API_KEY", "URLSCAN_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    ):
        val = os.getenv(key_env, "")
        if val and val in sanitized:
            sanitized = sanitized.replace(val, "***")
    return sanitized


async def _run_enrichment(
    name: str, module, ioc: str, ioc_type: str
) -> tuple[str, dict | None, str | None, float, str | None]:
    start = time.time()
    try:
        result = await module.query(ioc, ioc_type)
        elapsed = round(time.time() - start, 2)
        if result.get("skipped"):
            sr = (result.get("reason") or "").strip() or skip_reason_for_source(name, ioc_type)
            return name, None, None, elapsed, sr
        if result.get("error"):
            return name, None, _sanitize_error(result["error"]), elapsed, None
        return name, result, None, elapsed, None
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        logger.exception(f"Error querying {name}")
        return name, None, _sanitize_error(str(e)), elapsed, None


async def analysis_stream(
    ioc: str, ioc_type: IOCType, session_id: str | None = None
) -> AsyncGenerator[str, None]:
    overall_start = time.time()
    ioc_type_str = ioc_type.value

    yield _sse("init", {"ioc": ioc, "ioc_type": ioc_type_str})

    sources_list = list(ENRICHMENT_SOURCES.keys())
    yield _sse(
        "sources",
        [{"source": s, "status": "pending"} for s in sources_list],
    )

    for name in sources_list:
        yield _sse("source_status", {"source": name, "status": "querying"})

    tasks = {
        name: asyncio.create_task(
            _run_enrichment(name, module, ioc, ioc_type_str)
        )
        for name, module in ENRICHMENT_SOURCES.items()
    }

    enrichment_data = {}
    done_tasks: set = set()

    while len(done_tasks) < len(tasks):
        for name, task in tasks.items():
            if name not in done_tasks and task.done():
                done_tasks.add(name)
                try:
                    source_name, result, error, elapsed, skip_reason = task.result()
                except BaseException as e:
                    yield _sse(
                        "source_complete",
                        {
                            "source": name,
                            "status": "error",
                            "error": _sanitize_error(str(e)),
                            "elapsed": 0.0,
                        },
                    )
                    continue

                if error:
                    yield _sse(
                        "source_complete",
                        {
                            "source": source_name,
                            "status": "error",
                            "error": error,
                            "elapsed": elapsed,
                        },
                    )
                elif result is None:
                    payload = {
                        "source": source_name,
                        "status": "skipped",
                        "elapsed": elapsed,
                    }
                    if skip_reason:
                        payload["skip_reason"] = skip_reason
                    yield _sse("source_complete", payload)
                else:
                    enrichment_data[source_name] = result
                    yield _sse(
                        "source_complete",
                        {
                            "source": source_name,
                            "status": "complete",
                            "data": result,
                            "elapsed": elapsed,
                        },
                    )
        if len(done_tasks) < len(tasks):
            await asyncio.sleep(0.2)

    yield _sse("ai_start", {"status": "generating"})

    ai_result = None
    try:
        ai_result = await claude.analyze(ioc, ioc_type_str, enrichment_data)
    except Exception as e:
        logger.warning(f"Claude failed: {e}, falling back to OpenAI")
        try:
            ai_result = await openai_fallback.analyze(
                ioc, ioc_type_str, enrichment_data
            )
        except Exception as e2:
            logger.error(f"OpenAI fallback also failed: {e2}")
            ai_result = {
                "verdict": "INCONCLUSIVE",
                "confidence": "LOW",
                "reasoning": (
                    "AI analysis could not be completed due to API errors. "
                    "Please review the enrichment data manually."
                ),
                "mitre_attack": [],
                "recommended_actions": [
                    "Review enrichment data manually",
                    "Re-run analysis when AI services are available",
                ],
                "key_findings": [],
            }

    total_elapsed = round(time.time() - overall_start, 2)

    yield _sse("ai_complete", {"verdict": ai_result, "total_elapsed": total_elapsed})

    # Save to Supabase cache (fire-and-forget)
    source_results_for_cache = []
    for name in ENRICHMENT_SOURCES:
        task = tasks[name]
        try:
            source_name, result, error, elapsed, skip_reason = task.result()
        except BaseException as e:
            source_results_for_cache.append({
                "source": name,
                "status": "error",
                "error": _sanitize_error(str(e)),
                "elapsed": 0.0,
            })
            continue
        status = "error" if error else ("skipped" if result is None else "complete")
        row = {"source": source_name, "status": status, "elapsed": elapsed}
        if status == "skipped" and skip_reason:
            row["skip_reason"] = skip_reason
        source_results_for_cache.append(row)
    try:
        await save_results(
            ioc,
            ioc_type_str,
            source_results_for_cache,
            enrichment_data,
            ai_result,
            total_elapsed,
            session_id=session_id,
        )
    except Exception:
        logger.debug("Cache save failed in SSE stream", exc_info=True)

    yield _sse("done", {"total_elapsed": total_elapsed})


@app.post("/api/analyze")
async def analyze_ioc(request: AnalyzeRequest):
    ioc = refang(request.ioc)
    ioc_type = detect_ioc_type(ioc)

    if not ioc_type:
        raise HTTPException(
            status_code=400,
            detail="Could not detect IOC type. Supported: IPv4/IPv6, domain, URL, MD5/SHA1/SHA256 hash.",
        )

    sid = (request.session_id or "").strip() or None

    return StreamingResponse(
        analysis_stream(ioc, ioc_type, sid),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/analyze/batch")
async def analyze_ioc_batch(request: AnalyzeRequest):
    """Non-streaming fallback for serverless environments (Vercel)."""
    ioc = refang(request.ioc)
    ioc_type = detect_ioc_type(ioc)

    if not ioc_type:
        raise HTTPException(
            status_code=400,
            detail="Could not detect IOC type. Supported: IPv4/IPv6, domain, URL, MD5/SHA1/SHA256 hash.",
        )

    ioc_type_str = ioc_type.value
    sid = (request.session_id or "").strip() or None

    # Check cache unless force re-analyse requested
    if not request.force:
        cached = await check_cache(ioc)
        if cached:
            return cached

    overall_start = time.time()

    tasks = {
        name: asyncio.create_task(
            _run_enrichment(name, module, ioc, ioc_type_str)
        )
        for name, module in ENRICHMENT_SOURCES.items()
    }
    await asyncio.gather(*tasks.values(), return_exceptions=True)

    enrichment_data = {}
    source_results = []
    for name, task in tasks.items():
        try:
            raw = task.result()
        except BaseException as e:
            source_results.append({
                "source": name,
                "status": "error",
                "error": _sanitize_error(str(e)),
                "elapsed": 0.0,
            })
            continue
        source_name, result, error, elapsed, skip_reason = raw
        status = "error" if error else ("skipped" if result is None else "complete")
        entry = {"source": source_name, "status": status, "elapsed": elapsed}
        if error:
            entry["error"] = error
        if status == "skipped" and skip_reason:
            entry["skip_reason"] = skip_reason
        if result:
            entry["data"] = result
            enrichment_data[source_name] = result
        source_results.append(entry)

    ai_result = None
    try:
        ai_result = await claude.analyze(ioc, ioc_type_str, enrichment_data)
    except Exception as e:
        logger.warning(f"Claude failed: {e}, falling back to OpenAI")
        try:
            ai_result = await openai_fallback.analyze(ioc, ioc_type_str, enrichment_data)
        except Exception:
            ai_result = {
                "verdict": "INCONCLUSIVE", "confidence": "LOW",
                "reasoning": "AI analysis could not be completed. Please review enrichment data manually.",
                "mitre_attack": [], "recommended_actions": ["Review enrichment data manually"],
                "key_findings": [],
            }

    total_elapsed = round(time.time() - overall_start, 2)

    # Save to cache
    try:
        await save_results(
            ioc,
            ioc_type_str,
            source_results,
            enrichment_data,
            ai_result,
            total_elapsed,
            session_id=sid,
        )
    except Exception:
        logger.debug("Cache save failed in batch endpoint", exc_info=True)

    return {
        "ioc": ioc,
        "ioc_type": ioc_type_str,
        "sources": source_results,
        "verdict": ai_result,
        "total_elapsed": total_elapsed,
    }


@app.get("/api/cache/check")
async def cache_check(ioc: str):
    """Check if a fresh cached result exists for the given IOC."""
    clean = refang(ioc)
    cached = await check_cache(clean)
    if cached:
        return cached
    return {"cached": False}


@app.get("/api/history")
async def history_list(limit: int = 20, session_id: str | None = None):
    """Return recent IOC queries for this browser session only."""
    sid = (session_id or "").strip() or None
    items = await get_history(min(limit, 50), session_id=sid)
    return {"items": items}


@app.get("/api/detect")
async def detect_type(ioc: str):
    clean = refang(ioc)
    ioc_type = detect_ioc_type(clean)
    if not ioc_type:
        return {"ioc": ioc, "refanged": clean, "type": None}
    return {"ioc": ioc, "refanged": clean, "type": ioc_type.value}


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "SOCrates"}
