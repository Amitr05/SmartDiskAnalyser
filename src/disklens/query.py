"""Offline natural-language intent routing, grounded in scan data. Not an LLM."""

import re
import time

from .analysis import anomalies, applications, forecast, largest, summary


def intent(question):
    q = question.casefold()
    if re.search(r"\b(delete|safe|unsafe|remove|break)\b", q):
        return "safety"
    if any(word in q for word in ("forecast", "future", "predict", "will i", "run out")):
        return "forecast"
    if any(word in q for word in ("duplicate", "identical", "same content")):
        return "duplicates"
    if any(word in q for word in ("largest", "biggest", "most space", "most storage")):
        return "largest"
    if any(word in q for word in ("anomal", "unusual", "unexpected")):
        return "anomalies"
    if any(word in q for word in ("application", "apps", "docker", "chrome")):
        return "applications"
    if any(word in q for word in ("storage", "space", "breakdown", "summary")):
        return "summary"
    return "unknown"


def answer(db, scan, question):
    start = time.perf_counter()
    route = intent(question)
    handlers = {"summary": summary, "anomalies": anomalies, "applications": applications}
    if route in handlers:
        result = handlers[route](db, scan)
    elif route == "largest":
        result = largest(db, scan["id"])
    elif route == "forecast":
        result = forecast(db, scan["root"], exclusions=scan.get("exclusions", "[]"))
    elif route == "duplicates":
        result = {"action": "Run disklens duplicates to explicitly opt into selective content hashing."}
    elif route == "safety":
        result = {
            "answer": "Metadata cannot prove deletion safety. Use disklens risk <exact-path> or inspect. "
            "No natural-language query can authorize deletion."
        }
    else:
        result = {
            "answer": "Unsupported question; no answer inferred. Try largest files, storage summary, "
            "applications, anomalies, or storage forecast."
        }
    return {
        "source": "offline deterministic intent router over scanner facts; not generative AI",
        "intent": route,
        "scan_id": scan["id"],
        "scan_status": scan["status"],
        "result": result,
        "query_seconds": time.perf_counter() - start,
    }
