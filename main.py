# main.py
import hashlib
import json
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

FREEZE_STORE: dict[str, dict[str, Any]] = {}


def err(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": code})


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and v not in (float("inf"), float("-inf"))


def is_nonneg_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**53 - 1


# ---------------- FREEZE ----------------

def validate_freeze(body: dict) -> Optional[str]:
    if not is_str(body.get("freezeId")) or len(body["freezeId"]) > 128:
        return "bad freezeId"
    if not is_str(body.get("calibrationDigest")):
        return "bad calibrationDigest"
    if not is_str(body.get("tokenizerDigest")):
        return "bad tokenizerDigest"

    reasons = body.get("allowedUnsupportedReasons")
    if not isinstance(reasons, list) or not all(is_str(r) for r in reasons):
        return "bad allowedUnsupportedReasons"
    if len(set(reasons)) != len(reasons):
        return "dup reasons"

    candidates = body.get("candidates")
    if not isinstance(candidates, list) or len(candidates) == 0:
        return "bad candidates"

    names = []
    for c in candidates:
        if not isinstance(c, dict) or not is_str(c.get("name")):
            return "bad candidate"
        names.append(c["name"])
        # files/loadable/digests are intentionally NOT validated here.
        # Malformed files is a per-candidate "invalid" outcome (reasonCode
        # INVALID_INPUT), not a whole-request 400 — see compute_candidate().

    if len(set(names)) != len(names):
        return "dup names"
    return None


def compute_inventory(files: dict):
    entries = []
    for fn, fv in files.items():
        raw = fv.encode("utf-8")
        entries.append({"name": fn, "bytes": len(raw), "sha256": sha256_hex(raw)})
    entries.sort(key=lambda e: e["name"].encode("utf-8"))
    total = sum(e["bytes"] for e in entries)
    payload = json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = sha256_hex(payload)
    return entries, total, digest


def compute_candidate(c: dict, req: dict) -> dict:
    name = c["name"]
    files = c.get("files")
    files_valid = (
        isinstance(files, dict)
        and len(files) > 0
        and all(is_str(fn) and isinstance(fv, str) for fn, fv in files.items())
    )

    if not files_valid:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    inventory, total_bytes, digest = compute_inventory(files)
    codes = []
    reason = c.get("unsupportedReason")

    if is_str(reason):
        if reason in req.get("allowedUnsupportedReasons", []):
            status = "unsupported"
        else:
            status = "invalid"
            codes.append("UNALLOWED_UNSUPPORTED_REASON")
    else:
        if not c.get("loadable"):
            codes.append("NOT_LOADABLE")
        if c.get("calibrationDigest") != req.get("calibrationDigest"):
            codes.append("CALIBRATION_MISMATCH")
        if c.get("tokenizerDigest") != req.get("tokenizerDigest"):
            codes.append("TOKENIZER_MISMATCH")
        status = "frozen" if not codes else "invalid"

    codes = sorted(set(codes), key=lambda s: s.encode("utf-8"))
    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": digest,
        "reasonCodes": codes,
    }


def handle_freeze(body: dict):
    if validate_freeze(body) is not None:
        return err(400, "INVALID_INPUT")

    fid = body["freezeId"]
    if fid in FREEZE_STORE:
        stored = FREEZE_STORE[fid]
        if stored["request"] == body:
            return JSONResponse(status_code=200, content=stored["response"])
        return err(409, "FREEZE_ID_CONFLICT")

    results = [compute_candidate(c, body) for c in body["candidates"]]
    results.sort(key=lambda r: r["name"].encode("utf-8"))
    response = {"freezeId": fid, "candidates": results}
    FREEZE_STORE[fid] = {"request": body, "response": response}
    return JSONResponse(status_code=200, content=response)


# ---------------- SELECT ----------------

def round12(v: float) -> float:
    return round(v, 12)


def handle_select(body: dict):
    if not isinstance(body.get("candidates"), list) or not isinstance(body.get("rows"), list) or not isinstance(body.get("policy"), dict):
        return err(400, "INVALID_INPUT")

    fid = body.get("freezeId")
    submitted = body["candidates"]
    policy = body["policy"]
    rows = body["rows"]
    latencies = body.get("latencies") if isinstance(body.get("latencies"), dict) else {}

    stored = FREEZE_STORE.get(fid) if is_str(fid) else None

    max_bytes = policy.get("maxBytes")
    agg_floor = policy.get("aggregateFloor")
    req_slices = policy.get("requiredSlices")
    max_lat = policy.get("maxLatencyMs")
    order = policy.get("candidateOrder")

    policy_valid = True
    if not is_nonneg_int(max_bytes):
        policy_valid = False
    if not is_num(agg_floor) or not (0 <= agg_floor <= 1):
        policy_valid = False
    if not isinstance(req_slices, dict) or not all(is_str(k) and is_num(v) and 0 <= v <= 1 for k, v in req_slices.items()):
        policy_valid = False
    if not is_num(max_lat) or max_lat < 0:
        policy_valid = False
    if not isinstance(order, list) or not all(is_str(x) for x in order) or len(set(order)) != len(order):
        policy_valid = False

    submitted_names = [c["name"] for c in submitted if isinstance(c, dict) and is_str(c.get("name"))]
    if policy_valid and isinstance(order, list) and set(order) != set(submitted_names):
        policy_valid = False

    stored_by_name = {}
    if stored is not None:
        for sc in stored["response"]["candidates"]:
            stored_by_name[sc["name"]] = sc

    order_index = {n: i for i, n in enumerate(order)} if isinstance(order, list) else {}

    results = []
    for c in submitted:
        codes = set()
        name = c.get("name") if isinstance(c, dict) else None
        stored_c = stored_by_name.get(name) if name else None

        if stored is None:
            codes.add("NOT_FROZEN")
        elif stored_c is None:
            codes.add("INVALID_LINEAGE")
        else:
            lineage_ok = (
                isinstance(c, dict)
                and c.get("status") == stored_c.get("status")
                and c.get("inventory") == stored_c.get("inventory")
                and c.get("reasonCodes") == stored_c.get("reasonCodes")
            )
            if not lineage_ok:
                codes.add("INVALID_LINEAGE")
            elif stored_c.get("status") != "frozen":
                codes.add("INVALID_MANIFEST")

        if not policy_valid:
            codes.add("INVALID_POLICY")

        aggregate = None
        slices = {}
        total_correct = 0
        total_rows = 0
        slice_correct: dict[str, int] = {}
        slice_total: dict[str, int] = {}
        preds_valid = True

        for row in rows:
            if not isinstance(row, dict):
                preds_valid = False
                continue
            label = row.get("label")
            slice_name = row.get("slice")
            preds = row.get("predictions") if isinstance(row.get("predictions"), dict) else {}
            if name not in preds or preds.get(name) not in (0, 1) or label not in (0, 1):
                preds_valid = False
                continue
            total_rows += 1
            correct = 1 if preds[name] == label else 0
            total_correct += correct
            if is_str(slice_name):
                slice_total[slice_name] = slice_total.get(slice_name, 0) + 1
                slice_correct[slice_name] = slice_correct.get(slice_name, 0) + correct

        if not preds_valid or total_rows == 0:
            codes.add("INVALID_PREDICTIONS")
        else:
            aggregate = round12(total_correct / total_rows)
            if is_num(agg_floor) and aggregate < agg_floor:
                codes.add("AGGREGATE_FLOOR")
            if isinstance(req_slices, dict):
                for sname, floor in req_slices.items():
                    if sname not in slice_total:
                        codes.add(f"MISSING_SLICE:{sname}")
                        continue
                    acc = round12(slice_correct[sname] / slice_total[sname])
                    slices[sname] = acc
                    if is_num(floor) and acc < floor:
                        codes.add(f"SLICE_FLOOR:{sname}")

        total_bytes = None
        if isinstance(c, dict) and isinstance(c.get("inventory"), list):
            try:
                total_bytes = sum(int(i["bytes"]) for i in c["inventory"])
            except Exception:
                total_bytes = None
        if total_bytes is None:
            codes.add("SIZE_LIMIT")
        elif is_nonneg_int(max_bytes) and total_bytes > max_bytes:
            codes.add("SIZE_LIMIT")

        latency_ms = latencies.get(name) if name in latencies else None
        if not is_num(latency_ms) or latency_ms < 0:
            latency_ms = None
            codes.add("LATENCY_LIMIT")
        elif is_num(max_lat) and latency_ms > max_lat:
            codes.add("LATENCY_LIMIT")

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency_ms,
            "admitted": len(codes) == 0,
            "reasonCodes": sorted(codes, key=lambda s: s.encode("utf-8")),
        })

    def sort_key(r):
        return (0, order_index[r["name"]]) if r["name"] in order_index else (1, r["name"].encode("utf-8"))

    results.sort(key=sort_key)

    admitted = [r for r in results if r["admitted"]]
    selected = None
    package_manifest = None
    if admitted:
        def win_key(r):
            return (
                r["totalBytes"] if r["totalBytes"] is not None else float("inf"),
                r["latencyMs"] if r["latencyMs"] is not None else float("inf"),
                order_index.get(r["name"], len(order_index)),
            )
        winner = min(admitted, key=win_key)
        selected = winner["name"]
        package_manifest = stored_by_name.get(selected)

    return JSONResponse(status_code=200, content={
        "freezeId": fid,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    })


@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return err(400, "INVALID_INPUT")
    if not isinstance(body, dict):
        return err(400, "INVALID_INPUT")

    phase = body.get("phase")
    if phase == "freeze":
        return handle_freeze(body)
    if phase == "select":
        return handle_select(body)
    return err(400, "INVALID_INPUT")