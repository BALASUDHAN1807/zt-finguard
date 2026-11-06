"""AI Security Assistant - built in, offline, no external AI service.

How it works
    1. Intent understanding: the question is matched against intent patterns (keywords
       and phrases, with a score per intent) and entities are pulled out: transaction id,
       incident id, username, service name, time window, decision and severity words.
    2. Each intent names the platform data it needs and the OPA admin permission that
       protects that data. The gateway checks the permission for THIS administrator
       before reading anything - the assistant can never show more than the person
       could open themselves.
    3. The answer is composed only from that live data (audit chain, risk decisions,
       incidents, containers, devices, model metrics). If the data has no answer, it
       says so instead of guessing.
    4. The assistant never acts. Security-critical actions (revoke sessions, quarantine,
       lock, freeze) are returned as suggestions that need the administrator's explicit
       authorization (authenticator code) on the page that performs them.

compose(question, fetch, allowed, users) is pure apart from the `fetch` coroutine the
gateway passes in, which makes it easy to test.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Awaitable, Callable

Fetch = Callable[[str, dict], Awaitable[object]]

# intent -> (patterns with weights, admin permission that protects the data)
INTENTS: dict[str, tuple[list[tuple[str, int]], str]] = {
    "why_blocked": ([(r"\bwhy\b", 1), (r"\b(blocked|denied|refused|flagged|held|stopped|declined|step.?up)\b", 3),
                     (r"\b(transaction|transfer|payment|tx)\b", 2), (r"#\d+|\btx\s*\d+", 2)], "admin.fraud"),
    "quarantine": ([(r"quarantin", 4), (r"\bisolated?\b", 2), (r"\bcontainer", 1)], "admin.quarantine"),
    "incidents": ([(r"\bincidents?\b", 3), (r"\b(critical|high|severe)\b", 1), (r"\b(alerts?|threats?)\b", 2),
                   (r"\btoday\b", 1)], "admin.threats"),
    "incident_detail": ([(r"\binc-\d+", 5), (r"\b(timeline|summar\w*)\b", 1)], "admin.threats"),
    "device_trust": ([(r"\bdevices?\b", 3), (r"\b(untrusted|trust\w*|pending|unfamiliar|marked)\b", 2)],
                     "admin.devices"),
    "highest_risk": ([(r"\b(highest|top|riskiest|most risky|maximum|max)\b", 3), (r"\brisk\w*\b", 2),
                      (r"\bscore\b", 1), (r"\bcaused\b", 1)], "admin.fraud"),
    "falco": ([(r"\bfalco\b", 4), (r"\bruntime\b", 2), (r"\b(shell|syscall|process)\b", 1)], "admin.threats"),
    "vulnerabilities": ([(r"\bvulnerab\w*", 4), (r"\bcve\b", 4), (r"\btrivy\b", 4), (r"\b(image|sbom|patch)\w*", 1)],
                        "admin.containers"),
    "investigate": ([(r"\binvestigat\w*", 3), (r"\b(next steps?|what should|recommend\w*|advice|advise)\b", 3)],
                    "admin.threats"),
    "daily_report": ([(r"\b(daily|today'?s?)\b", 1), (r"\breport\b", 3), (r"\b(summary|summari[sz]e|overview)\b", 2)],
                     "admin.threats"),
    "zero_trust": ([(r"zero.?trust", 3), (r"\b(policy|opa|decision|rule)\b", 2), (r"\bdenied\b", 1)], "admin.fraud"),
    "fraud_model": ([(r"\b(model|ml|xgboost|random forest|accuracy|precision|recall|drift|shap)\b", 3),
                     (r"\bfraud\b", 1), (r"\bprediction", 2)], "admin.fraud"),
    "search": ([(r"\b(show|find|search|list|which|who)\b", 1), (r"\b(events?|logs?|audit|entries|sign.?ins?|logins?)\b", 2),
                (r"\b(last|past)\s+\d+\s*(minutes?|hours?|days?)\b", 1)], "admin.audit"),
    "help": ([(r"^\s*(help|\?|what can you do)", 5)], "admin.dashboard"),
}

EXAMPLES = [
    "Why was transaction #42 blocked?",
    "Which container is currently quarantined?",
    "Show today's critical security incidents",
    "Why was this device marked untrusted? (name the customer)",
    "What caused the highest risk score?",
    "Explain the latest Falco events",
    "Which container images have vulnerabilities?",
    "Summarize incident INC-3",
    "What should I investigate first?",
    "Generate today's security report",
    "Show failed sign-ins in the last 24 hours",
    "How accurate is the fraud model?",
]

DANGEROUS = re.compile(r"\b(quarantine|release|revoke|lock|unlock|freeze|unfreeze|delete|disable|block|restart|"
                       r"approve|reject|change|apply|rollback)\b\s+(the\s+|this\s+|user\s+|service\s+|container\s+)?\w+",
                       re.I)


def classify(question: str) -> tuple[str, dict[str, int]]:
    q = question.lower()
    scores = {}
    for name, (patterns, _perm) in INTENTS.items():
        scores[name] = sum(w for p, w in patterns if re.search(p, q))
    best = max(scores, key=lambda k: scores[k])
    return (best if scores[best] >= 3 else "help"), scores


def entities(question: str, users: list[str], services: list[str]) -> dict:
    q = question.lower()
    tx = re.search(r"(?:#|\btx\s*|\btransaction\s+|\btransfer\s+)(\d{1,12})\b", q)
    inc = re.search(r"\binc-(\d{1,12})\b", q)
    words = set(re.findall(r"[a-z0-9_.-]+", q))
    user = next((u for u in sorted(users, key=len, reverse=True) if u.lower() in words), None)
    svc = next((s for s in services if s in words), None)
    days = 1 if re.search(r"\b(today|last 24 ?h|24 hours|past day)\b", q) else 7
    if m := re.search(r"\b(?:last|past)\s+(\d+)\s*(day|hour|minute)s?\b", q):
        n, unit = int(m.group(1)), m.group(2)
        days = max(1, min(90, n if unit == "day" else 1))
    decision = "deny" if re.search(r"\b(failed|denied|blocked|refused)\b", q) else None
    severity = "critical" if "critical" in q else "high" if re.search(r"\bhigh\b", q) else None
    action = None
    if re.search(r"\b(sign.?ins?|logins?|log.?ins?)\b", q):
        action = "auth.login"
    elif re.search(r"\b(transfers?|payments?)\b", q):
        action = "transaction.transfer"
    elif "quarantin" in q:
        action = "container.quarantine"
    return {"tx_id": int(tx.group(1)) if tx else None, "incident": f"INC-{inc.group(1)}" if inc else None,
            "user": user, "service": svc, "days": days, "decision": decision, "severity": severity, "action": action}


def _when(ts: str | None) -> str:
    if not ts:
        return "-"
    try:
        return datetime.fromisoformat(ts).astimezone(timezone.utc).strftime("%d %b %H:%M UTC")
    except ValueError:
        return ts


def _reasons(rs: list) -> str:
    texts = [r.get("text", "") if isinstance(r, dict) else str(r) for r in (rs or [])]
    return "; ".join(t for t in texts if t)[:400] or "no recorded reasons"


def authorization_needed(question: str) -> str | None:
    m = DANGEROUS.search(question)
    if m and re.match(r"\s*(please\s+)?(can you\s+)?(quarantine|release|revoke|lock|unlock|freeze|unfreeze|delete|"
                      r"disable|block|restart|approve|reject|apply|rollback)\b", question, re.I):
        return m.group(0)
    return None


async def compose(question: str, fetch: Fetch, allowed: Callable[[str], Awaitable[bool]],
                  users: list[str], services: list[str]) -> dict:
    intent, scores = classify(question)
    ent = entities(question, users, services)
    out = {"question": question, "intent": intent, "entities": {k: v for k, v in ent.items() if v},
           "answer": "", "items": [], "sources": [], "suggested_actions": []}

    if act := authorization_needed(question):
        out["intent"] = "action_request"
        out["answer"] = (f"I do not perform security actions myself (\"{act}\"). Actions like this change the "
                         "platform, so they need your explicit authorization: open the page that performs it, "
                         "review the target and confirm with your authenticator code. I can explain the evidence "
                         "first - for example ask \"why was … blocked\" or \"summarize incident INC-…\".")
        out["suggested_actions"].append({"action": act, "requires_authorization": True,
                                         "where": "Threat center / Container security / Identity & devices"})
        return out

    perm = INTENTS[intent][1]
    if not await allowed(perm):
        out["answer"] = f"Your role is not permitted to read this information ({perm}), so I cannot answer it."
        out["denied"] = perm
        return out

    async def get(path, **params):
        out["sources"].append(path)
        return await fetch(path, params)

    if intent == "help":
        out["answer"] = ("I answer questions from the live platform data you are allowed to see: risk decisions, "
                         "fraud predictions, incidents, Falco events, containers, vulnerabilities, devices and the "
                         "audit log. Try one of the examples. I never take actions on my own.")
        out["items"] = [{"example": e} for e in EXAMPLES]

    elif intent == "why_blocked":
        ai = await get("ai", days=30, **({"subject": ent["user"]} if ent["user"] else {})) or {}
        decs = ai.get("decisions", [])
        pick = None
        if ent["tx_id"]:
            pick = next((d for d in decs if d.get("ref") == f"tx:{ent['tx_id']}"), None)
        if pick is None:
            pick = next((d for d in decs if d["kind"] != "login" and d["severity"] != "low"), None)
        if pick is None:
            out["answer"] = ("I found no blocked or flagged transaction" + (f" #{ent['tx_id']}" if ent["tx_id"] else "")
                             + " in the last 30 days of risk decisions.")
        else:
            eng = pick.get("engines") or {}
            top = sorted(((k, v) for k, v in eng.items() if k != "device_trust" and v), key=lambda kv: -kv[1])[:4]
            out["answer"] = (
                f"{pick['ref'] or 'The transaction'} by {pick['subject']} ({_when(pick['ts'])}) scored "
                f"{round(pick['score'] * 100)}/100 - severity {pick['severity'].upper()}, action "
                f"\"{pick.get('action') or pick['level']}\". {pick.get('explanation') or ''} "
                f"Strongest engines: " + (", ".join(f"{k} {v}/100" for k, v in top) or "none") + ". "
                f"Fraud model probability: {round((pick.get('ml_probability') or 0) * 100)}% "
                f"({pick.get('fraud_class') or 'n/a'}).")
            out["items"] = [{"reason": r.get("text"), "weight": r.get("weight"), "source": r.get("source", "")}
                            for r in pick.get("reasons", [])]
            out["suggested_actions"].append({"action": "label the decision fraud / legitimate in Fraud intelligence",
                                             "requires_authorization": False})

    elif intent == "quarantine":
        q = await get("quarantine") or {}
        state = q.get("quarantined") or {}
        if not state:
            out["answer"] = "No container is quarantined right now. " + (
                f"{len(q.get('containers', []))} service containers are running normally." if q.get("containers")
                else "")
        else:
            names = list(state)
            out["answer"] = (f"{len(names)} container(s) quarantined: {', '.join(names)}. Quarantine disconnects the "
                             "container from every network and preserves forensic evidence; release it from "
                             "Container security after the investigation (needs your authorization).")
            out["items"] = [{"service": k} | (v if isinstance(v, dict) else {"info": v}) for k, v in state.items()]

    elif intent in ("incidents", "daily_report", "investigate"):
        t = await get("threats", days=ent["days"]) or {}
        inc = t.get("incidents", [])
        if ent["severity"]:
            sel = [i for i in inc if i["severity"] == ent["severity"]
                   or (ent["severity"] == "high" and i["severity"] == "critical")]
        else:
            sel = [i for i in inc if i["severity"] in ("critical", "high")] or inc
        open_ = [i for i in sel if i["status"] != "resolved"]
        if intent == "incidents":
            span = "today" if ent["days"] == 1 else f"in the last {ent['days']} days"
            out["answer"] = (f"{len(sel)} {ent['severity'] or 'high/critical'} incident(s) {span}, {len(open_)} still "
                             "open." if sel else f"No {ent['severity'] or 'high or critical'} incidents {span}.")
            out["items"] = [{"id": i["id"], "severity": i["severity"], "status": i["status"], "title": i["title"],
                             "subject": i.get("subject"), "last_seen": i.get("last_seen")} for i in sel[:20]]
        else:
            ai = await get("ai", days=ent["days"]) or {}
            recs = await get("recommendations") or {}
            if intent == "investigate":
                items = (recs.get("items") or [])[:8]
                out["answer"] = ("Investigate in this order (highest priority first): " +
                                 "; ".join(f"{n + 1}. {r['title']}" for n, r in enumerate(items[:5]))
                                 if items else "Nothing needs investigation right now.")
                out["items"] = items
            else:
                tot = ai.get("totals", {})
                sev = t.get("detections_by_severity", {})
                out["answer"] = (
                    f"Security report ({'today' if ent['days'] == 1 else f'last {ent['days']} days'}): "
                    f"{len(inc)} incidents ({len([i for i in inc if i['status'] != 'resolved'])} open; "
                    f"{sev.get('critical', 0)} critical and {sev.get('high', 0)} high detections). "
                    f"Risk engine: {tot.get('decisions', 0)} decisions, {tot.get('flagged', 0)} flagged money "
                    f"movements, {tot.get('critical', 0)} critical, {tot.get('takeover_alerts', 0)} account-takeover "
                    f"alerts. Top recommendation: {((recs.get('items') or [{}])[0]).get('title', 'none')}.")
                out["items"] = [{"id": i["id"], "severity": i["severity"], "status": i["status"], "title": i["title"]}
                                for i in inc[:10]]
            for r in (recs.get("items") or [])[:3]:
                if r.get("requires_authorization"):
                    out["suggested_actions"].append({"action": r["title"], "requires_authorization": True,
                                                     "where": r.get("where")})

    elif intent == "incident_detail":
        if not ent["incident"]:
            out["answer"] = "Tell me the incident id (for example INC-3)."
        else:
            d = await get(f"incident:{ent['incident']}")
            if not d:
                out["answer"] = f"I could not find {ent['incident']}."
            else:
                tl = d.get("timeline", [])
                out["answer"] = (f"{d['id']}: {d['title']} - severity {d['severity']}, status {d['status']}, subject "
                                 f"{d.get('subject')}. {len(tl)} events from {_when(d.get('first_seen'))} to "
                                 f"{_when(d.get('last_seen'))}. " +
                                 (f"Playbook: {', '.join(s.get('title', '') for s in d.get('playbook', [])[:4])}."
                                  if d.get("playbook") else ""))
                out["items"] = [{"ts": e.get("ts"), "kind": e.get("kind"), "by": e.get("actor"),
                                 "event": e.get("what"), "detail": e.get("detail")} for e in tl[-25:]]

    elif intent == "device_trust":
        dv = await get("devices") or {}
        rows = dv.get("devices", [])
        if ent["user"]:
            rows = [r for r in rows if r["username"] == ent["user"]]
        low = sorted((r for r in rows if r.get("status") != "trusted" or (r.get("trust_score") or 100) < 60),
                     key=lambda r: r.get("trust_score") or 0)
        if not low:
            out["answer"] = "No untrusted or low-trust devices" + (f" for {ent['user']}." if ent["user"] else ".")
        else:
            r = low[0]
            out["answer"] = (f"{r['username']}'s {r['label']} is {r['status']} with trust score {r.get('trust_score')}"
                             f"/100 because: {'; '.join(r.get('assessment', []))}. A device becomes trusted only when "
                             "the customer approves it from an already trusted device with the authenticator code, "
                             "or the bank verifies it.")
            out["items"] = [{"user": x["username"], "device": x["label"], "status": x["status"],
                             "trust_score": x.get("trust_score"), "why": "; ".join(x.get("assessment", []))}
                            for x in low[:15]]

    elif intent == "highest_risk":
        ai = await get("ai", days=ent["days"] if ent["days"] != 7 else 30) or {}
        decs = sorted(ai.get("decisions", []), key=lambda d: -d["score"])
        if not decs:
            out["answer"] = "No risk decisions recorded in that period."
        else:
            d = decs[0]
            eng = {k: v for k, v in (d.get("engines") or {}).items() if k != "device_trust" and v}
            out["answer"] = (f"The highest score was {round(d['score'] * 100)}/100 ({d['severity']}) for {d['subject']}"
                             f" - {d['kind']} {d.get('ref') or ''} at {_when(d['ts'])}. Cause: "
                             f"{d.get('explanation') or _reasons(d.get('reasons'))}"
                             + (f" Engines: {', '.join(f'{k} {v}' for k, v in sorted(eng.items(), key=lambda kv: -kv[1]))}."
                                if eng else ""))
            out["items"] = [{"user": p["user"], "risk_rank": p["risk_rank"], "max_score": p["max_score"],
                             "critical": p["critical"], "last_flag": p.get("last")} for p in ai.get("profiles", [])[:10]]

    elif intent == "falco":
        t = await get("threats", days=ent["days"]) or {}
        ev = t.get("falco", [])
        if not ev:
            out["answer"] = "No Falco runtime events in that period - containers behaved as expected."
        else:
            cats: dict[str, int] = {}
            for e in ev:
                cats[e["category"]] = cats.get(e["category"], 0) + 1
            out["answer"] = (f"{len(ev)} Falco events: " + ", ".join(f"{n} {c.replace('_', ' ')}" for c, n in
                             sorted(cats.items(), key=lambda kv: -kv[1])) +
                             ". Falco watches system calls inside the containers; a shell, a write to the read-only "
                             "filesystem or an unexpected connection is a sign of compromise, and critical events "
                             "trigger automatic quarantine.")
            out["items"] = [{"severity": e["severity"], "category": e["category"], "subject": e["subject"],
                             "summary": e["summary"]} for e in ev[:20]]

    elif intent == "vulnerabilities":
        c = await get("containers") or {}
        trivy = c.get("trivy") or {}
        images = trivy.get("images") or trivy.get("results") or []
        if not trivy:
            out["answer"] = ("No Trivy report found - run `make scan` to scan the images. The deployment gate refuses "
                             "images with critical vulnerabilities once a report exists.")
        else:
            worst = sorted(images, key=lambda i: -((i.get("critical") or 0) * 100 + (i.get("high") or 0)))
            out["answer"] = ("Vulnerability summary: " + ", ".join(
                f"{i.get('image') or i.get('service')}: {i.get('critical', 0)} critical / {i.get('high', 0)} high"
                for i in worst[:6]) + ". Rebuild on a patched base image and redeploy; the gate blocks critical CVEs.")
            out["items"] = worst[:20]

    elif intent == "zero_trust":
        ai = await get("ai", days=ent["days"], **({"subject": ent["user"]} if ent["user"] else {})) or {}
        denied = [d for d in ai.get("decisions", []) if d.get("action") in ("block", "hold", "step_up")]
        out["answer"] = ("Every request is verified: mTLS workload identity, a device-bound MFA token, the session and "
                         "device checks at the gateway, the adaptive risk score, and finally the OPA policy, which "
                         "allows, asks for step-up MFA, holds for review or denies. " +
                         (f"Recent non-allow decisions: " + "; ".join(
                             f"{d['subject']} {d['kind']} -> {d['action']} ({d.get('explanation') or ''})"
                             for d in denied[:3]) if denied else "No recent step-up, hold or block decisions."))
        out["items"] = [{"user": d["subject"], "kind": d["kind"], "action": d["action"], "severity": d["severity"],
                         "why": d.get("explanation")} for d in denied[:15]]

    elif intent == "fraud_model":
        m = await get("model") or {}
        mon = await get("monitoring") or {}
        t = m.get("test", {})
        out["answer"] = (f"Serving {m.get('champion_name', m.get('champion', '?'))} ({m.get('version')}), chosen from "
                         f"{len(m.get('candidates', []))} candidates by validation PR-AUC. On the held-out test split: "
                         f"PR-AUC {t.get('pr_auc')}, ROC-AUC {t.get('roc_auc')}, precision {t.get('precision')}, "
                         f"recall {t.get('recall')}, F1 {t.get('f1')}, false-positive rate "
                         f"{t.get('false_positive_rate')}. Live drift status: "
                         f"{(mon.get('drift') or {}).get('status', 'unknown')}. {m.get('caveat', '')}")
        out["items"] = [{"model": c["name"], "validation_pr_auc": c["validation_pr_auc"],
                         "test_pr_auc": c["test"]["pr_auc"], "f1": c["test"]["f1"],
                         "latency_ms": c["latency"]["p50_single_ms"]} for c in m.get("candidates", [])]

    elif intent == "search":
        params = {"limit": 50}
        if ent["user"]:
            params["actor"] = ent["user"]
        if ent["action"]:
            params["action"] = ent["action"]
        if ent["decision"]:
            params["decision"] = ent["decision"]
        if ent["severity"]:
            params["severity"] = ent["severity"]
        if ent["service"]:
            params["service"] = ent["service"]
        since = datetime.now(timezone.utc).timestamp() - ent["days"] * 86400
        params["since"] = datetime.fromtimestamp(since, timezone.utc).isoformat(timespec="seconds")
        res = await get("explore", **params) or {}
        rows = res.get("rows", [])
        filt = ", ".join(f"{k}={v}" for k, v in params.items() if k not in ("limit",))
        out["answer"] = f"{len(rows)} audit entries match ({filt})." if rows else f"No audit entries match ({filt})."
        out["items"] = [{"id": r["id"], "ts": r["ts"], "actor": r["actor"], "action": r["action"],
                         "decision": r["decision"], "reason": r.get("reason")} for r in rows[:30]]
    out["scores"] = {k: v for k, v in scores.items() if v}
    return out
