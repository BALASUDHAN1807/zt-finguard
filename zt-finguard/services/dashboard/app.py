"""ZT-FinGuard dashboard (Streamlit).

The dashboard is NOT trusted by the backend. It is an ordinary client of the
public gateway: users sign in with password + TOTP, it receives a 15-minute
token bound to this browser session's device id, and every page load goes
through the same gateway checks, mTLS hops and OPA decisions as any other
client. It has no certificates, database access or secrets of its own.

Run:  streamlit run app.py
"""
from __future__ import annotations

import os
import ssl
import time
import uuid
from datetime import datetime

import altair as alt
import httpx
import pandas as pd
import streamlit as st

GATEWAY = os.environ.get("GATEWAY_URL", "https://gateway:8443")
CA_FILE = os.environ.get("TLS_CA_FILE", "/run/secrets/ca_crt")
INR = "₹"

st.set_page_config(page_title="ZT-FinGuard", page_icon="🛡️", layout="wide")


# ------------------------------------------------------------------ session
def S():
    ss = st.session_state
    ss.setdefault("device_id", "dash-" + uuid.uuid4().hex)
    ss.setdefault("token", None)
    ss.setdefault("refresh", None)
    ss.setdefault("user", None)
    ss.setdefault("role", None)
    ss.setdefault("expires_at", 0)
    ss.setdefault("notice", None)
    ss.setdefault("pending_stepup", None)
    ss.setdefault("last_transfer", None)
    return ss


@st.cache_resource
def http() -> httpx.Client:
    return httpx.Client(base_url=GATEWAY, verify=ssl.create_default_context(cafile=CA_FILE), timeout=30)


def headers() -> dict:
    ss = S()
    h = {"X-Device-Id": ss.device_id, "User-Agent": f"ZT-FinGuard-Dashboard/1.0 ({ss.device_id[:13]})"}
    if ss.token:
        h["Authorization"] = f"Bearer {ss.token}"
    return h


def end_session(reason: str) -> None:
    ss = S()
    ss.token = ss.refresh = ss.user = ss.role = None
    ss.pending_stepup = None
    ss.notice = reason
    # keep ss.last_transfer so a blocked transfer stays explained after the session ends


def maybe_refresh() -> None:
    """Silently rotate the access token shortly before it expires."""
    ss = S()
    if ss.token and ss.refresh and ss.expires_at - time.time() < 60:
        r = http().post("/api/auth/refresh", json={"refresh_token": ss.refresh}, headers=headers())
        if r.status_code == 200:
            d = r.json()
            ss.token, ss.refresh = d["access_token"], d["refresh_token"]
            ss.expires_at = time.time() + d["expires_in"]
        else:
            end_session("Your session expired. Please sign in again.")


def api(method: str, path: str, **kw) -> httpx.Response | None:
    maybe_refresh()
    try:
        r = http().request(method, path, headers=headers(), **kw)
    except httpx.HTTPError as exc:
        st.error(f"Gateway unreachable: {exc.__class__.__name__}")
        return None
    if r.status_code == 401 and S().token:
        detail = r.json().get("detail", "session ended")
        end_session(f"Session ended by the gateway: **{detail}**")
        st.rerun()
    return r


def detail(r: httpx.Response):
    try:
        return r.json().get("detail", r.json())
    except ValueError:
        return r.text


def money(x: float) -> str:
    return f"{INR}{x:,.2f}"


# ------------------------------------------------------------------- styles
st.markdown("""
<style>
  .block-container {padding-top: 1.6rem;}
  .zt-pill {display:inline-block;padding:2px 10px;border-radius:999px;font-size:0.78rem;font-weight:600;}
  .zt-allow {background:#d1fae5;color:#065f46;}
  .zt-deny {background:#fee2e2;color:#991b1b;}
  .zt-step {background:#fef3c7;color:#92400e;}
  .zt-card {border:1px solid rgba(128,128,128,.25);border-radius:12px;padding:14px 16px;margin-bottom:8px;}
  .zt-muted {opacity:.7;font-size:.85rem;}
</style>
""", unsafe_allow_html=True)


def pill(decision: str) -> str:
    cls = {"allow": "zt-allow", "deny": "zt-deny", "step_up": "zt-step", "alert": "zt-deny"}.get(decision, "")
    return f'<span class="zt-pill {cls}">{decision.upper()}</span>'


def show_reasons(risk: dict) -> None:
    for r in risk.get("reasons", []):
        st.markdown(f"- {r['text']} <span class='zt-muted'>(+{r['weight']:.2f})</span>", unsafe_allow_html=True)
    if not risk.get("reasons"):
        st.caption("No risk factors found.")


# -------------------------------------------------------------------- login
def login_page() -> None:
    ss = S()
    left, right = st.columns([1.1, 1])
    with left:
        st.title("🛡️ ZT-FinGuard")
        st.markdown("#### Zero Trust banking demo\nEvery request is authenticated, authorised by policy and risk-scored. "
                    "Nothing is trusted because of where it comes from.")
        st.markdown("""
- Password **+** authenticator code (TOTP) on every sign-in
- 15-minute tokens, locked to this browser session
- Policy check (OPA) and fraud-risk score on every transfer
- Service-to-service traffic over mutual TLS
""")
    with right:
        if ss.notice:
            st.warning(ss.notice)
        if ss.last_transfer and ss.last_transfer["body"].get("decision") == "deny":
            render_result(ss.last_transfer)
            ss.last_transfer = None
        tab_in, tab_reg = st.tabs(["Sign in", "Open an account"])
        with tab_in:
            with st.form("login"):
                u = st.text_input("Username")
                p = st.text_input("Password", type="password")
                c = st.text_input("Authenticator code", max_chars=6, placeholder="6 digits")
                go = st.form_submit_button("Sign in", type="primary", use_container_width=True)
            if go:
                r = api("POST", "/api/auth/login", json={"username": u.strip(), "password": p, "totp": c.strip()})
                if r is not None and r.status_code == 200:
                    d = r.json()
                    ss.token, ss.refresh = d["access_token"], d["refresh_token"]
                    ss.user, ss.role = d["username"], d["role"]
                    ss.expires_at = time.time() + d["expires_in"]
                    ss.notice = None
                    ss.last_transfer = None
                    st.rerun()
                elif r is not None:
                    d = detail(r)
                    st.error(d["error"] if isinstance(d, dict) and "error" in d else d)
                    if isinstance(d, dict) and "risk" in d:
                        show_reasons(d["risk"])
        with tab_reg:
            with st.form("register"):
                nu = st.text_input("Choose a username", help="3-20 characters: a-z, 0-9, _")
                np_ = st.text_input("Choose a password", type="password", help="At least 10 characters")
                reg = st.form_submit_button("Create account", use_container_width=True)
            if reg:
                r = api("POST", "/api/auth/register", json={"username": nu.strip(), "password": np_})
                if r is not None and r.status_code == 200:
                    d = r.json()
                    st.success(f"Account **{d['account']['account_no']}** opened for {d['username']}.")
                    st.markdown("Add this key to Google Authenticator / Authy (enter manually), then sign in:")
                    st.code(d["totp_secret"])
                    st.caption(d["otpauth_uri"])
                elif r is not None:
                    st.error(detail(r))


# ----------------------------------------------------------------- sidebar
def sidebar() -> str:
    ss = S()
    with st.sidebar:
        st.markdown("### 🛡️ ZT-FinGuard")
        st.markdown(f"**{ss.user}** · `{ss.role}`")
        left = int(ss.expires_at - time.time())
        st.caption(f"MFA verified · token rotates in {max(left, 0) // 60}m {max(left, 0) % 60:02d}s")
        pages = {
            "customer": ["My account", "Send money"],
            "teller": ["Account lookup"],
            "admin": ["Security overview", "Access decisions", "Risk model", "Audit integrity"],
        }[ss.role]
        page = st.radio("Navigate", pages, label_visibility="collapsed")
        st.divider()
        if st.button("Sign out", use_container_width=True):
            api("POST", "/api/auth/logout", json={"refresh_token": ss.refresh})
            end_session("Signed out. Your token was revoked on the server.")
            st.rerun()
        st.caption(f"Device session `{ss.device_id[:13]}`")
    return page


# ---------------------------------------------------------------- customer
def my_account() -> None:
    r = api("GET", "/api/accounts/me")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    a = r.json()
    st.title("My account")
    c1, c2, c3 = st.columns(3)
    c1.metric("Balance", money(a["balance"]))
    c2.metric("Account number", a["account_no"])
    c3.metric("Opened", a["opened"][:10])
    st.subheader("Recent activity")
    t = api("GET", "/api/accounts/me/transactions")
    rows = t.json() if t is not None and t.status_code == 200 else []
    if not rows:
        st.info("No transactions yet.")
        return
    df = pd.DataFrame(rows)
    df["when"] = pd.to_datetime(df["created_at"]).dt.strftime("%d %b %H:%M")
    df["counterparty"] = df.apply(lambda x: x["to_account"] if x["direction"] == "out" else x["from_account"], axis=1)
    df["amount"] = df.apply(lambda x: (-1 if x["direction"] == "out" else 1) * x["amount"], axis=1)
    st.dataframe(
        df[["when", "counterparty", "amount", "status", "risk_score"]],
        hide_index=True, use_container_width=True,
        column_config={
            "amount": st.column_config.NumberColumn("Amount (₹)", format="%.2f"),
            "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.2f"),
        })


def send_money() -> None:
    ss = S()
    st.title("Send money")
    st.caption("Every transfer is risk-scored and checked against policy before any money moves.")
    with st.form("transfer"):
        to = st.text_input("To account", placeholder="ZT10000000xx")
        amt = st.number_input("Amount (₹)", min_value=1.0, step=100.0, value=1000.0)
        go = st.form_submit_button("Send", type="primary")
    if go:
        ss.pending_stepup = None
        do_transfer(to.strip().upper(), float(amt), None)

    if ss.pending_stepup:
        p = ss.pending_stepup
        st.warning(f"**Extra verification needed** for {money(p['amount'])} to {p['to_account']}.")
        show_reasons(p["risk"])
        with st.form("stepup"):
            code = st.text_input("Fresh authenticator code", max_chars=6)
            ok = st.form_submit_button("Verify and send", type="primary")
        if ok:
            r = api("POST", "/api/auth/step-up",
                    json={"totp": code.strip(), "to_account": p["to_account"], "amount": p["amount"]})
            if r is not None and r.status_code == 200:
                do_transfer(p["to_account"], p["amount"], r.json()["step_up_token"])
            elif r is not None:
                st.error(detail(r))

    lt = ss.last_transfer
    if lt:
        render_result(lt)


def do_transfer(to: str, amount: float, stepup: str | None) -> None:
    ss = S()
    body = {"to_account": to, "amount": round(amount, 2)}
    if stepup:
        body["step_up_token"] = stepup
    r = api("POST", "/api/transfer", json=body)
    if r is None:
        return
    d = r.json()
    if r.status_code == 403 and d.get("decision") == "step_up":
        ss.pending_stepup = {"to_account": to, "amount": round(amount, 2), "risk": d["risk"]}
        ss.last_transfer = None
        st.rerun()
    ss.pending_stepup = None
    ss.last_transfer = {"status": r.status_code, "body": d, "to": to, "amount": amount,
                        "overhead": r.headers.get("x-zt-overhead-ms")}
    if d.get("session_revoked"):
        end_session("A high-risk transfer was blocked and **all your sessions were ended** "
                    "(continuous verification). Sign in again with your authenticator.")
    st.rerun()


def render_result(lt: dict) -> None:
    d = lt["body"]
    decision = d.get("decision", "error")
    st.markdown(f"#### Result {pill(decision)}", unsafe_allow_html=True)
    if decision == "allow":
        st.success(f"Sent {money(lt['amount'])} to {lt['to']}. New balance {money(d['new_balance'])}.")
    elif decision == "deny":
        st.error("Transfer blocked: " + ", ".join(d.get("reasons", [])))
    else:
        st.error(str(d.get("detail", d)))
    if "risk" in d:
        c1, c2, c3 = st.columns(3)
        c1.metric(f"Risk score · {d['risk']['level']}", f"{d['risk']['score']:.2f}")
        c2.metric("ML fraud probability", f"{d['risk'].get('ml_probability', 0):.2f}")
        c3.metric("Zero Trust decision time", f"{lt['overhead']} ms" if lt["overhead"] else "-")
        with st.expander("Why? (explainable risk)", expanded=decision != "allow"):
            show_reasons(d["risk"])


# ------------------------------------------------------------------ teller
def account_lookup() -> None:
    st.title("Account lookup")
    st.caption("Tellers may read any account (policy `account.read:any`) but cannot move money.")
    with st.form("lookup"):
        no = st.text_input("Account number", placeholder="ZT10000000xx").strip().upper()
        go = st.form_submit_button("Look up", type="primary")
    if go and no:
        r = api("GET", f"/api/accounts/{no}")
        if r is None:
            return
        if r.status_code != 200:
            st.error(detail(r))
            return
        a = r.json()
        c1, c2, c3 = st.columns(3)
        c1.metric("Owner", a["owner"])
        c2.metric("Balance", money(a["balance"]))
        c3.metric("Opened", a["opened"][:10])
        if a["transactions"]:
            df = pd.DataFrame(a["transactions"])
            df["when"] = pd.to_datetime(df["created_at"]).dt.tz_convert("Asia/Kolkata").dt.strftime("%d %b %H:%M")
            st.dataframe(df[["when", "direction", "from_account", "to_account", "amount", "status", "risk_score"]],
                         hide_index=True, use_container_width=True,
                         column_config={"amount": st.column_config.NumberColumn("amount (₹)", format="%.2f"),
                                        "risk_score": st.column_config.ProgressColumn(
                                            "risk", min_value=0, max_value=1, format="%.2f")})


# ------------------------------------------------------------------- admin
@st.fragment(run_every=5)
def security_overview() -> None:
    r = api("GET", "/api/admin/overview")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    o = r.json()
    s, lat = o["stats"], o["latency"]
    bd = s["by_decision"]
    healthy = sum(1 for h in o["health"] if h["healthy"])

    st.title("Zero Trust security overview")
    st.caption(f"Last 24 h · refreshed {datetime.now().strftime('%H:%M:%S')} · every 5 s")
    k = st.columns(5)
    k[0].metric("Decisions logged", f"{s['total']:,}")
    k[1].metric("Denied", f"{bd.get('deny', 0):,}")
    k[2].metric("Step-up MFA", f"{bd.get('step_up', 0):,}")
    k[3].metric("Runtime alerts (Falco)", f"{s['falco_alerts']:,}")
    k[4].metric("Services healthy", f"{healthy} / {len(o['health'])}")

    left, right = st.columns([1.2, 1])
    with left:
        st.subheader("Why requests were denied")
        if s["deny_reasons"]:
            df = pd.DataFrame(s["deny_reasons"]).rename(columns={"n": "count"})
            df["reason"] = df["reason"].replace("", "(none)")
            st.altair_chart(alt.Chart(df).mark_bar(color="#b91c1c", cornerRadiusEnd=3).encode(
                x=alt.X("count:Q", title="denials", axis=alt.Axis(tickMinStep=1, format="d")),
                y=alt.Y("reason:N", sort="-x", title=None),
                tooltip=["reason", "count"]).properties(height=260), use_container_width=True)
        else:
            st.info("No denials yet.")
    with right:
        st.subheader("Risk levels scored")
        rl = s["risk_levels"]
        if rl:
            df = pd.DataFrame({"level": ["low", "medium", "high"],
                               "count": [rl.get(lv, 0) for lv in ("low", "medium", "high")]})
            st.altair_chart(alt.Chart(df).mark_bar(cornerRadiusEnd=3).encode(
                x=alt.X("level:N", sort=["low", "medium", "high"], title=None, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("count:Q", title="scores", axis=alt.Axis(tickMinStep=1, format="d")),
                color=alt.Color("level:N", legend=None, scale=alt.Scale(
                    domain=["low", "medium", "high"], range=["#15803d", "#d97706", "#b91c1c"])),
                tooltip=["level", "count"]).properties(height=260), use_container_width=True)
        else:
            st.info("No risk scores yet.")

    a, b = st.columns(2)
    with a:
        st.subheader("Zero Trust overhead")
        budget = 100.0
        p95 = lat["transfer_decision_p95_ms"]
        st.metric("Transfer decision p95 (risk + policy)", f"{p95} ms" if p95 is not None else "-")
        if p95 is not None:
            (st.success if p95 <= budget else st.warning)(
                f"{'Within' if p95 <= budget else 'Over'} the {budget:.0f} ms budget from the requirements")
        st.metric("Gateway token checks p95", f"{lat['gateway_check_p95_ms']} ms"
                  if lat["gateway_check_p95_ms"] is not None else "-")
        st.caption(f"{lat['samples']} transfer samples since gateway start")
    with b:
        st.subheader("Service health (via mTLS)")
        st.dataframe(pd.DataFrame(o["health"]), hide_index=True, use_container_width=True,
                     column_config={"healthy": st.column_config.CheckboxColumn("healthy"),
                                    "ms": st.column_config.NumberColumn("probe ms", format="%.1f")})

    st.subheader("Container image scans (Trivy)")
    if o.get("trivy"):
        st.dataframe(pd.DataFrame(o["trivy"]["images"]), hide_index=True, use_container_width=True)
        st.caption(f"Scanned {o['trivy'].get('scanned_at', '')}")
    else:
        st.info("No scan report yet. Run `make scan` to scan every image with Trivy.")


@st.fragment(run_every=5)
def access_decisions() -> None:
    st.title("Access decisions")
    f = st.segmented_control("Filter", ["all", "allow", "deny", "step_up", "alert", "info"], default="all")
    params = {"limit": 200}
    if f and f != "all":
        params["decision"] = f
    r = api("GET", "/api/admin/events", params=params)
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    df = pd.DataFrame(r.json())
    if df.empty:
        st.info("Nothing logged yet.")
        return
    df["time"] = pd.to_datetime(df["ts"]).dt.tz_convert("Asia/Kolkata").dt.strftime("%d %b %H:%M:%S")
    icon = {"allow": "🟢 allow", "deny": "🔴 deny", "step_up": "🟡 step-up", "alert": "🚨 alert", "info": "⚪ info"}
    df["decision"] = df["decision"].map(icon).fillna(df["decision"])
    st.dataframe(df[["id", "time", "service", "actor", "action", "resource", "decision", "reason", "risk"]],
                 hide_index=True, use_container_width=True, height=560,
                 column_config={"risk": st.column_config.ProgressColumn("risk", min_value=0, max_value=1,
                                                                        format="%.2f")})


def risk_model() -> None:
    r = api("GET", "/api/admin/overview")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    m = r.json().get("model")
    st.title("Risk model")
    if not m:
        st.error("Risk engine unavailable.")
        return
    if m.get("synthetic"):
        st.warning("Trained on the bundled **synthetic PaySim-shaped sample**. Download the real PaySim dataset "
                   "and run `make train` before reporting results.")
    t = m["test"]
    c = st.columns(4)
    c[0].metric("PR-AUC", f"{t['pr_auc']:.3f}")
    c[1].metric("ROC-AUC", f"{t['roc_auc']:.3f}")
    c[2].metric("Recall @ step-up (0.40)", f"{t['at_medium']['recall']:.1%}")
    c[3].metric("Precision @ block (0.75)", f"{t['at_high']['precision']:.1%}")
    st.subheader("Why post-transaction balances are excluded")
    leak = m["leaky_baseline_with_post_balances"]["pr_auc"]
    cmp = pd.DataFrame({"model": ["Leak-free model (deployed)", "Leaky baseline (not usable)"],
                        "PR-AUC": [t["pr_auc"], leak]})
    st.altair_chart(alt.Chart(cmp).mark_bar(cornerRadiusEnd=3).encode(
        x=alt.X("PR-AUC:Q", scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("model:N", title=None, sort=None, axis=alt.Axis(labelLimit=320)),
        color=alt.Color("model:N", legend=None, scale=alt.Scale(range=["#0f766e", "#94a3b8"])),
        tooltip=["model", "PR-AUC"]).properties(height=140), use_container_width=True)
    st.caption("The leaky baseline uses `newbalanceOrig` / `newbalanceDest`, which only exist *after* the money "
               "has moved. It looks better on paper but cannot be used to stop a transfer.")
    st.subheader("Model card")
    st.json({k: m[k] for k in ("dataset", "trained_at", "rows_transfer_cashout", "fraud_rate", "features")})


def audit_integrity() -> None:
    st.title("Audit log integrity")
    st.markdown("Each entry stores `SHA-256(previous hash ‖ entry)`. Editing, deleting or re-ordering any past "
                "entry breaks the chain, even if done by the database superuser.")
    if st.button("Verify the whole chain now", type="primary"):
        r = api("GET", "/api/admin/audit/verify")
        if r is None:
            return
        v = r.json()
        if v.get("ok"):
            st.success(f"Chain intact: {v['checked']:,} entries verified.")
            st.code(f"head = {v['head']}")
        else:
            st.error(f"Tampering detected at entry #{v['broken_at']}: {v['problem']} "
                     f"(checked {v['checked']:,} entries)")


# -------------------------------------------------------------------- main
ss = S()
if not ss.token:
    login_page()
else:
    page = sidebar()
    {
        "My account": my_account,
        "Send money": send_money,
        "Account lookup": account_lookup,
        "Security overview": security_overview,
        "Access decisions": access_decisions,
        "Risk model": risk_model,
        "Audit integrity": audit_integrity,
    }[page]()
