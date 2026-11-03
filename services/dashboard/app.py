"""ZT-FinGuard dashboard (Streamlit).

The dashboard is NOT trusted by the backend. It is an ordinary client of the
public gateway: users sign in with password + TOTP, it receives a 15-minute
token bound to this browser session's device id, and every page load goes
through the same gateway checks, mTLS hops and OPA decisions as any other
client. It has no certificates, database access or secrets of its own.

Run:  streamlit run app.py
"""
from __future__ import annotations

import hashlib
import os
import ssl
import time
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
def browser_identity() -> tuple[str, str]:
    """F21: identify the *browser*, not the Streamlit session, so the same browser is the
    same device on every visit. Derived from the browser's own request headers (a light
    fingerprint - see docs for its limits)."""
    h = {k.lower(): v for k, v in (st.context.headers or {}).items()}
    ua = h.get("user-agent", "unknown-browser")
    basis = "|".join([ua, h.get("accept-language", ""), h.get("sec-ch-ua-platform", "")])
    return "web-" + hashlib.sha256(basis.encode()).hexdigest()[:24], ua


def S():
    ss = st.session_state
    if "device_id" not in ss:
        ss.device_id, ss.browser_ua = browser_identity()
    ss.setdefault("token", None)
    ss.setdefault("refresh", None)
    ss.setdefault("user", None)
    ss.setdefault("role", None)
    ss.setdefault("expires_at", 0)
    ss.setdefault("notice", None)
    ss.setdefault("pending_stepup", None)
    ss.setdefault("last_transfer", None)
    ss.setdefault("otp_mobile", "")       # F22 sign-in in progress
    ss.setdefault("otp_sent", False)
    ss.setdefault("otp_need_totp", False)
    ss.setdefault("otp_msg", None)
    return ss


@st.cache_resource
def http() -> httpx.Client:
    return httpx.Client(base_url=GATEWAY, verify=ssl.create_default_context(cafile=CA_FILE), timeout=30)


def headers(background: bool = False) -> dict:
    ss = S()
    h = {"X-Device-Id": ss.device_id, "User-Agent": ss.browser_ua}
    if ss.token:
        h["Authorization"] = f"Bearer {ss.token}"
    if background:
        h["X-ZT-Background"] = "1"   # auto-refresh: not user activity (F19)
    return h


REASONS = {
    "device_revoked": "This device was revoked from your device list.",
    "session_expired": "Your session expired.",
    "token_used_from_different_device": "This session belongs to another device.",
}


def friendly(reason: str) -> str:
    if reason.startswith("session_idle_timeout_"):
        mins = reason.rsplit("_", 1)[-1].rstrip("m")
        return f"You were signed out after **{mins} minute(s) of inactivity**. Please sign in again."
    return REASONS.get(reason, f"Session ended by the gateway: **{reason}**")


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
        r = http().post("/api/auth/refresh", json={"refresh_token": ss.refresh}, headers=headers(True))
        if r.status_code == 200:
            d = r.json()
            ss.token, ss.refresh = d["access_token"], d["refresh_token"]
            ss.expires_at = time.time() + d["expires_in"]
        else:
            end_session(friendly(str(r.json().get("detail", "session_expired"))))


PUBLIC_PATHS = ("/api/auth/login", "/api/auth/register", "/api/auth/otp/request", "/api/auth/login/otp")


def api(method: str, path: str, background: bool = False, **kw) -> httpx.Response | None:
    maybe_refresh()
    if S().token is None and path not in PUBLIC_PATHS:
        st.rerun()
    try:
        r = http().request(method, path, headers=headers(background), **kw)
    except httpx.HTTPError as exc:
        st.error(f"Gateway unreachable: {exc.__class__.__name__}")
        return None
    if r.status_code == 401 and S().token:
        end_session(friendly(str(r.json().get("detail", "session ended"))))
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


# ------------------------------------------------------- sign-in (F22 + MFA)
def signed_in(d: dict) -> None:
    ss = S()
    ss.token, ss.refresh = d["access_token"], d["refresh_token"]
    ss.user, ss.role = d["username"], d["role"]
    ss.expires_at = time.time() + d["expires_in"]
    ss.notice = None
    ss.last_transfer = None
    ss.otp_sent, ss.otp_need_totp, ss.otp_msg = False, False, None
    st.rerun()


def show_error(r: httpx.Response) -> None:
    d = detail(r)
    st.error(d["error"] if isinstance(d, dict) and "error" in d else d)
    if isinstance(d, dict) and "risk" in d:
        show_reasons(d["risk"])


def password_signin() -> None:
    with st.form("login"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        c = st.text_input("Authenticator code", max_chars=6, placeholder="6 digits")
        go = st.form_submit_button("Sign in", type="primary", use_container_width=True)
    if go:
        r = api("POST", "/api/auth/login", json={"username": u.strip(), "password": p, "totp": c.strip()})
        if r is not None and r.status_code == 200:
            signed_in(r.json())
        elif r is not None:
            show_error(r)


def send_otp(mobile: str) -> bool:
    r = api("POST", "/api/auth/otp/request", json={"mobile": mobile})
    if r is not None and r.status_code == 200:
        ss = S()
        ss.otp_mobile, ss.otp_sent, ss.otp_need_totp = mobile, True, False
        ss.otp_msg = ("info", f"Code sent to {r.json()['to']}. It is valid for 5 minutes and works once.")
        return True
    if r is not None:
        show_error(r)
    return False


def otp_signin() -> None:
    ss = S()
    if not ss.otp_sent:
        with st.form("otp_request"):
            m = st.text_input("Mobile number", placeholder="10-digit mobile number")
            go = st.form_submit_button("Send code", type="primary", use_container_width=True)
        if go and send_otp(m.strip()):
            st.rerun()
        return
    if ss.otp_msg:
        kind, text = ss.otp_msg
        getattr(st, kind)(text)
    with st.form("otp_login"):
        code = st.text_input("SMS code", max_chars=6, placeholder="6 digits from the SMS")
        totp = None
        if ss.otp_need_totp:
            totp = st.text_input("Authenticator code", max_chars=6, placeholder="6 digits from your app",
                                 help="Asked when the sign-in looks unusual: new device, new network, "
                                      "failed attempts or an odd hour")
        go = st.form_submit_button("Sign in", type="primary", use_container_width=True)
    if go:
        r = api("POST", "/api/auth/login/otp",
                json={"mobile": ss.otp_mobile, "otp": code.strip(), "totp": (totp or "").strip() or None})
        if r is not None and r.status_code == 200:
            signed_in(r.json())
        elif r is not None:
            d = detail(r)
            if isinstance(d, dict) and d.get("step_up") == "totp" and not ss.otp_need_totp:
                ss.otp_need_totp = True
                reasons = ", ".join(x["text"] for x in d.get("risk", {}).get("reasons", [])) or "unverified device"
                ss.otp_msg = ("warning", f"Extra check needed ({reasons}). Enter the SMS code again "
                                         "and the code from your authenticator app.")
                st.rerun()
            show_error(r)
    c1, c2 = st.columns(2)
    if c1.button("Resend code", use_container_width=True) and send_otp(ss.otp_mobile):
        st.rerun()
    if c2.button("Change number", use_container_width=True):
        ss.otp_sent, ss.otp_need_totp, ss.otp_msg = False, False, None
        st.rerun()
    sms_inbox(ss.otp_mobile)


def sms_inbox(mobile: str) -> None:
    """Simulated phone (SMS_PROVIDER=simulated). Hidden when a real SMS gateway is configured."""
    try:
        r = http().post("/api/demo/sms-inbox", json={"mobile": mobile}, headers=headers(True))
    except httpx.HTTPError:
        return
    if r.status_code != 200:
        return
    with st.expander(f"📱 Simulated phone {r.json()['mobile']} - SMS inbox", expanded=True):
        st.caption("Demo only: stands in for a real SMS gateway (Twilio / MSG91), which needs a paid account.")
        sms_messages(mobile)


@st.fragment(run_every=3)
def sms_messages(mobile: str) -> None:
    try:
        r = http().post("/api/demo/sms-inbox", json={"mobile": mobile}, headers=headers(True))
        msgs = r.json().get("messages", []) if r.status_code == 200 else []
    except (httpx.HTTPError, ValueError):
        msgs = []
    if not msgs:
        st.write("No messages yet.")
    for m in msgs[:3]:
        st.markdown(f"**{m['from']}** · {m['at'][11:19]} UTC  \n{m['text']}")


# -------------------------------------------------------------------- login
def login_page() -> None:
    ss = S()
    left, right = st.columns([1.1, 1])
    with left:
        st.title("🛡️ ZT-FinGuard")
        st.markdown("#### Zero Trust banking demo\nEvery request is authenticated, authorised by policy and risk-scored. "
                    "Nothing is trusted because of where it comes from.")
        st.markdown("""
- Sign in with your **mobile number + SMS code**; unusual sign-ins also need the authenticator code
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
            how = st.radio("Sign in with", ["Mobile number + SMS code", "Username + password"],
                           horizontal=True, label_visibility="collapsed")
            if how.startswith("Mobile"):
                otp_signin()
            else:
                password_signin()
        with tab_reg:
            with st.form("register"):
                nu = st.text_input("Choose a username", help="3-20 characters: a-z, 0-9, _")
                nm = st.text_input("Mobile number", placeholder="10-digit mobile number",
                                   help="Used to sign in with a one-time SMS code")
                np_ = st.text_input("Choose a password", type="password", help="At least 10 characters")
                reg = st.form_submit_button("Create account", use_container_width=True)
            if reg:
                r = api("POST", "/api/auth/register", json={"username": nu.strip(), "password": np_,
                                                         "mobile": nm.strip()})
                if r is not None and r.status_code == 200:
                    d = r.json()
                    st.success(f"Account **{d['account']['account_no']}** opened for {d['username']} "
                               f"(mobile {d['mobile']}).")
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
        me = api("GET", "/api/me", background=True)
        info = me.json() if me is not None and me.status_code == 200 else {}
        trust = info.get("device_trust", "pending")
        icon = {"trusted": "🟢 trusted device", "pending": "🟡 device pending approval"}.get(trust, trust)
        st.caption(f"MFA verified · {icon}")
        if ss.role == "customer" and trust != "trusted":
            st.info("New device: you can view your account, but transfers stay blocked until you approve "
                    "this device from a trusted one (Security settings).")
        pages = {
            "customer": ["My account", "Send money", "Security settings"],
            "teller": ["Account lookup", "Security settings"],
            "admin": ["Security overview", "Access decisions", "Risk model", "Audit integrity",
                      "Session & device policy", "Containers & quarantine", "Security settings"],
        }[ss.role]
        page = st.radio("Navigate", pages, label_visibility="collapsed")
        st.divider()
        if st.button("Sign out", use_container_width=True):
            api("POST", "/api/auth/logout", json={"refresh_token": ss.refresh})
            end_session("Signed out. Your token was revoked on the server.")
            st.rerun()
        st.caption(f"Device `{ss.device_id[:16]}`")
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
    me = api("GET", "/api/me", background=True)
    if me is not None and me.status_code == 200 and me.json().get("device_trust") != "trusted":
        st.warning("This device is **not trusted yet**, so transfers from it will be refused. "
                   "Approve it from a trusted device under *Security settings*.")
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
    r = api("GET", "/api/admin/overview", background=True)
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
    r = api("GET", "/api/admin/events", background=True, params=params)
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



# ------------------------------------------------- F19 / F21: self-service
def security_settings() -> None:
    st.title("Security settings")
    tab_s, tab_d = st.tabs(["Session timeout", "My devices"])

    with tab_s:
        r = api("GET", "/api/me/session")
        if r is None or r.status_code != 200:
            st.error(detail(r) if r is not None else "unavailable")
        else:
            cfg = r.json()
            st.markdown("Choose how long you can stay inactive before you are signed out automatically. "
                        f"Your administrator allows at most **{cfg['admin_max_minutes']} minutes**.")
            c1, c2, c3 = st.columns(3)
            c1.metric("Your choice", f"{cfg['preferred_minutes']} min")
            c2.metric("Effective timeout", f"{cfg['effective_minutes']} min")
            c3.metric("Administrator maximum", f"{cfg['admin_max_minutes']} min")
            with st.form("idle"):
                choices = cfg["choices"] or [cfg["effective_minutes"]]
                current = min(choices, key=lambda c: abs(c - cfg["effective_minutes"]))
                pick = st.select_slider("Sign me out after this many minutes of inactivity",
                                        options=choices, value=current)
                if st.form_submit_button("Save", type="primary"):
                    u = api("PUT", "/api/me/session", json={"idle_timeout_minutes": pick})
                    if u is not None and u.status_code == 200:
                        st.success(f"Saved. You will be signed out after {u.json()['effective_minutes']} "
                                   "minute(s) without activity.")
                    elif u is not None:
                        st.error(detail(u))
            st.caption("Automatic page refreshes do not count as activity. After a timeout you must sign in "
                       "again with your password and authenticator code.")

    with tab_d:
        r = api("GET", "/api/me/devices")
        if r is None or r.status_code != 200:
            st.error(detail(r) if r is not None else "unavailable")
            return
        data = r.json()
        devices = data["devices"]
        me = next((d for d in devices if d["current"]), None)
        st.markdown("Money can only be moved from a **trusted** device. A new device stays *pending* until you "
                    "approve it from a device you already trust (with a fresh authenticator code).")
        if me and me["status"] == "pending":
            if data["has_trusted"]:
                st.warning("This device is pending. Open *Security settings → My devices* on one of your "
                           "trusted devices and approve it.")
            else:
                st.warning("You have no trusted device left. Verify this one with a fresh authenticator code.")
                with st.form("selfverify"):
                    code = st.text_input("Authenticator code", max_chars=6)
                    if st.form_submit_button("Verify this device", type="primary"):
                        v = api("POST", "/api/me/devices/verify-current", json={"totp": code.strip()})
                        if v is not None and v.status_code == 200:
                            st.success("This device is now trusted.")
                            st.rerun()
                        elif v is not None:
                            st.error(detail(v))
        icons = {"trusted": "🟢", "pending": "🟡", "revoked": "🔴"}
        df = pd.DataFrame([{
            "": icons.get(d["status"], ""), "device": d["label"] + ("  (this device)" if d["current"] else ""),
            "status": d["status"], "last IP": d["last_ip"], "last seen": (d["last_seen"] or "")[:16].replace("T", " "),
            "verified": d["verified_by"] or "-", "id": d["id"]} for d in devices])
        st.dataframe(df, hide_index=True, use_container_width=True)

        can_manage = bool(me and me["status"] == "trusted")
        if not can_manage:
            st.caption("Device approvals and revocations can only be made from a trusted device.")
            return
        others = [d for d in devices if not d["current"]]
        if not others:
            st.info("Only this device is registered. Sign in from another browser or phone to see it here.")
            return
        with st.form("devop"):
            options = {f"{d['label']} · {d['status']} · #{d['id']}": d for d in others}
            choice = st.selectbox("Device", list(options))
            code = st.text_input("Fresh authenticator code (confirms it's you)", max_chars=6)
            c1, c2, c3 = st.columns(3)
            approve = c1.form_submit_button("Approve", type="primary")
            revoke = c2.form_submit_button("Revoke")
            forget = c3.form_submit_button("Remove revoked")
        if approve or revoke or forget:
            dev = options[choice]
            if forget:
                res = api("DELETE", f"/api/me/devices/{dev['id']}")
            else:
                op = "approve" if approve else "revoke"
                res = api("POST", f"/api/me/devices/{dev['id']}/{op}", json={"totp": code.strip()})
            if res is not None and res.status_code == 200:
                st.success("Done.")
                st.rerun()
            elif res is not None:
                st.error(detail(res))


# ----------------------------------------------- F19 / F21: admin policy
def session_device_policy() -> None:
    st.title("Session & device policy")
    r = api("GET", "/api/admin/session-policy")
    if r is not None and r.status_code == 200:
        pol = r.json()
        st.subheader("Maximum inactivity timeout")
        st.markdown(f"Customers choose their own timeout, up to this maximum. Currently **{pol['max_idle_minutes']} "
                    f"minutes** (set by {pol['updated_by']}). Lowering it applies to every active session "
                    "immediately.")
        with st.form("maxidle"):
            pick = st.select_slider("Maximum minutes of inactivity", options=pol["choices"],
                                    value=min(pol["choices"], key=lambda c: abs(c - pol["max_idle_minutes"])))
            if st.form_submit_button("Apply", type="primary"):
                u = api("PUT", "/api/admin/session-policy", json={"max_idle_minutes": pick})
                if u is not None and u.status_code == 200:
                    st.success(f"Maximum set to {pick} minutes.")
                elif u is not None:
                    st.error(detail(u))
    st.subheader("Device inventory")
    d = api("GET", "/api/admin/devices")
    if d is None or d.status_code != 200:
        st.error(detail(d) if d is not None else "unavailable")
        return
    inv = d.json()
    c = st.columns(3)
    c[0].metric("Trusted", inv["counts"].get("trusted", 0))
    c[1].metric("Pending approval", inv["counts"].get("pending", 0))
    c[2].metric("Revoked", inv["counts"].get("revoked", 0))
    if inv["devices"]:
        df = pd.DataFrame(inv["devices"])
        df["last_seen"] = df["last_seen"].str[:16].str.replace("T", " ")
        st.dataframe(df[["username", "label", "status", "last_ip", "last_seen"]], hide_index=True,
                     use_container_width=True)


# --------------------------------------------- F20: container quarantine
@st.fragment(run_every=5)
def containers_quarantine() -> None:
    st.title("Containers & quarantine")
    st.caption("Falco alerts at or above the configured severity automatically cut the container off from "
               "every network. It keeps running for forensics until an administrator releases it.")
    r = api("GET", "/api/admin/quarantine", background=True)
    if r is None or r.status_code != 200:
        st.error("Responder unavailable: " + str(detail(r) if r is not None else "no response"))
        return
    q = r.json()
    if not q["engine_connected"]:
        st.warning("The responder cannot reach the container engine socket, so quarantine is unavailable "
                   "(this is expected when running without containers).")
    k = st.columns(3)
    k[0].metric("Containers", len(q["containers"]))
    k[1].metric("Quarantined", len(q["quarantined"]))
    k[2].metric("Auto-quarantine at", q["min_priority"])
    for svc, rec in q["quarantined"].items():
        st.error(f"**{svc}** quarantined at {rec['at']} by {rec['actor']}: {rec['reason']}  \n"
                 f"Disconnected from: {', '.join(rec['networks'])}")
    if q["containers"]:
        df = pd.DataFrame(q["containers"])
        df["networks"] = df["networks"].apply(lambda n: ", ".join(x.split("_", 1)[-1] for x in n) or "none")
        df["quarantined"] = df["quarantined"].map({True: "🔒 isolated", False: "-"})
        st.dataframe(df[["service", "state", "status", "networks", "quarantined"]], hide_index=True,
                     use_container_width=True)


def quarantine_controls() -> None:
    st.subheader("Manual response")
    r = api("GET", "/api/admin/quarantine", background=True)
    q = r.json() if r is not None and r.status_code == 200 else {"containers": [], "quarantined": {}}
    services = [c["service"] for c in q["containers"] if c["service"] not in ("responder", "falco")]
    c1, c2 = st.columns(2)
    with c1, st.form("quarantine"):
        svc = st.selectbox("Isolate a container", services or ["-"])
        reason = st.text_input("Reason", value="suspicious behaviour reported")
        if st.form_submit_button("Quarantine", type="primary") and services:
            res = api("POST", "/api/admin/quarantine", json={"service": svc, "reason": reason})
            if res is not None and res.status_code == 200:
                st.success(f"{svc} isolated from its networks.")
            elif res is not None:
                st.error(detail(res))
    with c2, st.form("release"):
        isolated = list(q["quarantined"])
        rel = st.selectbox("Release a container", isolated or ["-"])
        if st.form_submit_button("Release") and isolated:
            res = api("POST", f"/api/admin/quarantine/{rel}/release")
            if res is not None and res.status_code == 200:
                st.success(f"{rel} reconnected to: {', '.join(res.json()['networks'])}")
            elif res is not None:
                st.error(detail(res))


def containers_page() -> None:
    containers_quarantine()
    quarantine_controls()

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
        "Security settings": security_settings,
        "Session & device policy": session_device_policy,
        "Containers & quarantine": containers_page,
    }[page]()
