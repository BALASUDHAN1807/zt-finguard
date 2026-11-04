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


STATUS_LABEL = {"completed": "Completed", "denied": "Blocked", "step_up_required": "Extra code needed",
                "pending_approval": "Waiting for approval", "cancelled": "Cancelled", "rejected": "Rejected"}


def compact_money(x: float) -> str:
    """Indian short form for tiles: 50110 -> 50.1K, 2500000 -> 25.0L, 30000000 -> 3.0Cr."""
    for size, unit in ((1e7, "Cr"), (1e5, "L"), (1e3, "K")):
        if x >= size:
            return f"{INR}{x / size:.1f}{unit}"
    return f"{INR}{x:,.0f}"


def daypart() -> str:
    h = datetime.now().hour
    return "morning" if h < 12 else "afternoon" if h < 17 else "evening"


def money(x: float) -> str:
    return f"{INR}{x:,.2f}"


# ------------------------------------------------------------------- styles
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;500;600;700&family=Source+Serif+4:opsz,wght@8..60,500;8..60,600&display=swap');
:root {
  --ink:#0B3D4A; --night:#072A33; --brass:#B8892B; --surface:#F3F5F6; --card:#FFFFFF;
  --line:#D9E0E3; --text:#15262C; --muted:#5A6B71; --credit:#1F7A4D; --debit:#B42318;
}
html, body, [class*="css"], .stMarkdown, .stTextInput, .stButton, .stRadio, .stTabs, .stDataFrame {
  font-family:'Public Sans', system-ui, sans-serif;
}
[data-testid="stAppViewContainer"] {background:var(--surface);}
[data-testid="stHeader"] {background:transparent; height:0;}
[data-testid="stDecoration"] {display:none;}
[data-testid="stToolbar"] {display:none;}
.block-container {padding-top:96px !important; max-width:1180px;}
h1, h2, h3 {font-family:'Source Serif 4', Georgia, serif !important; color:var(--text); letter-spacing:-0.01em;}
h1 {font-weight:600 !important; font-size:2.05rem !important; padding-bottom:.2rem !important;}
h2, h3 {font-weight:600 !important;}

/* top bar */
.zt-top {position:fixed; top:0; left:0; right:0; z-index:1000200; height:62px; padding:0 max(1rem, calc(50vw - 590px));
  background:var(--night); color:#fff; display:flex; align-items:center; justify-content:space-between;
  border-bottom:3px solid var(--brass);}
.zt-brand {display:flex; align-items:center; gap:10px; font-weight:700; font-size:1.15rem; letter-spacing:.01em;}
.zt-brand small {font-weight:400; color:#A9C1C7; font-size:.85rem; margin-left:6px;}
.zt-secure {font-size:.85rem; color:#CFE0E4; display:flex; align-items:center; gap:8px;}
.zt-dot {width:8px; height:8px; border-radius:50%; background:#3FB57A; display:inline-block;}

/* sign-in hero */
.zt-hero {background:var(--ink); color:#EAF2F4; border-radius:6px; padding:44px 40px; min-height:480px;
  position:relative; overflow:hidden;}
.zt-hero h2 {font-family:'Source Serif 4', Georgia, serif !important; color:#fff !important; font-size:2.3rem !important;
  line-height:1.15; margin:0 0 16px; max-width:15ch;}
.zt-hero p {color:#C6D8DC; font-size:1.02rem; line-height:1.6; max-width:42ch;}
.zt-hero ul {list-style:none; padding:0 !important; margin:28px 0 0 !important;}
.zt-hero li {margin:0 !important;}
.zt-hero li {padding:12px 0; border-top:1px solid rgba(255,255,255,.12); color:#E3EEF0; font-size:.95rem;}
.zt-hero li b {color:#fff; font-weight:600; display:block; margin-bottom:2px;}
.zt-hero:after {content:""; position:absolute; right:-80px; bottom:-80px; width:260px; height:260px;
  border:28px solid rgba(184,137,43,.18); border-radius:50%;}

/* panels */
[data-testid="stForm"] {background:var(--card); border:1px solid var(--line) !important; border-radius:6px; padding:22px 22px 10px;}
.stTabs [data-baseweb="tab-list"] {gap:28px; border-bottom:1px solid var(--line);}
.stTabs [data-baseweb="tab"] {font-weight:600; font-size:1rem; padding:10px 0;}
.stTabs [aria-selected="true"] {color:var(--ink) !important;}
.stTabs [data-baseweb="tab-highlight"] {background:var(--brass) !important; height:3px;}
.stButton > button, .stFormSubmitButton > button {border-radius:4px; font-weight:600; padding:.55rem 1rem;}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primaryFormSubmit"] {
  background:var(--ink); border-color:var(--ink);}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primaryFormSubmit"]:hover {
  background:var(--night); border-color:var(--night);}
.stTextInput input {border-radius:4px;}
[data-testid="stExpander"] {background:var(--card); border:1px solid var(--line); border-radius:6px;}
[data-testid="stMetric"] {background:var(--card); border:1px solid var(--line); border-radius:6px; padding:14px 16px;}
[data-testid="stMetricValue"] {font-family:'Source Serif 4', Georgia, serif; color:var(--text);}
[data-testid="stDataFrame"] {border:1px solid var(--line); border-radius:6px; background:var(--card);}

/* sidebar */
[data-testid="stSidebar"] {background:var(--night);}
[data-testid="stSidebarContent"] {padding-top:66px;}
[data-testid="stSidebar"] code {background:rgba(255,255,255,.08); color:#DCE8EB;}
[data-testid="stSidebar"] * {color:#DCE8EB;}
[data-testid="stSidebar"] .stRadio label {padding:7px 10px; border-radius:4px; width:100%;}
[data-testid="stSidebar"] .stRadio label:has(input:checked) {background:rgba(255,255,255,.09); box-shadow:inset 3px 0 0 var(--brass);}
[data-testid="stSidebar"] [data-baseweb="radio"] > div:first-child {display:none;}
[data-testid="stSidebar"] .stButton > button {background:transparent; border:1px solid rgba(255,255,255,.3); color:#fff;}
[data-testid="stSidebar"] hr {border-color:rgba(255,255,255,.12);}
.zt-who {padding:4px 0 14px;}
.zt-who b {font-size:1.05rem; color:#fff;}
.zt-who span {display:block; font-size:.82rem; color:#9FB8BE; margin-top:2px;}

/* passbook */
.zt-passbook {background:var(--card); border:1px solid var(--line); border-top:4px solid var(--brass);
  border-radius:6px; padding:26px 30px; display:grid; grid-template-columns:1.4fr 1fr 1fr; gap:24px; margin:6px 0 22px;}
.zt-passbook .k {color:var(--muted); font-size:.88rem; margin-bottom:6px;}
.zt-passbook .bal {font-family:'Source Serif 4', Georgia, serif; font-size:2.6rem; font-weight:600; color:var(--ink);
  font-variant-numeric:tabular-nums; line-height:1.1;}
.zt-passbook .v {font-size:1.15rem; font-weight:600; color:var(--text); font-variant-numeric:tabular-nums; letter-spacing:.04em;}
@media (max-width: 760px) {.zt-passbook {grid-template-columns:1fr;} .zt-brand small, .zt-secure, .zt-hero {display:none;}
  .zt-hero {min-height:auto; padding:30px 24px;}}

/* footer */
.zt-foot {margin-top:48px; padding:18px 0 8px; border-top:1px solid var(--line); color:var(--muted); font-size:.82rem; line-height:1.6;}

/* existing helpers */
.zt-pill {display:inline-block;padding:2px 10px;border-radius:4px;font-size:0.78rem;font-weight:600;}
.zt-allow {background:#E3F2EA;color:var(--credit);}
.zt-deny {background:#FBE7E5;color:var(--debit);}
.zt-step {background:#FBF0D9;color:#7A5410;}
.zt-card {background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px 16px;margin-bottom:8px;}
.zt-muted {color:var(--muted);font-size:.85rem;}
.zt-posture {display:flex; gap:18px; align-items:center; background:var(--card); border:1px solid var(--line);
  border-top:4px solid var(--brass); border-radius:6px; padding:18px 20px;}
.zt-posture-level {font-family:'Source Serif 4', Georgia, serif; font-size:1.6rem; font-weight:600;}
.zt-critical {background:#F6DCD8;color:#8E1B12;} .zt-high {background:#FBE7E5;color:#B42318;}
.zt-medium {background:#FBF0D9;color:#7A5410;} .zt-low {background:#E4EEF1;color:#2F5D6B;} .zt-info {background:#EEF1F2;color:#5A6B71;}
*:focus-visible {outline:2px solid var(--brass) !important; outline-offset:2px;}
</style>
""", unsafe_allow_html=True)

SHIELD = ('<svg width="26" height="28" viewBox="0 0 26 28" aria-hidden="true"><path d="M13 1 2 5v8c0 7 4.7 12 11 14 '
          '6.3-2 11-7 11-14V5L13 1z" fill="#0B3D4A" stroke="#B8892B" stroke-width="1.6"/><path d="M8 14l3.4 3.4L18.5 '
          '10" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def topbar(signed_in: bool) -> None:
    right = ('<span class="zt-secure"><span class="zt-dot"></span>Secure session over TLS 1.3</span>' if signed_in
             else '<span class="zt-secure">Demonstration bank, no real money</span>')
    st.markdown(f'<div class="zt-top"><div class="zt-brand">{SHIELD}ZT-FinGuard<small>Zero Trust banking</small>'
                f'</div>{right}</div>', unsafe_allow_html=True)


def footer() -> None:
    st.markdown('<div class="zt-foot">ZT-FinGuard is a demonstration bank built for a Linux &amp; Container '
                'Technology course project at SRM Institute of Science and Technology. It holds no real money and '
                'is not connected to any bank or payment network.<br>The bank will never ask for your password, '
                'SMS code or authenticator code by phone, email or chat.</div>', unsafe_allow_html=True)


def pill(decision: str) -> str:
    cls = {"allow": "zt-allow", "deny": "zt-deny", "step_up": "zt-step", "alert": "zt-deny",
           "pending_approval": "zt-step",
           "critical": "zt-critical", "high": "zt-high", "medium": "zt-medium", "low": "zt-low",
           "info": "zt-info"}.get(decision, "")
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
    left, right = st.columns([1.15, 1], gap="large")
    with left:
        st.markdown("""<div class="zt-hero">
<h2>Every request checked. Every time.</h2>
<p>Your money moves only after we confirm it is really you, on a device you trust, asking for something that looks like you.</p>
<ul>
<li><b>Sign in with your mobile</b>A one-time SMS code. Unfamiliar devices also need your authenticator app.</li>
<li><b>Every transfer is risk-checked</b>Unusual payments ask for an extra code; risky ones are stopped before money leaves.</li>
<li><b>Your session is yours</b>Locked to this browser and closed automatically when you step away.</li>
</ul></div>""", unsafe_allow_html=True)
    with right:
        if ss.notice:
            st.warning(ss.notice)
        if ss.last_transfer and ss.last_transfer["body"].get("decision") == "deny":
            render_result(ss.last_transfer)
            ss.last_transfer = None
        st.markdown("## Welcome back")
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
        me = api("GET", "/api/me", background=True)
        info = me.json() if me is not None and me.status_code == 200 else {}
        trust = info.get("device_trust", "pending")
        icon = {"trusted": "Trusted device", "pending": "Device waiting for approval"}.get(trust, trust)
        st.markdown(f'<div class="zt-who"><b>{ss.user}</b><span>{ss.role.title()} account</span>'
                    f'<span>Verified sign-in, {icon.lower()}</span></div>', unsafe_allow_html=True)
        if ss.role == "customer" and trust != "trusted":
            st.info("New device: you can view your account, but transfers stay blocked until you approve "
                    "this device from a trusted one (Security settings).")
        pages = {
            "customer": ["My account", "Send money", "Security settings"],
            "teller": ["Account lookup", "Security settings"],
            "operations": ["Banking & transactions", "Security settings"],
            "admin": ["Security overview", "Identity & devices", "AI fraud intelligence", "Access decisions", "Audit integrity",
                      "Session & device policy", "Container security", "Security settings"],
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
    st.title(f"Good {daypart()}, {S().user}")
    acct = a["account_no"]
    grouped = " ".join(acct[i:i + 4] for i in range(0, len(acct), 4))
    opened = datetime.fromisoformat(a["opened"][:10]).strftime("%d %b %Y")
    st.markdown(f"""<div class="zt-passbook">
<div><div class="k">Available balance</div><div class="bal">{money(a["balance"])}</div></div>
<div><div class="k">Savings account</div><div class="v">{grouped}</div></div>
<div><div class="k">Customer since</div><div class="v">{opened}</div></div>
</div>""", unsafe_allow_html=True)
    if a.get("status") == "frozen":
        st.error("This account is **frozen** by the bank's operations team"
                 + (f" ({a['frozen_reason']})" if a.get("frozen_reason") else "")
                 + ". You can view it, but no money can be sent or received until it is unfrozen.")
    if a.get("daily_limit"):
        used = a.get("used_today", 0)
        st.progress(min(1.0, used / a["daily_limit"]),
                    text=f"Sent today {money(used)} of your {money(a['daily_limit'])} daily limit")
    st.subheader("Recent activity")
    t = api("GET", "/api/accounts/me/transactions")
    rows = t.json() if t is not None and t.status_code == 200 else []
    if not rows:
        st.info("No transactions yet.")
        return
    df = pd.DataFrame(rows)
    df["when"] = local_time(df["created_at"], "%d %b %H:%M")
    df["counterparty"] = df.apply(lambda x: x["to_account"] if x["direction"] == "out" else x["from_account"], axis=1)
    df["amount"] = df.apply(lambda x: (-1 if x["direction"] == "out" else 1) * x["amount"], axis=1)
    raw_rows = rows
    df["status"] = df["status"].map(STATUS_LABEL).fillna(df["status"])
    st.dataframe(
        df[["when", "counterparty", "amount", "status", "risk_score"]],
        hide_index=True, use_container_width=True,
        column_config={
            "when": st.column_config.TextColumn("Date"),
            "counterparty": st.column_config.TextColumn("To / from account"),
            "amount": st.column_config.NumberColumn("Amount (₹)", format="%+.2f"),
            "status": st.column_config.TextColumn("Status"),
            "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=1, format="%.2f"),
        })
    customer_tx_tools(raw_rows)


def send_money() -> None:
    ss = S()
    st.title("Send money")
    st.caption("Every transfer is risk-scored and checked against policy before any money moves.")
    me = api("GET", "/api/me", background=True)
    if me is not None and me.status_code == 200 and me.json().get("device_trust") != "trusted":
        st.warning("This device is **not trusted yet**, so transfers from it will be refused. "
                   "Approve it from a trusted device under *Security settings*.")
    bens = beneficiaries_panel()
    with st.form("transfer"):
        choices = ["Enter an account number"] + [f"{b['nickname']} ({b['account_no']})" for b in bens]
        payee = st.selectbox("Pay to", choices)
        to = st.text_input("To account", placeholder="ZT10000000xx") if payee == choices[0] else \
            payee.rsplit("(", 1)[1].rstrip(")")
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
        receipt_button(d["transaction_id"], "last_receipt")
    elif decision == "pending_approval":
        st.info(f"{money(lt['amount'])} to {lt['to']} is **waiting for approval** (transaction "
                f"#{d['transaction_id']}). High-value transfers are checked by an operations officer before the "
                "money moves. You can cancel it from My account until then.")
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
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = ["#8E1B12", "#B42318", "#B8892B", "#5A8A9A", "#A7B4B9"]
DECISION_COLORS = {"allow": "#1F7A4D", "deny": "#B42318", "step_up": "#B8892B", "alert": "#8E1B12", "info": "#A7B4B9"}


def local_time(series: pd.Series, fmt: str = "%H:%M:%S") -> pd.Series:
    return pd.to_datetime(series, utc=True).dt.tz_convert("Asia/Kolkata").dt.strftime(fmt)


def posture_ring(score: int, level: str) -> str:
    color = "#1F7A4D" if score >= 85 else "#B8892B" if score >= 65 else "#B42318"
    c = 2 * 3.14159 * 52
    return f"""<div class="zt-posture">
<svg width="132" height="132" viewBox="0 0 132 132" style="flex:none;width:132px;height:132px" role="img" aria-label="Security posture {score} of 100">
<circle cx="66" cy="66" r="52" fill="none" stroke="#E3E9EB" stroke-width="12"/>
<circle cx="66" cy="66" r="52" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"
 stroke-dasharray="{c * score / 100:.1f} {c:.1f}" transform="rotate(-90 66 66)"/>
<text x="66" y="72" text-anchor="middle" font-size="34" font-weight="600" fill="#15262C"
 font-family="Source Serif 4, Georgia, serif">{score}</text></svg>
<div><div class="zt-posture-level" style="color:{color}">{level}</div>
<div class="zt-muted">Security posture, out of 100. Computed live from the controls listed alongside.</div></div></div>"""


def notifications(alerts: list[dict]) -> None:
    label = f"🔔 Alerts ({len(alerts)})" if alerts else "🔔 No alerts"
    with st.popover(label, use_container_width=True):
        if not alerts:
            st.write("Nothing critical or high in the last 24 hours.")
        for a in alerts[:12]:
            st.markdown(f"{pill(a['severity'])} **{a['action']}** by {a['actor']}  \n"
                        f"<span class='zt-muted'>{a['reason'] or '-'} · {local_time(pd.Series([a['ts']])).iloc[0]}</span>",
                        unsafe_allow_html=True)


def global_search() -> None:
    q = st.text_input("Search", placeholder="Search users, transactions, containers and incidents",
                      label_visibility="collapsed", key="global_q")
    if len(q.strip()) < 2:
        return
    r = api("GET", "/api/admin/search", params={"q": q.strip()})
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "search unavailable")
        return
    d = r.json()
    t = st.tabs([f"Users ({len(d['users'])})", f"Transactions ({len(d['transactions'])})",
                 f"Containers ({len(d['containers'])})", f"Incidents and events ({len(d['events'])})"])
    with t[0]:
        if d["users"]:
            st.dataframe(pd.DataFrame(d["users"]), hide_index=True, use_container_width=True)
        else:
            st.caption("No matching users.")
    with t[1]:
        if d["transactions"]:
            df = pd.DataFrame(d["transactions"])
            df["created_at"] = local_time(df["created_at"], "%d %b %H:%M")
            st.dataframe(df, hide_index=True, use_container_width=True)
            st.caption("Amounts and balances are hidden from administrators (separation of duties).")
        else:
            st.caption("No matching transactions.")
    with t[2]:
        if d["containers"]:
            st.dataframe(pd.DataFrame(d["containers"])[["service", "state", "health", "status"]],
                         hide_index=True, use_container_width=True)
        else:
            st.caption("No matching containers.")
    with t[3]:
        if d["events"]:
            df = pd.DataFrame(d["events"])
            df["ts"] = local_time(df["ts"], "%d %b %H:%M:%S")
            st.dataframe(df[["ts", "severity", "actor", "action", "decision", "reason"]],
                         hide_index=True, use_container_width=True)
        else:
            st.caption("No matching events.")


def security_overview() -> None:
    st.title("Security overview")
    global_search()
    overview_live()
    quick_actions()


@st.fragment(run_every=10)
def overview_live() -> None:
    r = api("GET", "/api/admin/overview", background=True)
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    o = r.json()
    s = o["summary"] or {"total": 0, "by_decision": {}, "series": [], "severity": {}, "fraud": {}, "incidents": [],
                         "alerts": [], "feed": [], "logins": []}
    bd = s["by_decision"]
    cont = o["containers"]
    running = sum(1 for c in cont if c["state"] == "running")
    healthy_c = sum(1 for c in cont if c["health"] == "healthy")
    h = st.columns([3, 1])
    h[0].caption(f"Last 24 hours, refreshed {datetime.now().strftime('%H:%M:%S')} (every 10 s)")
    with h[1]:
        notifications(s["alerts"])

    # ---- posture + headline numbers
    left, right = st.columns([1.05, 2])
    with left:
        p = o["posture"]
        st.markdown(posture_ring(p["score"], p["level"]), unsafe_allow_html=True)
        with st.expander("How the score is calculated"):
            st.dataframe(pd.DataFrame(p["parts"]), hide_index=True, use_container_width=True,
                         column_config={"points": st.column_config.ProgressColumn(
                             "points", min_value=0, max_value=25, format="%.1f")})
    with right:
        k = st.columns(4)
        k[0].metric("Requests verified", f"{s['total']:,}")
        k[1].metric("Allowed", f"{bd.get('allow', 0):,}")
        k[2].metric("Denied", f"{bd.get('deny', 0):,}")
        k[3].metric("Step-up MFA", f"{bd.get('step_up', 0):,}")
        k = st.columns(3)
        k[0].metric("Active incidents", len(s["incidents"]))
        k[1].metric("Running containers", f"{running} / {len(cont)}" if cont else "-")
        k[2].metric("Container health", f"{round(100 * healthy_c / len(cont))}%" if cont else "-")

    # ---- events graph + severity
    a, b = st.columns([1.6, 1])
    with a:
        st.subheader("Security events")
        if s["series"]:
            df = pd.DataFrame(s["series"])
            df["hour"] = pd.to_datetime(df["hour"], utc=True).dt.tz_convert("Asia/Kolkata")
            end = pd.Timestamp.now(tz="Asia/Kolkata").floor("h")
            hours = pd.date_range(end - pd.Timedelta(hours=23), end, freq="h")
            order = [h.strftime("%H:00") for h in hours]
            df = df[df["hour"] >= hours[0]]
            df["hour"] = df["hour"].dt.strftime("%H:00")
            st.altair_chart(alt.Chart(df).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
                x=alt.X("hour:O", title=None, sort=order, scale=alt.Scale(domain=order),
                        axis=alt.Axis(labelAngle=0, values=order[::3])),
                y=alt.Y("n:Q", title="events per hour", stack=True),
                color=alt.Color("decision:N", title=None, scale=alt.Scale(
                    domain=list(DECISION_COLORS), range=list(DECISION_COLORS.values())),
                    legend=alt.Legend(orient="top")),
                tooltip=["hour", "decision", "n"]).properties(height=250), use_container_width=True)
        else:
            st.info("No events yet.")
    with b:
        st.subheader("Threat severity")
        sev = s["severity"]
        df = pd.DataFrame({"severity": SEV_ORDER, "events": [sev.get(x, 0) for x in SEV_ORDER]})
        st.altair_chart(alt.Chart(df).mark_bar(cornerRadiusEnd=2).encode(
            y=alt.Y("severity:N", sort=SEV_ORDER, title=None),
            x=alt.X("events:Q", title="events (24 h)", axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color("severity:N", legend=None, scale=alt.Scale(domain=SEV_ORDER, range=SEV_COLORS)),
            tooltip=["severity", "events"]).properties(height=250), use_container_width=True)

    # ---- fraud
    st.subheader("Fraud detection")
    f = s["fraud"]
    k = st.columns(6)
    k[0].metric("Transfers checked", f.get("transfers_checked", 0))
    k[1].metric("Blocked", f.get("blocked", 0))
    k[2].metric("Extra code asked", f.get("step_up", 0))
    k[3].metric("Amount stopped", compact_money(f.get("blocked_amount", 0)))
    k[4].metric("High-risk accounts", f.get("high_risk_accounts", 0))
    k[5].metric("Average risk", f"{f['avg_transfer_risk']:.2f}" if f.get("avg_transfer_risk") is not None else "-")

    # ---- incidents + live feed
    a, b = st.columns([1, 1.5])
    with a:
        st.subheader("Active incidents")
        if s["incidents"]:
            df = pd.DataFrame(s["incidents"])
            df["last"] = local_time(df["last"])
            st.dataframe(df[["severity", "actor", "action", "reason", "count", "last"]], hide_index=True,
                         use_container_width=True, height=320)
        else:
            st.success("No critical or high-severity activity in the last 24 hours.")
    with b:
        st.subheader("Live security feed")
        if s["feed"]:
            df = pd.DataFrame(s["feed"])
            df["ts"] = local_time(df["ts"])
            st.dataframe(df[["ts", "severity", "service", "actor", "action", "decision", "reason"]],
                         hide_index=True, use_container_width=True, height=320,
                         column_config={"ts": "time"})

    # ---- logins + health
    a, b = st.columns([1.3, 1])
    with a:
        st.subheader("Recent sign-in activity")
        if s["logins"]:
            df = pd.DataFrame(s["logins"])
            df["ts"] = local_time(df["ts"])
            df["ip"] = df["details"].apply(lambda d: (d or {}).get("ip", "-"))
            df["method"] = df.apply(lambda x: "SMS code requested" if x["action"] == "auth.otp_request"
                                    else (x["reason"] or "-"), axis=1)
            st.dataframe(df[["ts", "actor", "decision", "method", "ip"]], hide_index=True,
                         use_container_width=True, height=300,
                         column_config={"ts": "time", "actor": "user", "decision": "result"})
        else:
            st.info("No sign-ins yet.")
    with b:
        st.subheader("Microservice health")
        hc = {c["service"]: c for c in cont}
        rows = [{"service": h["name"], "mTLS probe": "ok" if h["healthy"] else "failing",
                 "ms": h["ms"], "container": hc.get(h["name"], {}).get("health", "-")} for h in o["health"]]
        for c in cont:
            if c["service"] not in {r["service"] for r in rows}:
                rows.append({"service": c["service"], "mTLS probe": "-", "ms": None, "container": c["health"]})
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True, height=300,
                     column_config={"ms": st.column_config.NumberColumn("probe ms", format="%.1f")})

    with st.expander("Denial reasons, Zero Trust overhead and image scans"):
        stats_details(o, s)


def stats_details(o: dict, s: dict) -> None:
    lat = o["latency"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Transfer decision p95", f"{lat['transfer_decision_p95_ms']} ms"
              if lat["transfer_decision_p95_ms"] is not None else "-")
    c2.metric("Gateway token check p95", f"{lat['gateway_check_p95_ms']} ms"
              if lat["gateway_check_p95_ms"] is not None else "-")
    c3.metric("Audit chain", "intact" if (o.get("chain") or {}).get("ok") else "check needed")
    deny = [e for e in s["feed"] if e["decision"] == "deny"]
    if deny:
        df = pd.DataFrame(deny)["reason"].value_counts().rename_axis("reason").reset_index(name="count")
        st.altair_chart(alt.Chart(df).mark_bar(color="#9B3B2F", cornerRadiusEnd=2).encode(
            x=alt.X("count:Q", axis=alt.Axis(tickMinStep=1, format="d")), y=alt.Y("reason:N", sort="-x", title=None)
        ).properties(height=180), use_container_width=True)
    if o.get("trivy"):
        st.dataframe(pd.DataFrame(o["trivy"]["images"]), hide_index=True, use_container_width=True)
    else:
        st.caption("No image scan yet. Run `make scan` (Trivy).")


def quick_actions() -> None:
    st.subheader("Quick security actions")
    c = st.columns(4)
    with c[0], st.form("qa_logout"):
        st.markdown("**Force sign-out**")
        u = st.text_input("Username", key="qa_u1")
        if st.form_submit_button("Sign out everywhere", type="primary", use_container_width=True) and u:
            res = api("POST", f"/api/admin/users/{u.strip()}/force-logout")
            st.success(f"All sessions of {u} ended.") if res is not None and res.status_code == 200 \
                else st.error(detail(res) if res is not None else "failed")
    with c[1], st.form("qa_lock"):
        st.markdown("**Lock or unlock account**")
        u = st.text_input("Username", key="qa_u2")
        lock = st.radio("Action", ["Lock", "Unlock"], horizontal=True, label_visibility="collapsed")
        if st.form_submit_button("Apply", type="primary", use_container_width=True) and u:
            res = api("POST", f"/api/admin/users/{u.strip()}/lock",
                      json={"locked": lock == "Lock", "reason": "quick action from security overview"})
            st.success(f"{u} {'locked and signed out' if lock == 'Lock' else 'unlocked'}.") \
                if res is not None and res.status_code == 200 else st.error(detail(res) if res is not None else "failed")
    with c[2], st.form("qa_quarantine"):
        st.markdown("**Isolate a container**")
        qr = api("GET", "/api/admin/quarantine", background=True)
        q = qr.json() if qr is not None and qr.status_code == 200 else {"containers": []}
        svcs = [x["service"] for x in q["containers"] if x["service"] not in ("responder", "falco")]
        svc = st.selectbox("Container", svcs or ["-"])
        if st.form_submit_button("Quarantine", type="primary", use_container_width=True) and svcs:
            res = api("POST", "/api/admin/quarantine", json={"service": svc, "reason": "quick action"})
            st.success(f"{svc} cut off from its networks. Release it under Containers & quarantine.") \
                if res is not None and res.status_code == 200 else st.error(detail(res) if res is not None else "failed")
    with c[3], st.form("qa_audit"):
        st.markdown("**Verify the audit log**")
        st.caption("Recomputes every hash in the chain to prove nothing was edited or deleted.")
        if st.form_submit_button("Verify now", type="primary", use_container_width=True):
            res = api("GET", "/api/admin/audit/verify")
            v = res.json() if res is not None and res.status_code == 200 else {}
            st.success(f"Chain intact ({v.get('checked', '?')} entries).") if v.get("ok") \
                else st.error(f"Chain broken: {v.get('problem', 'unavailable')}")


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
        color=alt.Color("model:N", legend=None, scale=alt.Scale(range=["#0B3D4A", "#A7B4B9"])),
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

# ------------------------------------------------ admin module 2: identity
def identity_devices() -> None:
    st.title("Identity & devices")
    st.caption("Who can sign in, from which devices, and what is signed in right now.")
    t = st.tabs(["Users", "Devices", "Active sessions", "Sign-in history"])
    with t[0]:
        identity_users()
    with t[1]:
        identity_device_list()
    with t[2]:
        identity_sessions()
    with t[3]:
        identity_logins()


def ok_or_error(res, success: str) -> None:
    if res is not None and res.status_code == 200:
        st.success(success)
    else:
        d = detail(res) if res is not None else "no response"
        st.error(d["error"] if isinstance(d, dict) and "error" in d else d)


def identity_users() -> None:
    r = api("GET", "/api/admin/users")
    users = r.json() if r is not None and r.status_code == 200 else []
    if not users:
        st.info("No users found.")
        return
    df = pd.DataFrame(users)
    k = st.columns(5)
    k[0].metric("Users", len(df))
    k[1].metric("Customers", int((df["role"] == "customer").sum()))
    k[2].metric("Staff", int((df["role"] != "customer").sum()))
    k[3].metric("Locked", int(df["locked"].sum()))
    k[4].metric("Signed in now", int((df["active_sessions"] > 0).sum()))
    f1, f2 = st.columns([1, 2])
    roles = f1.multiselect("Role", sorted(df["role"].unique()), placeholder="All roles")
    q = f2.text_input("Find user", placeholder="Username or mobile digits")
    view = df[df["role"].isin(roles)] if roles else df
    if q:
        view = view[view["username"].str.contains(q, case=False) | view["mobile"].fillna("").str.contains(q)]
    view = view.assign(
        status=view["locked"].map({True: "Locked", False: "Active"}),
        mfa=view.apply(lambda x: "Authenticator + SMS" if x["mfa_sms"] else "Authenticator", axis=1),
        devices=view.apply(lambda x: f"{x['devices_trusted']} trusted, {x['devices_pending']} pending"
                           + (f", {x['devices_revoked']} revoked" if x["devices_revoked"] else ""), axis=1),
        last_seen=local_time(view["last_seen"], "%d %b %H:%M").fillna("never"))
    st.dataframe(view[["username", "role", "status", "mobile", "mfa", "devices", "active_sessions",
                       "failed_attempts", "last_login_ip", "last_seen"]],
                 hide_index=True, use_container_width=True,
                 column_config={"active_sessions": "sessions", "failed_attempts": "failed sign-ins",
                                "last_login_ip": "last IP", "mfa": "MFA enrolled"})

    st.subheader("Manage a user")
    names = [u["username"] for u in users if u["username"] != S().user]
    who = st.selectbox("User", names)
    cur = next(u for u in users if u["username"] == who)
    c = st.columns(3)
    with c[0], st.form("role_form"):
        st.markdown(f"**Role** (now: {cur['role']})")
        roles = ["customer", "teller", "operations", "admin"]
        role = st.selectbox("New role", roles, index=roles.index(cur["role"]) if cur["role"] in roles else 0)
        code = st.text_input("Your authenticator code", max_chars=6, key="role_code")
        if st.form_submit_button("Change role", type="primary", use_container_width=True):
            ok_or_error(api("PUT", f"/api/admin/users/{who}/role", json={"role": role, "totp": code.strip()}),
                        f"{who} is now {role}. Their sessions were ended so the new role applies at next sign-in.")
    with c[1], st.form("lock_form"):
        st.markdown(f"**Account** ({'locked' if cur['locked'] else 'active'})")
        reason = st.text_input("Reason", placeholder="e.g. reported stolen phone")
        label = "Unlock account" if cur["locked"] else "Lock account"
        if st.form_submit_button(label, type="primary", use_container_width=True):
            ok_or_error(api("POST", f"/api/admin/users/{who}/lock",
                            json={"locked": not cur["locked"], "reason": reason}),
                        f"{who} {'unlocked' if cur['locked'] else 'locked and signed out everywhere'}.")
    with c[2], st.form("logout_form"):
        st.markdown(f"**Sessions** ({cur['active_sessions']} active)")
        st.caption("Ends every session and refresh token of this user at once.")
        if st.form_submit_button("Force sign-out", type="primary", use_container_width=True):
            ok_or_error(api("POST", f"/api/admin/users/{who}/force-logout"), f"All sessions of {who} ended.")


def identity_device_list() -> None:
    r = api("GET", "/api/admin/devices")
    d = r.json() if r is not None and r.status_code == 200 else {"counts": {}, "devices": []}
    c = d["counts"]
    k = st.columns(4)
    k[0].metric("Devices", sum(c.values()))
    k[1].metric("Trusted", c.get("trusted", 0))
    k[2].metric("Waiting for approval", c.get("pending", 0))
    k[3].metric("Revoked", c.get("revoked", 0))
    if not d["devices"]:
        st.info("No devices registered yet.")
        return
    df = pd.DataFrame(d["devices"])
    status = st.radio("Show", ["All", "pending", "trusted", "revoked"], horizontal=True, key="dev_filter")
    view = df if status == "All" else df[df["status"] == status]
    view = view.assign(first_seen=local_time(view["first_seen"], "%d %b %H:%M"),
                       last_seen=local_time(view["last_seen"], "%d %b %H:%M"))
    st.dataframe(view[["id", "username", "label", "status", "fingerprint", "first_ip", "last_ip",
                       "first_seen", "last_seen", "verified_by"]],
                 hide_index=True, use_container_width=True,
                 column_config={"label": "device", "fingerprint": "fingerprint (SHA-256, first 16)",
                                "verified_by": "approved by"})
    st.caption("A device is registered automatically at its first sign-in: the first device of a user is "
               "trusted, every later one waits for approval. The fingerprint is a hash of the browser's "
               "device id and user agent.")
    st.subheader("Approve or revoke a device")
    opts = {f"#{x['id']} {x['username']} - {x['label']} ({x['status']})": x for x in d["devices"]}
    pick = st.selectbox("Device", list(opts))
    dev = opts[pick]
    a, b = st.columns(2)
    with a, st.form("dev_approve"):
        st.markdown("**Approve** (device becomes trusted, transfers allowed)")
        code = st.text_input("Your authenticator code", max_chars=6, key="dev_code")
        if st.form_submit_button("Approve device", type="primary", use_container_width=True,
                                 disabled=dev["status"] == "trusted"):
            ok_or_error(api("POST", f"/api/admin/devices/{dev['id']}/approve",
                            json={"totp": code.strip(), "reason": "approved by administrator"}),
                        "Device trusted.")
    with b, st.form("dev_revoke"):
        st.markdown("**Revoke** (signs the device out and blocks it)")
        reason = st.text_input("Reason", placeholder="e.g. lost or stolen", key="dev_reason")
        if st.form_submit_button("Revoke device", type="primary", use_container_width=True,
                                 disabled=dev["status"] == "revoked"):
            res = api("POST", f"/api/admin/devices/{dev['id']}/revoke", json={"reason": reason})
            ok_or_error(res, f"Device revoked, {res.json().get('sessions_ended', 0) if res is not None and res.status_code == 200 else 0} session(s) ended.")


def identity_sessions() -> None:
    r = api("GET", "/api/admin/sessions")
    d = r.json() if r is not None and r.status_code == 200 else {"sessions": []}
    sess = d["sessions"]
    k = st.columns(4)
    k[0].metric("Active sessions", len(sess))
    k[1].metric("Users signed in", len({x["user"] for x in sess}))
    k[2].metric("Concurrent (2+ devices)", len({x["user"] for x in sess if x["concurrent"]}))
    k[3].metric("Access token lifetime", f"{d.get('access_token_minutes', 15)} min",
                help=f"Refresh tokens rotate on every use and live at most {d.get('refresh_token_hours', 8)} h")
    if not sess:
        st.info("Nobody is signed in.")
        return
    df = pd.DataFrame(sess)
    df["started"] = pd.to_datetime(df["started_ms"].astype(int), unit="ms", utc=True).dt.tz_convert(
        "Asia/Kolkata").dt.strftime("%d %b %H:%M")
    df["idle"] = df["idle_seconds"].apply(lambda x: f"{x // 60} min {x % 60} s")
    df["flag"] = df["concurrent"].map({True: "concurrent", False: ""})
    st.dataframe(df[["user", "role", "device", "device_status", "ip", "method", "started", "idle",
                     "timeout_minutes", "flag"]], hide_index=True, use_container_width=True,
                 column_config={"timeout_minutes": "idle limit (min)", "device_status": "device trust",
                                "method": "signed in with"})
    st.caption("Each session is one refresh-token family (JWT access tokens are re-issued every 15 minutes). "
               "Revoking a session stops its tokens immediately: the gateway checks it on every request.")
    with st.form("sess_revoke"):
        opts = {f"{x['user']} on {x['device']} from {x['ip']} (since {row})": x["sid"]
                for x, row in zip(sess, df["started"])}
        pick = st.selectbox("Session", list(opts))
        if st.form_submit_button("Revoke this session", type="primary"):
            ok_or_error(api("POST", f"/api/admin/sessions/{opts[pick]}/revoke"), "Session revoked.")


def identity_logins() -> None:
    f = st.columns([1, 1, 2])
    user = f[0].text_input("User", placeholder="All users")
    only = f[1].toggle("Suspicious only")
    r = api("GET", "/api/admin/logins", params={"user": user.strip()} if user.strip() else {})
    d = r.json() if r is not None and r.status_code == 200 else {"events": [], "failed_by_user_24h": []}
    ev = d["events"]
    if not ev:
        st.info("No sign-in activity.")
        return
    df = pd.DataFrame(ev)
    df["time"] = local_time(df["ts"], "%d %b %H:%M:%S")
    df["why"] = df["suspicious"].apply(lambda x: ", ".join(x))
    df["event"] = df["action"].map({"auth.login": "sign-in", "auth.otp_request": "SMS code requested",
                                    "auth.refresh": "token refresh", "session.concurrent": "concurrent session"})
    k = st.columns(4)
    k[0].metric("Sign-in attempts", int((df["action"] == "auth.login").sum()))
    k[1].metric("Failed", int(((df["action"] == "auth.login") & (df["decision"] == "deny")).sum()))
    k[2].metric("Suspicious", int((df["why"] != "").sum()))
    k[3].metric("Distinct IPs", df["ip"].nunique())
    view = df[df["why"] != ""] if only else df
    st.dataframe(view[["time", "actor", "event", "decision", "reason", "ip", "location", "why"]],
                 hide_index=True, use_container_width=True, height=420,
                 column_config={"actor": "user", "decision": "result", "reason": "method / reason",
                                "why": "suspicious because"})
    st.caption("Location is the network type of the address. City/country needs a GeoIP database, "
               "which is a licensed download and is not bundled.")
    if d["failed_by_user_24h"]:
        st.subheader("Failed sign-ins by user (24 h)")
        fd = pd.DataFrame(d["failed_by_user_24h"]).rename(columns={"actor": "user", "n": "failed"})
        st.altair_chart(alt.Chart(fd).mark_bar(color="#B42318", cornerRadiusEnd=2).encode(
            x=alt.X("failed:Q", axis=alt.Axis(tickMinStep=1, format="d")), y=alt.Y("user:N", sort="-x", title=None),
            tooltip=["user", "failed"]).properties(height=max(120, 26 * len(fd))), use_container_width=True)


# ------------------------------------------------ module 3: banking helpers
TX_STATUS = {"completed": "Completed", "denied": "Blocked", "step_up_required": "Extra code needed",
             "pending_approval": "Waiting for approval", "cancelled": "Cancelled", "rejected": "Rejected"}


def pdf_escape(t: str) -> str:
    return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("latin-1", "replace").decode("latin-1")


def simple_pdf(title: str, rows: list[tuple[str, str]], footer: str) -> bytes:
    """One-page A4 PDF built by hand (Helvetica, no extra libraries in the image)."""
    ops = ["BT /F2 18 Tf 56 770 Td (" + pdf_escape(title) + ") Tj ET",
           "0.72 0.54 0.17 RG 2 w 56 756 m 539 756 l S"]
    y = 726
    for k, v in rows:
        ops.append(f"BT /F1 10 Tf 0.35 0.42 0.44 rg 56 {y} Td ({pdf_escape(k)}) Tj ET")
        ops.append(f"BT /F2 11 Tf 0.08 0.15 0.17 rg 220 {y} Td ({pdf_escape(v)}) Tj ET")
        y -= 24
    ops.append(f"0.85 0.88 0.89 RG 1 w 56 {y + 8} m 539 {y + 8} l S")
    for i, line in enumerate(footer.split("\n")):
        ops.append(f"BT /F1 8 Tf 0.35 0.42 0.44 rg 56 {y - 12 - 12 * i} Td ({pdf_escape(line)}) Tj ET")
    content = "\n".join(ops).encode("latin-1")
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
            b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def receipt_pdf(r: dict) -> bytes:
    when = pd.to_datetime(r["created_at"], utc=True).tz_convert("Asia/Kolkata").strftime("%d %b %Y, %H:%M:%S IST")
    rows = [("Transaction ID", str(r["transaction_id"])), ("Reference", r["reference"]), ("Date and time", when),
            ("From", f"{r['from_name']}  ({r['from_account']})"), ("To", f"{r['to_name']}  ({r['to_account']})"),
            ("Amount", f"INR {r['amount']:,.2f}"), ("Status", TX_STATUS.get(r["status"], r["status"])),
            ("Fraud risk score", f"{r['risk_score']:.2f}" if r["risk_score"] is not None else "-")]
    if r.get("decided_by"):
        rows.append(("Decided by", f"{r['decided_by']} ({r.get('note') or ''})"))
    return simple_pdf("ZT-FinGuard transaction receipt", rows,
                      "Generated by ZT-FinGuard, a demonstration bank for a Linux & Container Technology course "
                      "project.\nIt holds no real money. The reference is a SHA-256 fingerprint of this transaction.")


def receipt_button(tx_id: int, key: str) -> None:
    r = api("GET", f"/api/transactions/{tx_id}/receipt")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "receipt unavailable")
        return
    st.download_button("Download receipt (PDF)", receipt_pdf(r.json()), file_name=f"zt-finguard-receipt-{tx_id}.pdf",
                       mime="application/pdf", key=key, use_container_width=True)


def customer_tx_tools(rows: list[dict]) -> None:
    pending = [x for x in rows if x["status"] == "pending_approval" and x["direction"] == "out"]
    a, b = st.columns(2)
    with a:
        st.markdown("**Receipt**")
        opts = {f"#{x['id']} {local_time(pd.Series([x['created_at']]), '%d %b %H:%M').iloc[0]} "
                f"{money(x['amount'])} {TX_STATUS.get(x['status'], x['status'])}": x["id"] for x in rows}
        pick = st.selectbox("Transaction", list(opts), label_visibility="collapsed")
        receipt_button(opts[pick], "cust_receipt")
    with b:
        st.markdown("**Waiting for approval**")
        if not pending:
            st.caption("Nothing waiting. Transfers of ₹50,000 or more are checked by an operations officer "
                       "before the money moves; until then you can cancel them.")
        for x in pending:
            if st.button(f"Cancel #{x['id']} ({money(x['amount'])} to {x['to_account']})", key=f"cx{x['id']}",
                         use_container_width=True):
                ok_or_error(api("POST", f"/api/transactions/{x['id']}/cancel", json={"note": "cancelled by customer"}),
                            "Transfer cancelled. No money moved.")


def beneficiaries_panel() -> list[dict]:
    r = api("GET", "/api/beneficiaries")
    bens = r.json() if r is not None and r.status_code == 200 else []
    with st.expander(f"Saved payees ({len(bens)})"):
        for bn in bens:
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{bn['nickname']}**  \n<span class='zt-muted'>{bn['account_no']}</span>",
                        unsafe_allow_html=True)
            if c2.button("Remove", key=f"rmb{bn['id']}"):
                api("DELETE", f"/api/beneficiaries/{bn['id']}")
                st.rerun()
        with st.form("add_ben"):
            st.markdown("**Add a payee**")
            c = st.columns(3)
            acct = c[0].text_input("Account number", placeholder="ZT10000000xx")
            nick = c[1].text_input("Nickname", placeholder="e.g. Amma")
            code = c[2].text_input("Authenticator code", max_chars=6,
                                   help="Saving a payee is a sensitive change, so it needs a fresh code")
            if st.form_submit_button("Save payee", type="primary"):
                res = api("POST", "/api/beneficiaries", json={"account_no": acct.strip().upper(),
                                                              "nickname": nick.strip(), "totp": code.strip()})
                if res is not None and res.status_code == 200:
                    st.rerun()
                ok_or_error(res, "Saved.")
    return bens


# ---------------------------------------------- module 3: operations pages
def banking_operations() -> None:
    st.title("Banking & transactions")
    st.caption("Operations desk: accounts, transfers, approvals and limits. Security administration is a "
               "separate role (separation of duties).")
    t = st.tabs(["Overview", "Accounts", "Transactions", "Pending approvals"])
    with t[0]:
        ops_overview()
    with t[1]:
        ops_accounts()
    with t[2]:
        ops_transactions()
    with t[3]:
        ops_pending()


def ops_overview() -> None:
    r = api("GET", "/api/ops/summary")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    s = r.json()
    k = st.columns(4)
    k[0].metric("Customer deposits", compact_money(s["deposits"]))
    k[1].metric("Accounts", s["accounts"])
    k[2].metric("Frozen accounts", s["frozen"])
    k[3].metric("Low balance (< ₹1,000)", s["low_balance"])
    k = st.columns(3)
    k[0].metric("Transfers today", f"{s['today_count']} ({compact_money(s['today_amount'])})")
    k[1].metric("Waiting for approval", f"{s['pending_count']} ({compact_money(s['pending_amount'])})")
    k[2].metric("High-value transfers (24 h)", s["high_value_24h"])
    a, b = st.columns([1, 1.4])
    with a:
        st.subheader("Transfer status (24 h)")
        if s["by_status_24h"]:
            df = pd.DataFrame(s["by_status_24h"])
            df["status"] = df["status"].map(TX_STATUS).fillna(df["status"])
            st.altair_chart(alt.Chart(df).mark_bar(color="#0B3D4A", cornerRadiusEnd=2).encode(
                x=alt.X("n:Q", title="transfers", axis=alt.Axis(tickMinStep=1, format="d")),
                y=alt.Y("status:N", sort="-x", title=None), tooltip=["status", "n", "amount"]
            ).properties(height=220), use_container_width=True)
        else:
            st.info("No transfers in the last 24 hours.")
    with b:
        st.subheader("Money moved per hour")
        if s["volume_24h"]:
            df = pd.DataFrame(s["volume_24h"])
            df["hour"] = local_time(df["hour"], "%H:00")
            st.altair_chart(alt.Chart(df).mark_bar(color="#B8892B", cornerRadiusTopLeft=2,
                                                   cornerRadiusTopRight=2).encode(
                x=alt.X("hour:O", title=None, sort=None, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("amount:Q", title="₹ completed"), tooltip=["hour", "amount", "n"]
            ).properties(height=220), use_container_width=True)
        else:
            st.info("No completed transfers in the last 24 hours.")
    st.subheader("High-value transfer alerts")
    hv = api("GET", "/api/ops/transactions", params={"min_amount": 50000, "limit": 15})
    rows = hv.json() if hv is not None and hv.status_code == 200 else []
    if rows:
        df = pd.DataFrame(rows)
        df["created_at"] = local_time(df["created_at"], "%d %b %H:%M")
        df["status"] = df["status"].map(TX_STATUS).fillna(df["status"])
        st.dataframe(df[["id", "created_at", "from_name", "to_name", "amount", "status", "risk_score", "decided_by"]],
                     hide_index=True, use_container_width=True,
                     column_config={"amount": st.column_config.NumberColumn("amount (₹)", format="%.2f"),
                                    "created_at": "time", "from_name": "from", "to_name": "to"})
    else:
        st.caption("No transfers of ₹50,000 or more.")


def ops_accounts() -> None:
    r = api("GET", "/api/ops/accounts")
    rows = r.json() if r is not None and r.status_code == 200 else []
    if not rows:
        st.info("No accounts.")
        return
    df = pd.DataFrame(rows)
    q = st.text_input("Find account", placeholder="Name or account number", key="acct_q")
    view = df[df["owner"].str.contains(q, case=False) | df["account_no"].str.contains(q, case=False)] if q else df
    view = view.assign(used=(100 * view["used_today"] / view["daily_limit"]).round(0),
                       status=view["status"].map({"active": "Active", "frozen": "Frozen"}),
                       last_tx=local_time(view["last_tx"], "%d %b %H:%M").fillna("-"))
    st.dataframe(view[["account_no", "owner", "balance", "status", "daily_limit", "used_today", "used", "tx_24h",
                       "last_tx", "frozen_reason"]], hide_index=True, use_container_width=True,
                 column_config={"balance": st.column_config.NumberColumn("balance (₹)", format="%.2f"),
                                "daily_limit": st.column_config.NumberColumn("daily limit (₹)", format="%.0f"),
                                "used_today": st.column_config.NumberColumn("sent today (₹)", format="%.0f"),
                                "used": st.column_config.ProgressColumn("limit used", min_value=0, max_value=100,
                                                                        format="%d%%"),
                                "tx_24h": "transfers (24 h)", "last_tx": "last activity",
                                "frozen_reason": "freeze reason"})
    opts = {f"{x['account_no']} - {x['owner']} ({x['status']})": x for x in rows}
    pick = opts[st.selectbox("Account", list(opts))]
    a, b = st.columns(2)
    with a, st.form("freeze"):
        frozen = pick["status"] == "frozen"
        st.markdown(f"**{'Unfreeze' if frozen else 'Freeze'} account**")
        st.caption("A frozen account can be viewed but cannot send or receive money.")
        reason = st.text_input("Reason", value="" if not frozen else pick.get("frozen_reason") or "",
                               placeholder="e.g. suspected account takeover")
        if st.form_submit_button("Unfreeze" if frozen else "Freeze", type="primary", use_container_width=True):
            ok_or_error(api("POST", f"/api/ops/accounts/{pick['account_no']}/freeze",
                            json={"frozen": not frozen, "reason": reason}),
                        f"{pick['account_no']} {'unfrozen' if frozen else 'frozen'}.")
    with b, st.form("limit"):
        st.markdown("**Daily transfer limit**")
        st.caption(f"Now {money(pick['daily_limit'])}; sent today {money(pick['used_today'])}.")
        lim = st.number_input("New limit (₹)", min_value=1000.0, max_value=10_000_000.0, step=5000.0,
                              value=float(pick["daily_limit"]))
        if st.form_submit_button("Set limit", type="primary", use_container_width=True):
            ok_or_error(api("PUT", f"/api/ops/accounts/{pick['account_no']}/limit", json={"daily_limit": lim}),
                        f"Daily limit of {pick['account_no']} set to {money(lim)}.")


def ops_transactions() -> None:
    with st.form("tx_filters"):
        c = st.columns(4)
        status = c[0].selectbox("Status", ["Any"] + list(TX_STATUS), format_func=lambda x: TX_STATUS.get(x, x))
        q = c[1].text_input("Customer name or transaction id")
        account = c[2].text_input("Account number")
        dates = c[3].date_input("Dates", value=[], format="DD/MM/YYYY")
        c = st.columns(4)
        mn = c[0].number_input("Minimum amount (₹)", min_value=0.0, value=0.0, step=1000.0)
        mx = c[1].number_input("Maximum amount (₹, 0 = any)", min_value=0.0, value=0.0, step=1000.0)
        c[3].markdown("&nbsp;")
        c[3].form_submit_button("Search", type="primary", use_container_width=True)
    params = {"limit": 300}
    if status != "Any":
        params["status"] = status
    if q.strip():
        params["q"] = q.strip()
    if account.strip():
        params["account"] = account.strip().upper()
    if len(dates) >= 1:
        params["date_from"] = dates[0].isoformat()
        params["date_to"] = (dates[1] if len(dates) > 1 else dates[0]).isoformat()
    if mn:
        params["min_amount"] = mn
    if mx:
        params["max_amount"] = mx
    r = api("GET", "/api/ops/transactions", params=params)
    rows = r.json() if r is not None and r.status_code == 200 else []
    st.caption(f"{len(rows)} transactions")
    if not rows:
        return
    df = pd.DataFrame(rows)
    df["created_at"] = local_time(df["created_at"], "%d %b %H:%M")
    df["status"] = df["status"].map(TX_STATUS).fillna(df["status"])
    st.dataframe(df[["id", "created_at", "from_name", "from_account", "to_name", "to_account", "amount", "status",
                     "risk_score", "decided_by", "decision_note"]], hide_index=True, use_container_width=True,
                 height=420, column_config={"amount": st.column_config.NumberColumn("amount (₹)", format="%.2f"),
                                            "created_at": "time", "from_name": "from", "to_name": "to",
                                            "decision_note": "note"})
    a, b = st.columns(2)
    with a:
        pick = st.selectbox("Receipt for transaction", [x["id"] for x in rows])
        receipt_button(pick, "ops_receipt")
    with b:
        pend = [x for x in rows if x["status"] == "pending_approval"]
        if pend:
            pid = st.selectbox("Cancel a transfer waiting for approval", [x["id"] for x in pend])
            if st.button("Cancel transfer", use_container_width=True):
                ok_or_error(api("POST", f"/api/transactions/{pid}/cancel", json={"note": "cancelled by operations"}),
                            f"Transfer #{pid} cancelled.")


def ops_pending() -> None:
    r = api("GET", "/api/ops/transactions", params={"status": "pending_approval", "limit": 100})
    rows = r.json() if r is not None and r.status_code == 200 else []
    st.caption("Transfers of ₹50,000 or more stop here (maker-checker): the customer made the request, an "
               "operations officer checks it. Approving moves the money; rejecting returns nothing to do.")
    if not rows:
        st.success("No transfers waiting for approval.")
        return
    for x in rows:
        with st.container(border=True):
            c = st.columns([3, 2])
            c[0].markdown(f"**#{x['id']} {money(x['amount'])}** from **{x['from_name']}** ({x['from_account']}) "
                          f"to **{x['to_name']}** ({x['to_account']})  \n"
                          f"<span class='zt-muted'>requested {local_time(pd.Series([x['created_at']]), '%d %b %H:%M').iloc[0]}"
                          f", fraud risk {x['risk_score'] or 0:.2f}</span>", unsafe_allow_html=True)
            note = c[1].text_input("Note", key=f"note{x['id']}", placeholder="e.g. called customer, confirmed")
            b1, b2 = c[1].columns(2)
            if b1.button("Approve", key=f"ap{x['id']}", type="primary", use_container_width=True):
                ok_or_error(api("POST", f"/api/ops/pending/{x['id']}/approve", json={"note": note}),
                            f"#{x['id']} approved and completed.")
            if b2.button("Reject", key=f"rj{x['id']}", use_container_width=True):
                ok_or_error(api("POST", f"/api/ops/pending/{x['id']}/reject", json={"note": note}),
                            f"#{x['id']} rejected. No money moved.")


# ------------------------------------------- admin module 4: fraud intelligence
PATTERN_LABEL = {"unusual_amount": "Unusual amount for the customer", "drains_balance": "Drains most of the balance",
                 "unusual_time": "Unusual time of day", "new_payee": "First transfer to a payee",
                 "velocity": "Many transfers in 10 minutes", "mule_destination": "Empty receiving account (mule)",
                 "untrusted_device": "From an unverified device"}
LEVEL_COLORS = alt.Scale(domain=["low", "medium", "high"], range=["#1F7A4D", "#B8892B", "#B42318"])


def fraud_intelligence() -> None:
    st.title("AI fraud intelligence")
    top = st.columns([3, 1])
    top[0].caption("Every transfer is scored by the PaySim-trained model plus behavioural rules before money moves. "
                   "Amounts are shown as ratios (share of balance, times the usual) - administrators never see "
                   "balances or rupee amounts.")
    days = top[1].selectbox("Window", [1, 7, 30, 90], index=1, format_func=lambda d: f"Last {d} day{'s' * (d > 1)}")
    r = api("GET", "/api/admin/fraud", params={"days": days})
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    f = r.json()
    t = st.tabs(["Live scoring", "Patterns & anomalies", "High-risk accounts", "Model & accuracy"])
    with t[0]:
        fraud_live(f)
    with t[1]:
        fraud_patterns(f)
    with t[2]:
        fraud_accounts(f)
    with t[3]:
        fraud_model(f)


def tx_frame(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["time"] = local_time(df["ts"], "%d %b %H:%M:%S")
    df["top factors"] = df["explanation"].apply(
        lambda ex: ", ".join(str(x.get("factor") or x.get("text") or "?") for x in (ex or [])[:3]) or "-")
    df["share of balance"] = df["drain_ratio"].apply(lambda x: f"{x:.0%}" if pd.notna(x) else "-")
    df["vs usual"] = df["times_usual"].apply(lambda x: f"{x:.1f}x" if pd.notna(x) else "-")
    df["ML probability"] = df["ml_probability"].apply(lambda x: f"{x:.0%}" if pd.notna(x) else "-")
    df["level"] = df.apply(lambda x: x["level"] if isinstance(x["level"], str) else
                           ("-" if pd.isna(x["score"]) else "high" if x["score"] >= 0.75
                            else "medium" if x["score"] >= 0.4 else "low"), axis=1)
    df["label"] = df["label"].fillna("")
    return df


def fraud_live(f: dict) -> None:
    tt = f["totals"]
    k = st.columns(6)
    k[0].metric("Transfers scored", tt["transfers"])
    k[1].metric("Flagged", tt["flagged"])
    k[2].metric("Blocked", tt["blocked"])
    k[3].metric("Extra code asked", tt["step_up"])
    k[4].metric("Average risk", f"{tt['avg_score']:.2f}" if tt["avg_score"] is not None else "-")
    k[5].metric("Average ML probability", f"{tt['avg_ml_probability']:.0%}" if tt["avg_ml_probability"] else "-")
    if not f["live"]:
        st.info("No transfers in this window yet.")
        return
    st.subheader("Real-time risk scores")
    df = tx_frame(f["live"])
    st.dataframe(df[["time", "customer", "account", "score", "ML probability", "level", "decision",
                     "share of balance", "vs usual", "top factors", "label"]],
                 hide_index=True, use_container_width=True, height=360,
                 column_config={"score": st.column_config.ProgressColumn("risk score", min_value=0, max_value=1,
                                                                          format="%.2f")})
    st.subheader("Why was it flagged?")
    pool = f["suspicious"] or f["live"]
    opts = {f"#{x['tx_id'] or '-'} {x['customer']} {local_time(pd.Series([x['ts']]), '%d %b %H:%M').iloc[0]} "
            f"score {x['score'] or 0:.2f} ({x['decision']})": x for x in pool}
    x = opts[st.selectbox("Flagged transfer", list(opts))]
    a, b = st.columns([1.4, 1])
    with a:
        ex = pd.DataFrame([e | {"factor": e.get("factor") or "rule", "weight": e.get("weight") or 0,
                                "text": e.get("text") or e.get("factor") or "?"} for e in x["explanation"]]) \
            if x["explanation"] else pd.DataFrame()
        if ex.empty:
            st.caption("No risk factors: the model saw a typical transfer.")
        else:
            st.altair_chart(alt.Chart(ex).mark_bar(color="#0B3D4A", cornerRadiusEnd=2).encode(
                x=alt.X("weight:Q", title="contribution to the score"),
                y=alt.Y("text:N", sort="-x", title=None, axis=alt.Axis(labelLimit=360)),
                tooltip=["factor", "weight", "text"]).properties(height=40 * len(ex) + 30), use_container_width=True)
            st.caption("ML factors come from an occlusion explanation (each feature reset to a typical legitimate "
                       "value, measuring how much the fraud probability drops); rule factors carry fixed weights.")
    with b:
        sig = {"Risk score": f"{x['score'] or 0:.2f} ({x['level'] or '-'})",
               "ML fraud probability": f"{x['ml_probability']:.0%}" if x["ml_probability"] is not None else "-",
               "Share of balance": f"{x['drain_ratio']:.0%}" if x["drain_ratio"] is not None else "-",
               "Versus usual transfer": f"{x['times_usual']:.1f}x" if x["times_usual"] is not None else "-",
               "New payee": "yes" if x["new_payee"] else "no",
               "Hour": f"{x['hour']:02d}:00" if x["hour"] is not None else "-",
               "Transfers in 10 min": x["velocity_10m"] if x["velocity_10m"] is not None else "-",
               "Device": x["device_trust"] or "-", "Outcome": x["decision"]}
        st.dataframe(pd.DataFrame(sig.items(), columns=["signal", "value"]), hide_index=True,
                     use_container_width=True)
        if x["tx_id"]:
            with st.form("label"):
                st.markdown(f"**Analyst review** (now: {x['label'] or 'not reviewed'})")
                note = st.text_input("Note", placeholder="e.g. customer confirmed by phone")
                c1, c2 = st.columns(2)
                fraud = c1.form_submit_button("Confirmed fraud", type="primary", use_container_width=True)
                legit = c2.form_submit_button("False positive", use_container_width=True)
                if fraud or legit:
                    ok_or_error(api("POST", "/api/admin/fraud/label",
                                    json={"tx_id": x["tx_id"], "label": "fraud" if fraud else "legit", "note": note}),
                                "Label saved to the audit log. Accuracy figures update on the next refresh.")


def fraud_patterns(f: dict) -> None:
    a, b = st.columns(2)
    with a:
        st.subheader("Detected patterns")
        p = pd.DataFrame([{"pattern": PATTERN_LABEL[k], "transfers": v} for k, v in f["patterns"].items()])
        st.altair_chart(alt.Chart(p).mark_bar(color="#B8892B", cornerRadiusEnd=2).encode(
            x=alt.X("transfers:Q", axis=alt.Axis(tickMinStep=1, format="d")),
            y=alt.Y("pattern:N", sort="-x", title=None, axis=alt.Axis(labelLimit=260)),
            tooltip=["pattern", "transfers"]).properties(height=250), use_container_width=True)
    with b:
        st.subheader("Transfer frequency by hour")
        h = pd.DataFrame(f["hourly"])
        h["night"] = h["hour"].apply(lambda x: "00-06 (unusual)" if x < 6 else "day")
        st.altair_chart(alt.Chart(h).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2).encode(
            x=alt.X("hour:O", title="hour of day (IST)", axis=alt.Axis(labelAngle=0, values=list(range(0, 24, 3)))),
            y=alt.Y("transfers:Q", axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color("night:N", title=None, scale=alt.Scale(domain=["day", "00-06 (unusual)"],
                                                                     range=["#0B3D4A", "#B42318"]),
                            legend=alt.Legend(orient="top")),
            tooltip=["hour", "transfers"]).properties(height=250), use_container_width=True)
    a, b = st.columns(2)
    with a:
        st.subheader("Device-based risk")
        if f["device"]:
            d = pd.DataFrame(f["device"])
            d["flagged share"] = (d["flagged"] / d["transfers"]).round(2)
            st.dataframe(d, hide_index=True, use_container_width=True,
                         column_config={"flagged share": st.column_config.ProgressColumn(
                             "flagged share", min_value=0, max_value=1, format="%.2f")})
        st.caption("Transfers from devices that are not yet trusted are refused by policy (device_not_trusted).")
    with b:
        st.subheader("Sign-in and location anomalies")
        ls = f["login_signals"]
        k = st.columns(4)
        k[0].metric("New network", ls["network_changed"])
        k[1].metric("New device", ls["new_device"])
        k[2].metric("After failures", ls["failed_attempts"])
        k[3].metric("Odd hour", ls["odd_hour"])
        if f["location_anomaly_users"]:
            st.dataframe(pd.DataFrame(f["location_anomaly_users"]), hide_index=True, use_container_width=True)
        st.caption("Location is compared as the network a user signs in from (no GeoIP database is bundled).")
    st.subheader("Abnormal spending patterns")
    if f["spikes"]:
        st.dataframe(pd.DataFrame(f["spikes"]), hide_index=True, use_container_width=True,
                     column_config={"today": "transfers today", "usual_per_day": "usual per day"})
    else:
        st.caption("No account sent more than 3x its usual number of transfers today.")


def fraud_accounts(f: dict) -> None:
    st.subheader("High-risk accounts")
    if f["accounts"]:
        df = pd.DataFrame(f["accounts"])
        st.dataframe(df[["account", "customer", "risk_rank", "max_score", "avg_score", "transfers", "blocked",
                         "step_up", "high", "sessions_revoked", "confirmed_fraud"]], hide_index=True,
                     use_container_width=True,
                     column_config={"risk_rank": st.column_config.ProgressColumn("risk rank", min_value=0,
                                                                                  max_value=1.5, format="%.2f"),
                                    "max_score": "highest score", "avg_score": "average score",
                                    "high": "high-risk", "step_up": "extra code"})
        st.caption("Rank = 0.6 x highest score + 0.4 x average score + 0.1 per blocked transfer "
                   "+ 0.3 per analyst-confirmed fraud.")
    else:
        st.info("No transfers in this window.")
    st.subheader("Fraud alerts")
    if f["alerts"]:
        df = tx_frame(f["alerts"])
        st.dataframe(df[["time", "customer", "account", "score", "decision", "reason", "share of balance",
                         "top factors", "session_revoked"]], hide_index=True, use_container_width=True,
                     column_config={"session_revoked": "sessions ended"})
    else:
        st.success("No blocked high-risk or high-value transfers in this window.")
    st.subheader("Historical fraud analytics")
    if f["daily"]:
        d = pd.DataFrame(f["daily"]).melt(id_vars=["day"], value_vars=["low", "medium", "high"],
                                          var_name="level", value_name="transfers")
        st.altair_chart(alt.Chart(d).mark_bar().encode(
            x=alt.X("day:O", title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("transfers:Q", stack=True, axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color("level:N", scale=LEVEL_COLORS, legend=alt.Legend(orient="top"), title=None),
            tooltip=["day", "level", "transfers"]).properties(height=240), use_container_width=True)
        dd = pd.DataFrame(f["daily"])
        dd["blocked rate"] = (dd["blocked"] / dd["total"]).round(3)
        st.dataframe(dd, hide_index=True, use_container_width=True)


def fraud_model(f: dict) -> None:
    m, acc = f.get("model"), f["accuracy"]
    st.subheader("In production: accuracy against analyst reviews")
    k = st.columns(5)
    k[0].metric("Reviewed transfers", acc["labelled"])
    k[1].metric("Precision", f"{acc['precision']:.0%}" if acc["precision"] is not None else "-",
                help="Of flagged transfers that were reviewed, the share that was real fraud")
    k[2].metric("Recall", f"{acc['recall']:.0%}" if acc["recall"] is not None else "-",
                help="Of reviewed real fraud, the share the system flagged")
    k[3].metric("False-positive rate", f"{acc['false_positive_rate']:.0%}"
                if acc["false_positive_rate"] is not None else "-")
    k[4].metric("Cleared by the customer", f"{acc['step_up_cleared_by_customer']} of {acc['step_ups']}",
                help="Medium-risk transfers the customer confirmed with a fresh authenticator code")
    cm = pd.DataFrame([["Flagged", acc["true_positive"], acc["false_positive"]],
                       ["Not flagged", acc["false_negative"], acc["true_negative"]]],
                      columns=["system", "confirmed fraud", "false positive / legitimate"])
    a, b = st.columns([1, 1.4])
    with a:
        st.markdown("**Confusion matrix (reviewed transfers)**")
        st.dataframe(cm, hide_index=True, use_container_width=True)
        if not acc["labelled"]:
            st.caption("Review flagged transfers on the Live scoring tab to measure real-world precision "
                       "and false positives.")
    with b:
        st.markdown("**Fraud prediction: score distribution**")
        hdf = pd.DataFrame(f["histogram"]).melt(id_vars=["bin"], var_name="level", value_name="transfers")
        st.altair_chart(alt.Chart(hdf).mark_bar().encode(
            x=alt.X("bin:O", title="risk score", axis=alt.Axis(labelAngle=0, values=[0.0, 0.25, 0.4, 0.5, 0.75])),
            y=alt.Y("transfers:Q", stack=True, axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color("level:N", scale=LEVEL_COLORS, title=None, legend=alt.Legend(orient="top")),
            tooltip=["bin", "level", "transfers"]).properties(height=220), use_container_width=True)
        st.caption("0.40 and above asks for an extra code; 0.75 and above blocks and ends every session.")
    st.subheader("Model performance (held-out test set)")
    if not m:
        st.error("Risk engine unavailable.")
        return
    if m.get("synthetic"):
        st.warning("Trained on the bundled **synthetic PaySim-shaped sample**. Download the real PaySim dataset "
                   "and run `make train` before reporting results.")
    t = m["test"]
    c = st.columns(5)
    c[0].metric("PR-AUC", f"{t['pr_auc']:.3f}")
    c[1].metric("ROC-AUC", f"{t['roc_auc']:.3f}")
    c[2].metric("Recall @ 0.40", f"{t['at_medium']['recall']:.1%}")
    c[3].metric("Precision @ 0.40", f"{t['at_medium']['precision']:.1%}")
    c[4].metric("Precision @ 0.75", f"{t['at_high']['precision']:.1%}")
    leak = m["leaky_baseline_with_post_balances"]["pr_auc"]
    cmp = pd.DataFrame({"model": ["Leak-free model (deployed)", "Leaky baseline (not usable)"],
                        "PR-AUC": [t["pr_auc"], leak]})
    st.altair_chart(alt.Chart(cmp).mark_bar(cornerRadiusEnd=3).encode(
        x=alt.X("PR-AUC:Q", scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("model:N", title=None, sort=None, axis=alt.Axis(labelLimit=320)),
        color=alt.Color("model:N", legend=None, scale=alt.Scale(range=["#0B3D4A", "#A7B4B9"])),
        tooltip=["model", "PR-AUC"]).properties(height=120), use_container_width=True)
    st.caption("The leaky baseline uses post-transaction balances, which only exist after the money has moved.")
    with st.expander("Model card"):
        st.json({k: m[k] for k in ("dataset", "trained_at", "rows_transfer_cashout", "fraud_rate", "features")})


# ------------------------------------------- admin module 5: container security
CHECK_LABEL = {"non_root_user": "Non-root user", "read_only_rootfs": "Read-only filesystem",
               "all_caps_dropped": "All capabilities dropped", "no_new_privileges": "No new privileges",
               "not_privileged": "Not privileged", "memory_limit": "Memory limit", "pids_limit": "Process limit",
               "cpu_limit": "CPU limit", "no_host_network": "Own network namespace"}


def human_bytes(n) -> str:
    if n is None or (isinstance(n, float) and pd.isna(n)):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_uptime(s) -> str:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return "-"
    s = int(s)
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m {s % 60}s"


def container_security() -> None:
    st.title("Container security")
    r = api("GET", "/api/admin/containers")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    d = r.json()
    if not d.get("engine_connected"):
        st.error("The responder cannot reach the container engine socket, so live container data is unavailable.")
        return
    cs, eng = d["containers"], d["engine"]
    st.caption(f"{eng['name'].title()} {eng.get('version', '')} on {eng.get('os', '')}, kernel {eng.get('kernel', '')}, "
               f"cgroup v{eng.get('cgroup', '?')}. Live from the engine API via the responder (the only service "
               "with the container socket).")
    running = [c for c in cs if c["state"] == "running"]
    healthy = [c for c in cs if c["health"] in ("healthy", "no healthcheck") and c["state"] == "running"]
    k = st.columns(6)
    k[0].metric("Containers", len(cs))
    k[1].metric("Running", f"{len(running)} / {len(cs)}")
    k[2].metric("Healthy", f"{len(healthy)} / {len(cs)}")
    k[3].metric("Quarantined", sum(1 for c in cs if c["quarantined"]))
    k[4].metric("Signatures verified", f"{sum(1 for c in cs if c['signature'] == 'verified')} / {len(cs)}")
    k[5].metric("Engine mode", "rootless" if eng["rootless"] else "rootful",
                help="Rootless engines map container root to an unprivileged host user (user namespaces)")
    t = st.tabs(["Containers", "Isolation & hardening", "Images & vulnerabilities", "Processes & network",
                 "Actions & history"])
    with t[0]:
        cont_overview(cs)
    with t[1]:
        cont_isolation(cs, eng)
    with t[2]:
        cont_images(cs, d)
    with t[3]:
        cont_processes(cs)
    with t[4]:
        cont_actions(cs)


def cont_overview(cs: list[dict]) -> None:
    df = pd.DataFrame(cs)
    df["uptime"] = df["uptime_seconds"].apply(human_uptime)
    df["memory"] = df.apply(lambda x: f"{human_bytes(x['memory_bytes'])} / {human_bytes(x['memory_limit_bytes'])}",
                            axis=1)
    df["network I/O"] = df.apply(lambda x: f"{human_bytes(x['net_rx_bytes'])} in, {human_bytes(x['net_tx_bytes'])} out",
                                 axis=1)
    df["isolation"] = df["quarantined"].map({True: "QUARANTINED", False: "normal"})
    st.dataframe(df[["service", "state", "health", "uptime", "cpu_percent", "memory_percent", "memory", "pids",
                     "network I/O", "restart_count", "isolation", "hardening_score", "signature"]],
                 hide_index=True, use_container_width=True, height=440,
                 column_config={"cpu_percent": st.column_config.NumberColumn("CPU %", format="%.2f"),
                                "memory_percent": st.column_config.ProgressColumn("memory used", min_value=0,
                                                                                   max_value=100, format="%.1f%%"),
                                "pids": "processes", "restart_count": "restarts", "hardening_score": "hardening"})
    st.caption("CPU % is measured between two refreshes (the first view after a restart shows a dash). "
               "Memory excludes the page cache. Limits come from the cgroup settings in compose.yaml.")
    a, b = st.columns(2)
    with a:
        m = df[["service", "memory_bytes"]].assign(MB=df["memory_bytes"] / 1048576)
        st.altair_chart(alt.Chart(m).mark_bar(color="#0B3D4A", cornerRadiusEnd=2).encode(
            x=alt.X("MB:Q", title="memory (MB)"), y=alt.Y("service:N", sort="-x", title=None),
            tooltip=["service", alt.Tooltip("MB:Q", format=".1f")]).properties(height=280), use_container_width=True)
    with b:
        c = df[["service", "cpu_percent"]].fillna(0)
        st.altair_chart(alt.Chart(c).mark_bar(color="#B8892B", cornerRadiusEnd=2).encode(
            x=alt.X("cpu_percent:Q", title="CPU %"), y=alt.Y("service:N", sort="-x", title=None),
            tooltip=["service", "cpu_percent"]).properties(height=280), use_container_width=True)


def cont_isolation(cs: list[dict], eng: dict) -> None:
    rows = []
    for c in cs:
        row = {"service": c["service"], "user": c["user"]}
        row.update({CHECK_LABEL[k]: ("yes" if v else "NO") for k, v in c["checks"].items() if k in CHECK_LABEL})
        row["networks"] = ", ".join(n.split("_", 1)[-1] for n in c["networks"]) or "none (isolated)"
        rows.append(row)
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True, use_container_width=True, height=440)
    st.caption("Postgres starts as root only to fix its key file permissions, then drops to the postgres user; "
               "it keeps the five capabilities it needs (CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID). OPA, Redis "
               "and Postgres use their official images' own users. Check the real process users on the "
               "Processes & network tab.")
    k = st.columns(5)
    k[0].metric("Engine rootless", "yes" if eng["rootless"] else "no")
    k[1].metric("seccomp", "on" if eng["seccomp"] else "off")
    k[2].metric("AppArmor", "on" if eng["apparmor"] else "off")
    k[3].metric("SELinux", "on" if eng["selinux"] else "off")
    k[4].metric("User namespaces", "on" if eng["userns"] else "off")
    if not eng["rootless"]:
        st.info("This engine runs rootful (as in Codespaces and Docker Desktop). Containers still run as non-root "
                "users with every capability dropped; for full rootless mode run `./deploy.sh --podman` as a "
                "normal user.")


def cont_images(cs: list[dict], d: dict) -> None:
    st.subheader("Image signature verification")
    status = d.get("manifest_status", "")
    (st.success if status.startswith("valid") else st.error)(
        f"Signed manifest: {status}" + (f" (signed {d['manifest_signed_at'][:19].replace('T', ' ')} UTC)"
                                         if d.get("manifest_signed_at") else ""))
    df = pd.DataFrame(cs)
    df["size"] = df["image_size_bytes"].apply(human_bytes)
    df["built"] = df["image_created"].fillna("").str[:10]
    st.dataframe(df[["service", "image", "image_id", "built", "size", "image_user", "signature"]],
                 hide_index=True, use_container_width=True,
                 column_config={"image_id": "image digest", "image_user": "image default user"})
    st.caption("Every deployment signs the exact image digests with an Ed25519 key (scripts/sign-images.sh). "
               "The responder checks the signature and compares each running container's image digest: an image "
               "swapped after deployment shows as DIGEST MISMATCH.")
    st.subheader("Vulnerability scans (Trivy)")
    tv = d.get("trivy")
    if not tv:
        st.warning("No scan yet. Run `make scan` in the Codespace terminal (Trivy scans every image and fails "
                   "on CRITICAL findings or leaked secrets), then refresh this page.")
        return
    imgs = pd.DataFrame(tv["images"])
    k = st.columns(4)
    for i, sev in enumerate(("critical", "high", "medium", "low")):
        k[i].metric(sev.title(), int(imgs.get(sev, pd.Series([0])).sum()))
    st.dataframe(imgs, hide_index=True, use_container_width=True)
    st.caption(f"Scanned {tv.get('scanned_at', '')[:19].replace('T', ' ')} UTC.")


def cont_processes(cs: list[dict]) -> None:
    svc = st.selectbox("Container", [c["service"] for c in cs], key="proc_svc")
    r = api("GET", f"/api/admin/containers/{svc}/processes")
    if r is None or r.status_code != 200:
        st.error(detail(r) if r is not None else "unavailable")
        return
    p = r.json()
    c = next(x for x in cs if x["service"] == svc)
    k = st.columns(4)
    k[0].metric("Processes", len(p["processes"]))
    k[1].metric("Running as root", p["root_processes"])
    k[2].metric("Networks", len(c["networks"]))
    k[3].metric("Network I/O", f"{human_bytes(c['net_rx_bytes'])} / {human_bytes(c['net_tx_bytes'])}")
    if p["processes"]:
        st.dataframe(pd.DataFrame(p["processes"]), hide_index=True, use_container_width=True)
    st.caption("Process list from the engine (`top`), which works even though the images contain no shell or ps.")
    st.markdown("**Networks:** " + (", ".join(c["networks"]) or "none - the container is isolated"))


def cont_actions(cs: list[dict]) -> None:
    services = [c["service"] for c in cs if c["service"] not in ("responder", "falco")]
    a, b = st.columns(2)
    with a, st.form("cs_q"):
        st.markdown("**Quarantine**: cut a container off from every network, keep it running for forensics")
        svc = st.selectbox("Container", services, key="cs_q_svc")
        reason = st.text_input("Reason", value="suspicious behaviour reported", key="cs_q_reason")
        c1, c2 = st.columns(2)
        if c1.form_submit_button("Quarantine", type="primary", use_container_width=True):
            ok_or_error(api("POST", "/api/admin/quarantine", json={"service": svc, "reason": reason}),
                        f"{svc} isolated.")
        if c2.form_submit_button("Release", use_container_width=True):
            ok_or_error(api("POST", f"/api/admin/quarantine/{svc}/release"), f"{svc} reconnected to its networks.")
    with b, st.form("cs_r"):
        st.markdown("**Restart or recover** (needs your authenticator code)")
        svc2 = st.selectbox("Container", services, key="cs_r_svc")
        code = st.text_input("Your authenticator code", max_chars=6, key="cs_r_code")
        c1, c2 = st.columns(2)
        if c1.form_submit_button("Restart", type="primary", use_container_width=True):
            ok_or_error(api("POST", f"/api/admin/containers/{svc2}/restart", json={"totp": code.strip()}),
                        f"{svc2} restarted.")
        if c2.form_submit_button("Recover", use_container_width=True,
                                 help="Release from quarantine if needed, restart from the signed image, "
                                      "wait until healthy"):
            res = api("POST", f"/api/admin/containers/{svc2}/recover", json={"totp": code.strip()})
            if res is not None and res.status_code == 200:
                (st.success if res.json()["recovered"] else st.warning)(" -> ".join(res.json()["steps"]))
            else:
                ok_or_error(res, "")
    st.subheader("Container security history")
    pick = st.selectbox("Filter", ["All containers"] + [c["service"] for c in cs], key="cs_hist")
    h = api("GET", "/api/admin/containers/history",
            params={} if pick == "All containers" else {"service": pick})
    rows = h.json() if h is not None and h.status_code == 200 else []
    if rows:
        df = pd.DataFrame(rows)
        df["time"] = local_time(df["ts"], "%d %b %H:%M:%S")
        st.dataframe(df[["time", "severity", "service", "actor", "action", "resource", "reason"]], hide_index=True,
                     use_container_width=True, column_config={"resource": "container", "service": "source"})
    else:
        st.caption("No quarantines, restarts, recoveries or runtime alerts yet.")


# -------------------------------------------------------------------- main
ss = S()
topbar(bool(ss.token))
if not ss.token:
    login_page()
    footer()
else:
    page = sidebar()
    {
        "My account": my_account,
        "Send money": send_money,
        "Account lookup": account_lookup,
        "Security overview": security_overview,
        "Identity & devices": identity_devices,
        "Banking & transactions": banking_operations,
        "AI fraud intelligence": fraud_intelligence,
        "Access decisions": access_decisions,
        "Risk model": risk_model,
        "Audit integrity": audit_integrity,
        "Security settings": security_settings,
        "Session & device policy": session_device_policy,
        "Containers & quarantine": containers_page,
        "Container security": container_security,
    }[page]()
    footer()
