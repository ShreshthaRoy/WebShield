import streamlit as st
import os
import pandas as pd
import requests
from datetime import datetime
from urllib.parse import urlparse
import socket
import re
from pathlib import Path


# ============================================================
# CONFIG
# ============================================================

st.set_page_config(
    page_title="WebShield Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "phishing_history.csv"
BACKEND_URL = "http://127.0.0.1:5000/analyze"
HEALTH_URL = "http://127.0.0.1:5000/health"


# ============================================================
# LOAD BROWSING HISTORY
# ============================================================

@st.cache_data(ttl=2)
def load_history():

    try:
        # Skip malformed legacy rows instead of making the entire dashboard fail.
        df = pd.read_csv(HISTORY_FILE, on_bad_lines="skip")

        if df.empty:
            return df

        if "risk_score" in df.columns:
            df["risk_score"] = pd.to_numeric(
                df["risk_score"],
                errors="coerce"
            ).fillna(0)

        if "time" in df.columns:
            df["time"] = pd.to_datetime(
                df["time"],
                errors="coerce"
            )

        required_columns = [
            "url",
            "risk_score",
            "status",
            "time",
            "ml_score",
            "dl_score",
            "model_score",
            "url_risk",
            "domain_risk",
            "page_risk",
            "page_analysis_available"
        ]

        for column in required_columns:
            if column not in df.columns:
                df[column] = 0 if column in {
                    "ml_score",
                    "dl_score",
                    "model_score"
                } else ""

        for column in ["ml_score", "dl_score", "model_score"]:
            df[column] = pd.to_numeric(
                df[column],
                errors="coerce"
            ).fillna(0)

        return df

    except FileNotFoundError:

        return pd.DataFrame(
            columns=[
                "url",
                "risk_score",
                "status",
                "time",
                "ml_score",
                "dl_score",
                "model_score",
                "url_risk",
                "domain_risk",
                "page_risk",
                "page_analysis_available"
            ]
        )

    except Exception as e:

        st.error(
            f"Unable to load browsing history: {e}"
        )

        return pd.DataFrame(
            columns=[
                "url", "risk_score", "status", "time", "ml_score", "dl_score",
                "model_score", "url_risk", "domain_risk", "page_risk",
                "page_analysis_available"
            ]
        )


df = load_history()


# ============================================================
# CSS — WEBSHIELD DARK SECURITY THEME
# ============================================================

st.markdown("""
<style>

/* ============================================================
   GLOBAL
   ============================================================ */

html, body, [class*="css"] {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                 Roboto, Helvetica, Arial, sans-serif;
}

.stApp {
    background:
        radial-gradient(
            circle at 15% 10%,
            rgba(37, 99, 235, 0.08),
            transparent 28%
        ),
        radial-gradient(
            circle at 85% 80%,
            rgba(14, 165, 233, 0.05),
            transparent 30%
        ),
        #07111f;

    color: #f8fafc;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}


/* ============================================================
   MAIN HEADINGS
   ============================================================ */

.main-title {
    font-size: 38px;
    font-weight: 800;
    color: #f8fafc !important;
    letter-spacing: -0.8px;
    margin-bottom: 5px;
}

.main-subtitle {
    color: #94a3b8 !important;
    font-size: 14px;
    margin-bottom: 25px;
}

h1, h2, h3, h4, h5, h6 {
    color: #f8fafc !important;
}

p {
    color: #cbd5e1 !important;
}

label {
    color: #cbd5e1 !important;
}

.stMarkdown {
    color: #cbd5e1;
}

.stMarkdown p {
    color: #cbd5e1 !important;
}

.stMarkdown strong {
    color: #f8fafc !important;
}

.stMarkdown li {
    color: #cbd5e1 !important;
}


/* ============================================================
   SIDEBAR
   ============================================================ */

[data-testid="stSidebar"] {
    background:
        linear-gradient(
            180deg,
            #030b16 0%,
            #06101d 100%
        );

    border-right: 1px solid #17263a;
}

[data-testid="stSidebar"] * {
    color: #e2e8f0;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #f8fafc !important;
}

[data-testid="stSidebar"] .stCaption,
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
    color: #64748b !important;
}

[data-testid="stSidebar"] .stRadio label {
    color: #cbd5e1 !important;
    padding: 8px 0;
    font-weight: 500;
}

[data-testid="stSidebar"] .stRadio label:hover {
    color: #60a5fa !important;
}

[data-testid="stSidebar"] hr {
    border-color: #1e293b !important;
}


/* ============================================================
   CARDS
   ============================================================ */

.card {
    background: #0d1a2b;
    border: 1px solid #1e334d;
    border-radius: 16px;
    padding: 20px;
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.25);
}

.card-title {
    color: #94a3b8 !important;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .7px;
}

.card-value {
    color: #f8fafc !important;
    font-size: 30px;
    font-weight: 800;
}

.card-description {
    color: #64748b !important;
    font-size: 12px;
}


/* ============================================================
   STREAMLIT CONTAINERS
   ============================================================ */

[data-testid="stVerticalBlockBorderWrapper"] {
    background: #0d1a2b !important;
    border: 1px solid #1e334d !important;
    border-radius: 15px !important;
}

[data-testid="stVerticalBlockBorderWrapper"] p {
    color: #cbd5e1 !important;
}


/* ============================================================
   METRICS
   ============================================================ */

[data-testid="stMetric"] {
    background: #0d1a2b !important;
    border: 1px solid #1e334d !important;
    border-radius: 14px !important;
    padding: 16px !important;
}

[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
}

[data-testid="stMetricLabel"] * {
    color: #94a3b8 !important;
}

[data-testid="stMetricValue"] {
    color: #f8fafc !important;
}

[data-testid="stMetricValue"] * {
    color: #f8fafc !important;
}

[data-testid="stMetricDelta"] {
    color: #60a5fa !important;
}


/* ============================================================
   TEXT INPUTS
   ============================================================ */

[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input {
    background: #0d1a2b !important;
    color: #f8fafc !important;
    border: 1px solid #334155 !important;
    border-radius: 10px !important;
}

[data-testid="stTextInput"] input:focus,
[data-testid="stNumberInput"] input:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 1px #3b82f6 !important;
}

[data-testid="stTextInput"] input::placeholder {
    color: #64748b !important;
}


/* ============================================================
   SELECTBOX
   ============================================================ */

[data-testid="stSelectbox"] label {
    color: #cbd5e1 !important;
}

[data-testid="stSelectbox"] div[data-baseweb="select"] {
    background: #0d1a2b !important;
    border-color: #334155 !important;
}

[data-testid="stSelectbox"] div[data-baseweb="select"] * {
    color: #f8fafc !important;
}

[data-baseweb="popover"] {
    background: #0d1a2b !important;
}

[data-baseweb="menu"] {
    background: #0d1a2b !important;
}

[data-baseweb="menu"] * {
    color: #f8fafc !important;
}


/* ============================================================
   SLIDER
   ============================================================ */

[data-testid="stSlider"] label {
    color: #cbd5e1 !important;
}

[data-testid="stSlider"] [role="slider"] {
    background: #3b82f6 !important;
}


/* ============================================================
   BUTTONS
   ============================================================ */

.stButton > button {
    background: linear-gradient(
        135deg,
        #2563eb,
        #1d4ed8
    ) !important;

    color: #ffffff !important;

    border: 1px solid #3b82f6 !important;
    border-radius: 10px !important;

    font-weight: 700 !important;

    min-height: 42px;

    transition:
        transform 0.15s ease,
        box-shadow 0.15s ease;
}

.stButton > button p {
    color: #ffffff !important;
}

.stButton > button:hover {
    background: linear-gradient(
        135deg,
        #3b82f6,
        #2563eb
    ) !important;

    color: #ffffff !important;

    border-color: #60a5fa !important;

    box-shadow:
        0 5px 20px rgba(37, 99, 235, 0.25);

    transform: translateY(-1px);
}


/* ============================================================
   SAFE / WARNING / DANGER
   ============================================================ */

.safe-box {
    background: #052e1b;
    border: 1px solid #166534;
    color: #86efac !important;
    border-radius: 12px;
    padding: 12px 15px;
    font-weight: 700;
}

.warning-box {
    background: #3a2505;
    border: 1px solid #a16207;
    color: #fcd34d !important;
    border-radius: 12px;
    padding: 12px 15px;
    font-weight: 700;
}

.danger-box {
    background: #3b0a0a;
    border: 1px solid #991b1b;
    color: #fca5a5 !important;
    border-radius: 12px;
    padding: 12px 15px;
    font-weight: 700;
}


/* ============================================================
   WEBSITE / URL
   ============================================================ */

.website-url {
    color: #f1f5f9 !important;
    font-weight: 700;
    font-size: 14px;
    word-break: break-all;
}

.website-time {
    color: #64748b !important;
    font-size: 11px;
}


/* ============================================================
   DATAFRAME
   ============================================================ */

[data-testid="stDataFrame"] {
    background: #0d1a2b !important;
    border: 1px solid #1e334d !important;
    border-radius: 12px !important;
    overflow: hidden;
}

[data-testid="stDataFrame"] * {
    color: #e2e8f0 !important;
}


/* ============================================================
   ALERTS
   ============================================================ */

[data-testid="stAlert"] {
    border-radius: 12px !important;
}

[data-testid="stAlert"] p {
    color: inherit !important;
}


/* ============================================================
   EXPANDERS
   ============================================================ */

[data-testid="stExpander"] {
    background: #0d1a2b !important;
    border: 1px solid #1e334d !important;
    border-radius: 12px !important;
}

[data-testid="stExpander"] summary {
    color: #f8fafc !important;
}

[data-testid="stExpander"] summary p {
    color: #f8fafc !important;
}


/* ============================================================
   TABS
   ============================================================ */

button[data-baseweb="tab"] {
    color: #94a3b8 !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #60a5fa !important;
}


/* ============================================================
   CHARTS
   ============================================================ */

[data-testid="stVegaLiteChart"],
[data-testid="stArrowVegaLiteChart"] {
    background: #0d1a2b !important;
    border: 1px solid #1e334d !important;
    border-radius: 14px !important;
    padding: 10px !important;
}


/* ============================================================
   PROGRESS
   ============================================================ */

[data-testid="stProgress"] {
    background: #1e293b !important;
    border-radius: 999px;
}

[data-testid="stProgress"] > div > div {
    background: #2563eb !important;
}


/* ============================================================
   CAPTIONS
   ============================================================ */

[data-testid="stCaptionContainer"],
.stCaption {
    color: #64748b !important;
}

[data-testid="stCaptionContainer"] * {
    color: #64748b !important;
}


/* ============================================================
   LINKS
   ============================================================ */

a {
    color: #60a5fa !important;
}

a:hover {
    color: #93c5fd !important;
}


/* ============================================================
   DIVIDERS
   ============================================================ */

hr {
    border-color: #1e293b !important;
}


/* ============================================================
   ARCHITECTURE
   ============================================================ */

.architecture {
    background: #0d1a2b;
    border: 1px solid #1e334d;
    border-radius: 16px;
    padding: 25px;
    text-align: center;
}

.arch-step {
    background: #111f33;
    border: 1px solid #263b55;
    border-radius: 10px;
    padding: 13px;
    margin: 7px 0;
    color: #f1f5f9 !important;
}

.arch-arrow {
    color: #64748b !important;
    font-size: 18px;
}


/* ============================================================
   INFORMATION CARDS
   ============================================================ */

.info-title {
    font-size: 17px;
    font-weight: 800;
    color: #f8fafc !important;
    margin-bottom: 8px;
}

.info-text {
    color: #94a3b8 !important;
    line-height: 1.6;
    font-size: 13px;
}


/* ============================================================
   CODE / MONOSPACE
   ============================================================ */

code {
    color: #93c5fd !important;
    background: #111827 !important;
}


/* ============================================================
   SCROLLBAR
   ============================================================ */

::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: #07111f;
}

::-webkit-scrollbar-thumb {
    background: #263449;
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: #334155;
}


/* ============================================================
   STREAMLIT HEADER / FOOTER
   ============================================================ */

#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

header {
    background: transparent !important;
}

[data-testid="stHeader"] {
    background: transparent !important;
}


/* ============================================================
   TOOLTIP / POPOVER
   ============================================================ */

[data-baseweb="tooltip"] {
    background: #111827 !important;
    color: #f8fafc !important;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# LIGHT THEME — APPEARANCE OVERRIDE
# ============================================================

if st.session_state.get("webshield_theme", "🌙 Dark") == "☀️ Light":
    st.markdown("""
    <style>
    .stApp,
    [data-testid="stAppViewContainer"] {
        background: #f4f7fb !important;
        color: #172033 !important;
    }

    [data-testid="stHeader"] {
        background: #f4f7fb !important;
    }

    [data-testid="stSidebar"] {
        background: #ffffff !important;
        border-right: 1px solid #e2e8f0 !important;
    }

    [data-testid="stSidebar"] * {
        color: #334155 !important;
    }

    .main-title,
    h1, h2, h3, h4, h5, h6 {
        color: #0f172a !important;
    }

    .main-subtitle,
    [data-testid="stCaptionContainer"],
    .stCaption {
        color: #64748b !important;
    }

    p, label,
    .stMarkdown,
    .stMarkdown p,
    .stMarkdown li {
        color: #334155 !important;
    }

    .stMarkdown strong {
        color: #0f172a !important;
    }

    .card,
    .architecture,
    .info-card,
    [data-testid="stVerticalBlockBorderWrapper"],
    [data-testid="stMetric"],
    [data-testid="stExpander"],
    [data-testid="stVegaLiteChart"],
    [data-testid="stArrowVegaLiteChart"],
    [data-testid="stDataFrame"] {
        background: #ffffff !important;
        color: #1e293b !important;
        border-color: #e2e8f0 !important;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.04) !important;
    }

    .card-title,
    [data-testid="stMetricLabel"],
    [data-testid="stMetricLabel"] *,
    .info-text {
        color: #64748b !important;
    }

    .card-value,
    [data-testid="stMetricValue"],
    [data-testid="stMetricValue"] * {
        color: #0f172a !important;
    }

    .arch-step {
        background: #eff6ff !important;
        color: #1e3a8a !important;
        border-color: #bfdbfe !important;
    }

    .safe-box {
        background: #dcfce7 !important;
        border-color: #86efac !important;
        color: #166534 !important;
    }

    .warning-box {
        background: #fef3c7 !important;
        border-color: #fcd34d !important;
        color: #92400e !important;
    }

    .danger-box {
        background: #fee2e2 !important;
        border-color: #fca5a5 !important;
        color: #991b1b !important;
    }

    .website-url {
        color: #1d4ed8 !important;
    }

    .website-time {
        color: #64748b !important;
    }

    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input,
    [data-testid="stTextArea"] textarea {
        background: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
    }

    [data-testid="stSelectbox"] div[data-baseweb="select"],
    [data-baseweb="popover"],
    [data-baseweb="menu"] {
        background: #ffffff !important;
        border-color: #cbd5e1 !important;
    }

    [data-baseweb="menu"] *,
    [data-testid="stSelectbox"] div[data-baseweb="select"] * {
        color: #0f172a !important;
    }

    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] summary p {
        color: #1e293b !important;
    }

    [data-testid="stDataFrame"] *,
    [data-testid="stTable"] * {
        color: #334155 !important;
    }

    button[data-baseweb="tab"] {
        color: #475569 !important;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        color: #1d4ed8 !important;
    }

    a {
        color: #1d4ed8 !important;
    }

    hr {
        border-color: #e2e8f0 !important;
    }

    code {
        color: #1d4ed8 !important;
        background: #eff6ff !important;
    }

    [data-testid="stProgress"] {
        background: #e2e8f0 !important;
    }
    </style>
    """, unsafe_allow_html=True)



# ============================================================
# BACKEND STATUS
# ============================================================

def backend_status():

    try:

        response = requests.get(
            HEALTH_URL,
            timeout=2
        )

        return response.status_code == 200

    except Exception:

        return False


# ============================================================
# DOMAIN
# ============================================================

def get_domain(url):

    try:

        candidate = str(url or "").strip()
        if not candidate.startswith(("http://", "https://")):
            candidate = "https://" + candidate
        parsed = urlparse(candidate)
        domain = (parsed.hostname or "").lower().removeprefix("www.")
        return domain

    except Exception:

        return str(url)


# ============================================================
# THREAT INFRASTRUCTURE INTELLIGENCE
# ============================================================

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


# ============================================================
# DNS RESOLUTION
# ============================================================

@st.cache_data(ttl=3600)
def resolve_ip(domain):

    if not domain:
        return None

    try:

        results = socket.getaddrinfo(
            domain,
            443,
            type=socket.SOCK_STREAM
        )

        ips = []

        for result in results:

            ip = result[4][0]

            if ip not in ips:
                ips.append(ip)

        return ips[0] if ips else None

    except Exception as e:

        print(
            "DNS RESOLUTION ERROR:",
            repr(e)
        )

        return None


# ============================================================
# IPINFO INTELLIGENCE
# ============================================================

@st.cache_data(ttl=300)
def get_ip_intelligence(ip):

    if not ip:
        return {
            "lookup_status": "DNS resolution failed"
        }

    token = os.getenv("IPINFO_TOKEN", "").strip()

    # Allow Streamlit secrets as an alternative to environment variables.
    if not token:
        try:
            token = str(st.secrets.get("IPINFO_TOKEN", "")).strip()
        except Exception:
            token = ""

    if not token:
        return {
            "ip": ip,
            "lookup_status": "IPINFO_TOKEN missing"
        }

    try:

        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": token},
            headers={
                "User-Agent": "WebShield/2.0"
            },
            timeout=10
        )

        print(
            "IPINFO STATUS:",
            response.status_code
        )

        if response.status_code != 200:

            print(
                "IPINFO RESPONSE:",
                response.text[:500]
            )

            return {
                "ip": ip,
                "lookup_status":
                    f"IPinfo HTTP {response.status_code}"
            }

        data = response.json()

        # ----------------------------------------------------
        # LOCATION
        # ----------------------------------------------------

        latitude = None
        longitude = None

        location = data.get("loc")

        if location:

            try:

                parts = location.split(",")

                if len(parts) == 2:
                    latitude = float(parts[0])
                    longitude = float(parts[1])

            except Exception:
                pass

        # ----------------------------------------------------
        # ASN / ORGANIZATION
        # ----------------------------------------------------

        asn = None
        organization = data.get("org")

        if organization:

            match = re.match(
                r"(AS\d+)\s+(.*)",
                organization
            )

            if match:
                asn = match.group(1)
                organization = match.group(2)

        # IPinfo's "country" field is the ISO 3166-1 alpha-2
        # country code, e.g. US, IN, DE.
        country_code = data.get("country")

        return {
            "ip": data.get("ip", ip),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": country_code,
            "country_code": country_code,
            "postal": data.get("postal"),
            "latitude": latitude,
            "longitude": longitude,
            "timezone": data.get("timezone"),
            "asn": asn,
            "organization": organization,
            "lookup_status": "success"
        }

    except requests.exceptions.Timeout:

        return {
            "ip": ip,
            "lookup_status": "IPinfo timeout"
        }

    except requests.exceptions.ConnectionError:

        return {
            "ip": ip,
            "lookup_status": "IPinfo connection failed"
        }

    except Exception as e:

        print(
            "IPINFO ERROR:",
            repr(e)
        )

        return {
            "ip": ip,
            "lookup_status": "IPinfo lookup failed"
        }


# ============================================================
# IP RDAP INTELLIGENCE
# ============================================================

@st.cache_data(ttl=3600)
def get_ip_rdap(ip):

    if not ip:
        return {}

    try:

        response = requests.get(
            f"https://rdap.org/ip/{ip}",
            timeout=10,
            headers={
                "Accept":
                    "application/rdap+json"
            }
        )

        if response.status_code != 200:

            return {}

        data = response.json()

        # ----------------------------------------------------
        # NETWORK INFORMATION
        # ----------------------------------------------------

        network_name = (
            data.get("name")
            or data.get("handle")
        )

        start_address = data.get(
            "startAddress"
        )

        end_address = data.get(
            "endAddress"
        )

        ip_version = data.get(
            "ipVersion"
        )

        country = data.get(
            "country"
        )

        # ----------------------------------------------------
        # ENTITIES
        # ----------------------------------------------------

        entities = []

        for entity in data.get(
            "entities",
            []
        ):

            roles = entity.get(
                "roles",
                []
            )

            handle = entity.get(
                "handle"
            )

            entities.append(
                {
                    "handle": handle,
                    "roles": roles
                }
            )

        return {

            "network_name":
                network_name,

            "start_address":
                start_address,

            "end_address":
                end_address,

            "ip_version":
                ip_version,

            "country":
                country,

            "entities":
                entities
        }

    except Exception as e:

        print(
            "IP RDAP ERROR:",
            repr(e)
        )

        return {}


# ============================================================
# DOMAIN RDAP INTELLIGENCE
# ============================================================

@st.cache_data(ttl=3600)
def get_domain_intelligence(domain):

    if not domain:
        return {}

    try:

        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=10,
            headers={
                "Accept":
                    "application/rdap+json"
            }
        )

        if response.status_code != 200:

            return {}

        data = response.json()

        registration_date = None
        expiration_date = None

        # ----------------------------------------------------
        # DOMAIN EVENTS
        # ----------------------------------------------------

        for event in data.get(
            "events",
            []
        ):

            action = event.get(
                "eventAction"
            )

            date = event.get(
                "eventDate"
            )

            if action == "registration":

                registration_date = date

            elif action == "expiration":

                expiration_date = date

        # ----------------------------------------------------
        # REGISTRAR
        # ----------------------------------------------------

        registrar = "Unknown"

        for entity in data.get(
            "entities",
            []
        ):

            roles = entity.get(
                "roles",
                []
            )

            if "registrar" not in roles:
                continue

            vcard = entity.get(
                "vcardArray",
                []
            )

            if len(vcard) > 1:

                for item in vcard[1]:

                    if (
                        len(item) >= 4
                        and item[0] == "fn"
                    ):

                        registrar = str(
                            item[3]
                        )

                        break

            if registrar != "Unknown":
                break

        # ----------------------------------------------------
        # NAMESERVERS
        # ----------------------------------------------------

        nameservers = []

        for ns in data.get(
            "nameservers",
            []
        ):

            name = ns.get(
                "ldhName"
            )

            if name:

                nameservers.append(
                    name
                )

        return {

            "domain": domain,

            "registration_date":
                registration_date,

            "expiration_date":
                expiration_date,

            "registrar":
                registrar,

            "nameservers":
                nameservers,

            "status":
                data.get(
                    "status",
                    []
                )
        }

    except Exception as e:

        print(
            "DOMAIN RDAP ERROR:",
            repr(e)
        )

        return {}


# ============================================================
# DOMAIN AGE
# ============================================================

def calculate_domain_age(
    registration_date
):

    if not registration_date:

        return None

    try:

        created = pd.to_datetime(
            registration_date,
            utc=True
        )

        now = pd.Timestamp.now(
            tz="UTC"
        )

        age_days = (
            now - created
        ).days

        return max(
            age_days,
            0
        )

    except:

        return None


# ============================================================
# INFRASTRUCTURE RISK
# ============================================================

def infrastructure_risk(
    domain_age
):

    """
    Domain age is only one risk signal.

    A new domain is NOT automatically malicious.
    """

    if domain_age is None:

        return 0

    if domain_age <= 7:

        return 25

    if domain_age <= 30:

        return 15

    if domain_age <= 90:

        return 8

    return 0


# ============================================================
# COMPLETE INFRASTRUCTURE INTELLIGENCE
# ============================================================

def get_infrastructure_intelligence(
    url
):

    domain = get_domain(url)

    if not domain:

        return {}

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    ip = resolve_ip(
        domain
    )

    # --------------------------------------------------------
    # IPINFO
    # --------------------------------------------------------

    ip_data = get_ip_intelligence(
        ip
    )

    # --------------------------------------------------------
    # IP RDAP
    # --------------------------------------------------------

    ip_rdap = get_ip_rdap(
        ip
    )

    # --------------------------------------------------------
    # DOMAIN RDAP
    # --------------------------------------------------------

    domain_data = get_domain_intelligence(
        domain
    )

    # --------------------------------------------------------
    # DOMAIN AGE
    # --------------------------------------------------------

    age_days = calculate_domain_age(
        domain_data.get(
            "registration_date"
        )
    )

    age_risk = infrastructure_risk(
        age_days
    )

    # --------------------------------------------------------
    # COMPLETE RESULT
    # --------------------------------------------------------

    return {

        "domain": domain,

        # DNS
        "ip": ip,

        # IP intelligence
        "country": ip_data.get(
            "country"
        ),

        "country_code":
            ip_data.get(
                "country_code"
            ),

        "city": ip_data.get(
            "city"
        ),

        "region": ip_data.get(
            "region"
        ),

        "latitude": ip_data.get(
            "latitude"
        ),

        "longitude": ip_data.get(
            "longitude"
        ),

        "timezone": ip_data.get(
            "timezone"
        ),

        "postal": ip_data.get(
            "postal"
        ),

        "asn": ip_data.get(
            "asn"
        ),

        "organization":
            ip_data.get(
                "organization"
            ),

        "hostname":
            ip_data.get(
                "hostname"
            ),

        "ip_lookup_status":
            ip_data.get(
                "lookup_status"
            ),

        # IP RDAP
        "network_name":
            ip_rdap.get(
                "network_name"
            ),

        "network_start":
            ip_rdap.get(
                "start_address"
            ),

        "network_end":
            ip_rdap.get(
                "end_address"
            ),

        "ip_version":
            ip_rdap.get(
                "ip_version"
            ),

        "ip_rdap_country":
            ip_rdap.get(
                "country"
            ),

        # Domain RDAP
        "registration_date":
            domain_data.get(
                "registration_date"
            ),

        "expiration_date":
            domain_data.get(
                "expiration_date"
            ),

        "registrar":
            domain_data.get(
                "registrar",
                "Unknown"
            ),

        "nameservers":
            domain_data.get(
                "nameservers",
                []
            ),

        "domain_status":
            domain_data.get(
                "status",
                []
            ),

        # Risk
        "domain_age_days":
            age_days,

        "infrastructure_risk":
            age_risk
    }

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ WebShield")
    st.caption("ADAPTIVE PHISHING DEFENSE")

    theme = st.radio(
        "🎨 APPEARANCE",
        ["🌙 Dark", "☀️ Light"],
        horizontal=True,
        key="webshield_theme",
    )

    st.divider()

    page = st.radio(
        "SECURITY CENTER",
        [
            "🏠 Overview",
            "🔍 Live Scanner",
            "🚨 Threat Monitor",
            "📊 Analytics",
            "🤖 ML vs DL Comparison",
            "🧠 Detection Intelligence",
            "⚙️ System Status",
            "🎬 Demo Lab"
        ]
    )

    st.divider()

    if backend_status():

        st.success("● Protection Active")

    else:

        st.error("● Backend Offline")

    st.caption("WebShield Security Center")
    ipinfo_token_present = bool(
        os.getenv("IPINFO_TOKEN", "").strip()
    )

    if ipinfo_token_present:
        st.caption("🟢 IPinfo Connected")
    else:
        st.caption("🔴 IPinfo Token Missing")

    st.caption("Version 2.0")


# ============================================================
# PAGE HEADER
# ============================================================

def page_header(title, subtitle):

    st.markdown(
        f"""
        <div class="main-title">{title}</div>
        <div class="main-subtitle">{subtitle}</div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# STATUS DISPLAY
# ============================================================

def display_status(status):

    status = str(status).upper()

    if status == "SAFE":

        st.markdown(
            '<div class="safe-box">🟢 SAFE</div>',
            unsafe_allow_html=True
        )

    elif status == "SUSPICIOUS":

        st.markdown(
            '<div class="warning-box">🟠 SUSPICIOUS</div>',
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            '<div class="danger-box">🔴 HIGH RISK</div>',
            unsafe_allow_html=True
        )


# ============================================================
# OVERVIEW
# ============================================================

if page == "🏠 Overview":

    page_header(
        "Security Overview",
        "Real-time visibility into WebShield's phishing detection and threat intelligence engine"
    )

    total = len(df)

    if not df.empty:

        statuses = (
            df["status"]
            .astype(str)
            .str.upper()
            .str.strip()
        )

        safe = int(
            (statuses == "SAFE").sum()
        )

        suspicious = int(
            (statuses == "SUSPICIOUS").sum()
        )

        high_risk = int(
            (statuses == "HIGH RISK").sum()
        )

        avg_risk = round(
            float(
                df["risk_score"].mean()
            ),
            1
        )

        max_risk = int(
            df["risk_score"].max()
        )

    else:

        safe = 0
        suspicious = 0
        high_risk = 0
        avg_risk = 0
        max_risk = 0

    threats = suspicious + high_risk

    # --------------------------------------------------------
    # SECURITY POSTURE
    # --------------------------------------------------------

    if high_risk > 0:

        st.error(
            f"🔴 SECURITY ALERT — {high_risk} high-risk "
            f"website{'s' if high_risk != 1 else ''} detected."
        )

    elif suspicious > 0:

        st.warning(
            f"🟠 ELEVATED RISK — {suspicious} suspicious "
            f"website{'s' if suspicious != 1 else ''} detected."
        )

    else:

        st.success(
            "🟢 SYSTEM SECURE — No active high-risk threats detected."
        )

    # --------------------------------------------------------
    # TOP METRICS
    # --------------------------------------------------------

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "🌐 Websites Scanned",
            total,
            help="Total websites analyzed by WebShield"
        )

    with c2:

        st.metric(
            "🟢 Safe Websites",
            safe,
            help="Websites classified as safe"
        )

    with c3:

        st.metric(
            "🚨 Threats Detected",
            threats,
            help="Suspicious and high-risk websites"
        )

    with c4:

        st.metric(
            "⚠️ Average Risk",
            f"{avg_risk}%",
            help="Average risk score across all scans"
        )

    st.write("")

    # --------------------------------------------------------
    # SECURITY ANALYTICS
    # --------------------------------------------------------

    left, right = st.columns(2)

    with left:

        st.subheader("Threat Distribution")

        if total > 0:

            distribution = pd.DataFrame(
                {
                    "Category": [
                        "Safe",
                        "Suspicious",
                        "High Risk"
                    ],
                    "Websites": [
                        safe,
                        suspicious,
                        high_risk
                    ]
                }
            )

            st.bar_chart(
                distribution.set_index(
                    "Category"
                ),
                height=300
            )

        else:

            st.info(
                "Threat distribution will appear after websites are scanned."
            )

    with right:

        st.subheader("Risk Activity")

        if total > 0:

            trend = (
                df
                .dropna(
                    subset=["risk_score"]
                )
                .sort_values("time")
                .tail(20)
                .copy()
            )

            if not trend.empty:

                trend["Scan"] = range(
                    1,
                    len(trend) + 1
                )

                trend = trend.set_index(
                    "Scan"
                )

                st.line_chart(
                    trend["risk_score"],
                    height=300
                )

            else:

                st.info(
                    "Risk activity will appear after scans."
                )

        else:

            st.info(
                "Risk activity will appear after scans."
            )

    st.divider()

    # --------------------------------------------------------
    # SECURITY SUMMARY
    # --------------------------------------------------------

    st.subheader("Security Summary")

    s1, s2, s3 = st.columns(3)

    with s1:

        st.metric(
            "Highest Risk Score",
            f"{max_risk}%"
        )

    with s2:

        if total > 0:

            unique_domains = (
                df["url"]
                .astype(str)
                .apply(get_domain)
                .nunique()
            )

        else:

            unique_domains = 0

        st.metric(
            "Unique Domains",
            unique_domains
        )

    with s3:

        if total > 0:

            threat_percentage = round(
                (threats / total) * 100,
                1
            )

        else:

            threat_percentage = 0

        st.metric(
            "Threat Rate",
            f"{threat_percentage}%"
        )

    st.write("")

    # --------------------------------------------------------
    # RECENT SECURITY ACTIVITY
    # --------------------------------------------------------

    st.subheader("Recent Security Activity")

    st.caption(
        "Latest websites analyzed by the WebShield security engine"
    )

    if df.empty:

        st.info(
            "🛡️ No browsing activity recorded yet."
        )

    else:

        recent = (
            df
            .sort_values(
                "time",
                ascending=False
            )
            .head(7)
        )

        for _, row in recent.iterrows():

            url = str(
                row.get(
                    "url",
                    "Unknown website"
                )
            )

            score = int(
                float(
                    row.get(
                        "risk_score",
                        0
                    )
                )
            )

            status = str(
                row.get(
                    "status",
                    "UNKNOWN"
                )
            ).upper().strip()

            timestamp = str(
                row.get(
                    "time",
                    ""
                )
            )

            if status == "SAFE":

                status_text = "🟢 SAFE"

            elif status == "SUSPICIOUS":

                status_text = "🟠 SUSPICIOUS"

            else:

                status_text = "🔴 HIGH RISK"

            with st.container(border=True):

                c1, c2, c3 = st.columns(
                    [6, 1.5, 1.5]
                )

                with c1:

                    st.markdown(
                        f"**🌐 {url}**"
                    )

                    st.caption(
                        f"🕒 {timestamp}"
                    )

                with c2:

                    st.metric(
                        "Risk",
                        f"{score}%"
                    )

                with c3:

                    if status == "SAFE":

                        st.success(
                            status_text
                        )

                    elif status == "SUSPICIOUS":

                        st.warning(
                            status_text
                        )

                    else:

                        st.error(
                            status_text
                        )

    # --------------------------------------------------------
    # SECURITY ENGINE STATUS
    # --------------------------------------------------------

    st.write("")

    st.subheader("Protection Status")

    p1, p2, p3, p4 = st.columns(4)

    with p1:
        st.success("🟢 URL Analysis\n\nActive")

    with p2:
        st.success("🟢 ML Detection\n\nActive")

    with p3:
        st.success("🟢 Domain Analysis\n\nActive")

    with p4:
        st.info("🧩 Page Telemetry\n\nProvided by the browser extension on supported pages")


# ============================================================
# LIVE SCANNER
# ============================================================

elif page == "🔍 Live Scanner":

    page_header(
        "🔍 Live Threat Scanner",
        "Analyze a website using WebShield's multi-layer detection engine"
    )

    st.markdown("---")

    st.subheader("Website Analysis")

    url_input = st.text_input(
        "Enter website URL",
        placeholder="example.com",
        help="Enter the website you want WebShield to analyze"
    )

    analyze = st.button(
        "🔎 Analyze Website",
        type="primary",
        use_container_width=True
    )

    if analyze:

        if not url_input.strip():

            st.warning(
                "⚠️ Please enter a website URL."
            )

        else:

            url = url_input.strip()

            if not url.startswith(
                ("http://", "https://")
            ):

                url = "https://" + url

            with st.spinner(
                "🛡️ WebShield is analyzing the website..."
            ):

                try:

                    response = requests.post(
                        BACKEND_URL,
                        json={
                            "url": url,
                            "page_analysis": {}
                        },
                        timeout=15
                    )

                    if response.status_code != 200:

                        st.error(
                            f"❌ Backend returned HTTP "
                            f"{response.status_code}"
                        )

                    else:

                        result = response.json()

                        # Flask records this scan once for both dashboard and extension.
                        load_history.clear()
                        df = load_history()

                        score = int(
                            float(
                                result.get(
                                    "risk_score",
                                    0
                                )
                            )
                        )

                        level = str(
                            result.get(
                                "risk_level",
                                "UNKNOWN"
                            )
                        ).upper()

                        breakdown = result.get(
                            "risk_breakdown",
                            {}
                        )

                        reasons = result.get(
                            "reasons",
                            []
                        )

                        context = result.get(
                            "context",
                            "General"
                        )

                        # ====================================================
                        # INFRASTRUCTURE INTELLIGENCE
                        # IMPORTANT FIX:
                        # infrastructure is now defined BEFORE if infrastructure
                        # ====================================================

                        infrastructure = (
                            get_infrastructure_intelligence(url)
                        )

                        # ------------------------------------------------
                        # RESULT HEADER
                        # ------------------------------------------------

                        st.divider()

                        if level == "SAFE":

                            st.success(
                                f"🟢 WEBSITE SAFE — {score}% RISK"
                            )

                        elif level == "SUSPICIOUS":

                            st.warning(
                                f"🟠 SUSPICIOUS WEBSITE — {score}% RISK"
                            )

                        else:

                            st.error(
                                f"🔴 HIGH RISK WEBSITE — {score}% RISK"
                            )

                        st.markdown(
                            f"### 🌐 {url}"
                        )

                        # ------------------------------------------------
                        # RISK SCORE
                        # ------------------------------------------------

                        st.subheader(
                            "Overall Risk Score"
                        )

                        st.progress(
                            min(
                                max(score, 0),
                                100
                            )
                        )

                        st.markdown(
                            f"""
                            <div style="
                                text-align:center;
                                font-size:38px;
                                font-weight:800;
                                color:#f8fafc;
                                margin:10px 0 20px 0;
                            ">
                                {score}%
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                        # ------------------------------------------------
                        # DETECTION BREAKDOWN
                        # ------------------------------------------------

                        st.subheader(
                            "Detection Breakdown"
                        )

                        c1, c2, c3, c4 = st.columns(4)

                        with c1:

                            st.metric(
                                "🤖 ML Detection",
                                f"{breakdown.get('ml_score', 0)}%"
                            )

                        with c2:

                            st.metric(
                                "🔗 URL Analysis",
                                f"{breakdown.get('url_risk', 0)}%"
                            )

                        with c3:

                            st.metric(
                                "🌐 Domain Risk",
                                f"{breakdown.get('domain_risk', 0)}%"
                            )

                        with c4:
                            page_score_value = breakdown.get("page_risk")
                            st.metric(
                                "📄 Page Analysis",
                                f"{page_score_value}%" if page_score_value is not None else "Not analyzed"
                            )

                        # ------------------------------------------------
                        # DETECTION FINDINGS
                        # ------------------------------------------------

                        st.divider()

                        st.subheader(
                            "🔎 Detection Findings"
                        )

                        if reasons:

                            for reason in reasons:

                                st.info(
                                    f"• {str(reason)}"
                                )

                        else:

                            st.success(
                                "✓ No suspicious indicators were detected."
                            )

                        # ------------------------------------------------
                        # SECURITY CONTEXT
                        # ------------------------------------------------

                        st.subheader(
                            "Security Context"
                        )

                        st.info(
                            str(context)
                        )

                        # ------------------------------------------------
                        # FINAL ASSESSMENT
                        # ------------------------------------------------

                        st.divider()

                        st.subheader(
                            "Security Assessment"
                        )

                        if level == "SAFE":

                            st.success(
                                "🟢 This website appears safe based "
                                "on the available detection signals."
                            )

                        elif level == "SUSPICIOUS":

                            st.warning(
                                "🟠 This website contains suspicious "
                                "characteristics. Proceed with caution."
                            )

                        else:

                            st.error(
                                "🔴 This website presents a high "
                                "phishing risk. Avoid entering sensitive "
                                "information."
                            )

                        # ====================================================
                        # INFRASTRUCTURE INTELLIGENCE
                        # ====================================================

                        st.divider()

                        st.subheader(
                            "🌍 Threat Infrastructure Intelligence"
                        )

                        if infrastructure:

                            # ------------------------------------------------
                            # DOMAIN AGE
                            # ------------------------------------------------

                            domain_age = infrastructure.get(
                                "domain_age_days"
                            )

                            if domain_age is not None:

                                if domain_age <= 7:

                                    st.warning(
                                        f"⚠️ Very new domain — "
                                        f"registered {domain_age} days ago"
                                    )

                                elif domain_age <= 30:

                                    st.warning(
                                        f"⚠️ Recently registered domain — "
                                        f"{domain_age} days old"
                                    )

                                elif domain_age <= 90:

                                    st.info(
                                        f"ℹ️ Relatively new domain — "
                                        f"{domain_age} days old"
                                    )

                                else:

                                    st.success(
                                        f"✓ Domain age: "
                                        f"{domain_age:,} days"
                                    )

                            # ------------------------------------------------
                            # INFRASTRUCTURE METRICS
                            # ------------------------------------------------

                            lookup_status = infrastructure.get(
                                "ip_lookup_status"
                            )

                            if lookup_status and lookup_status != "success":
                                st.warning(
                                    f"⚠️ IP intelligence status: {lookup_status}"
                                )

                            i1, i2, i3, i4 = st.columns(4)

                            with i1:

                                st.metric(
                                    "🌐 IP Address",
                                    infrastructure.get(
                                        "ip"
                                    ) or "Unavailable"
                                )

                            with i2:

                                st.metric(
                                    "🌍 Country",
                                    infrastructure.get(
                                        "country"
                                    ) or "Unknown"
                                )

                            with i3:

                                st.metric(
                                    "🏢 ASN",
                                    infrastructure.get(
                                        "asn"
                                    ) or "Unknown"
                                )

                            with i4:

                                age_display = (
                                    f"{domain_age:,} days"
                                    if domain_age is not None
                                    else "Unknown"
                                )

                                st.metric(
                                    "📅 Domain Age",
                                    age_display
                                )

                            # ------------------------------------------------
                            # HOSTING ORGANIZATION / REGISTRAR
                            # ------------------------------------------------

                            st.write("")

                            i1, i2 = st.columns(2)

                            with i1:

                                with st.container(
                                    border=True
                                ):

                                    st.markdown(
                                        "### 🏢 Hosting Organization"
                                    )

                                    st.write(
                                        infrastructure.get(
                                            "organization"
                                        ) or "Unknown"
                                    )

                            with i2:

                                with st.container(
                                    border=True
                                ):

                                    st.markdown(
                                        "### 🏷️ Registrar"
                                    )

                                    st.write(
                                        infrastructure.get(
                                            "registrar"
                                        ) or "Unknown"
                                    )

                            # ------------------------------------------------
                            # HOSTING LOCATION
                            # ------------------------------------------------

                            st.markdown(
                                "### 📍 Hosting Location"
                            )

                            country = infrastructure.get(
                                "country"
                            )

                            country_code = infrastructure.get(
                                "country_code"
                            )

                            city = infrastructure.get(
                                "city"
                            )

                            region = infrastructure.get(
                                "region"
                            )

                            latitude = infrastructure.get(
                                "latitude"
                            )

                            longitude = infrastructure.get(
                                "longitude"
                            )

                            if country:

                                location_text = country

                                if country_code and country_code != country:
                                    location_text += f" ({country_code})"

                                if region:
                                    location_text += (
                                        f", {region}"
                                    )

                                if city:
                                    location_text += (
                                        f", {city}"
                                    )

                                st.info(
                                    f"🌍 {location_text}"
                                )

                            else:

                                st.info(
                                    "Location information unavailable."
                                )

                            # ------------------------------------------------
                            # THREAT MAP
                            # ------------------------------------------------

                            if (
                                latitude is not None
                                and longitude is not None
                            ):

                                st.markdown(
                                    "### 🗺️ Infrastructure Location"
                                )

                                try:

                                    map_data = pd.DataFrame(
                                        {
                                            "lat": [
                                                float(latitude)
                                            ],
                                            "lon": [
                                                float(longitude)
                                            ]
                                        }
                                    )

                                    st.map(
                                        map_data,
                                        zoom=3
                                    )

                                    st.caption(
                                        "⚠️ This represents the approximate "
                                        "hosting/IP geolocation, not necessarily "
                                        "the physical location of the attacker."
                                    )

                                except Exception:

                                    st.info(
                                        "Map location could not be displayed."
                                    )

                            # ------------------------------------------------
                            # DOMAIN REGISTRATION
                            # ------------------------------------------------

                            st.markdown(
                                "### 📅 Domain Registration"
                            )

                            registration = infrastructure.get(
                                "registration_date"
                            )

                            expiration = infrastructure.get(
                                "expiration_date"
                            )

                            r1, r2 = st.columns(2)

                            with r1:

                                if registration:

                                    try:

                                        formatted_registration = (
                                            pd.to_datetime(
                                                registration
                                            ).strftime(
                                                "%d %B %Y"
                                            )
                                        )

                                    except Exception:

                                        formatted_registration = (
                                            str(registration)
                                        )

                                    st.write(
                                        f"**Registered:** "
                                        f"{formatted_registration}"
                                    )

                                else:

                                    st.write(
                                        "**Registered:** Unknown"
                                    )

                            with r2:

                                if expiration:

                                    try:

                                        formatted_expiration = (
                                            pd.to_datetime(
                                                expiration
                                            ).strftime(
                                                "%d %B %Y"
                                            )
                                        )

                                    except Exception:

                                        formatted_expiration = (
                                            str(expiration)
                                        )

                                    st.write(
                                        f"**Expires:** "
                                        f"{formatted_expiration}"
                                    )

                                else:

                                    st.write(
                                        "**Expires:** Unknown"
                                    )

                            # ------------------------------------------------
                            # NAMESERVERS
                            # ------------------------------------------------

                            nameservers = infrastructure.get(
                                "nameservers",
                                []
                            )

                            if nameservers:

                                st.markdown(
                                    "### 🌐 Nameservers"
                                )

                                for nameserver in nameservers:

                                    st.code(
                                        nameserver
                                    )

                            # ------------------------------------------------
                            # INFRASTRUCTURE RISK
                            # ------------------------------------------------

                            infrastructure_score = infrastructure.get(
                                "infrastructure_risk",
                                0
                            )

                            st.markdown(
                                "### 🧠 Infrastructure Risk Signal"
                            )

                            if infrastructure_score >= 20:

                                st.error(
                                    f"🔴 High infrastructure risk signal: "
                                    f"{infrastructure_score}/25"
                                )

                            elif infrastructure_score > 0:

                                st.warning(
                                    f"🟠 Moderate infrastructure risk signal: "
                                    f"{infrastructure_score}/25"
                                )

                            else:

                                st.success(
                                    "🟢 No significant domain-age risk signal detected."
                                )

                        else:

                            st.info(
                                "ℹ️ Infrastructure intelligence "
                                "could not be retrieved for this domain."
                            )

                # --------------------------------------------------------
                # CONNECTION ERROR
                # --------------------------------------------------------

                except requests.exceptions.ConnectionError:

                    st.error(
                        "🔴 WebShield backend is unavailable. "
                        "Please make sure the Flask backend is running "
                        "on port 5000."
                    )

                except requests.exceptions.Timeout:

                    st.error(
                        "⏱️ The security analysis timed out. "
                        "Please try again."
                    )

                except ValueError:

                    st.error(
                        "❌ The backend returned an invalid response."
                    )

                except Exception as e:

                    st.error(
                        f"❌ Unexpected error: {e}"
                    )

    else:

        st.info(
            "🛡️ Enter a website above and click "
            "**Analyze Website** to begin a security scan."
        )

        st.write("")

        c1, c2, c3 = st.columns(3)

        with c1:

            st.markdown(
                """
                ### 🤖 Machine Learning

                Detects URL patterns associated
                with phishing websites.
                """
            )

        with c2:

            st.markdown(
                """
                ### 🔗 URL Intelligence

                Examines suspicious URL
                characteristics and structure.
                """
            )

        with c3:

            st.markdown(
                """
                ### 🌐 Domain Analysis

                Evaluates domain-level indicators
                and suspicious characteristics.
                """
            )


# ============================================================
# DEMO LAB — REPEATABLE END-TO-END TESTS
# ============================================================

elif page == "🎬 Demo Lab":

    page_header(
        "🎬 Demo Lab",
        "Repeatable, presentation-ready test suite for legitimate, suspicious and lookalike URLs"
    )

    st.info(
        "This lab submits URL strings to your local WebShield API. It does not open the URLs or visit suspicious websites. "
        "A URL result is a model/risk-engine assessment, not a guarantee of safety."
    )

    demo_cases = [
        ("Official BIT homepage", "Expected legitimate", "https://bit-bangalore.edu.in/"),
        ("BIT ISE department", "Expected legitimate", "https://bit-bangalore.edu.in/ise-about"),
        ("Google homepage", "Expected legitimate", "https://www.google.com/"),
        ("Brand-lookalike pattern", "Should raise suspicion", "https://microsoft.com.security-check.example/login/verify-account"),
        ("IP-hosted login pattern", "Should raise suspicion", "http://192.0.2.10/login/verify-account"),
        ("High-risk synthetic URL", "Should be high risk", "http://secure-login-verify-account-update-password-check.example-work.top/a/b/c/d"),
        ("BIT spelling lookalike", "Should raise suspicion", "https://bit-banglore.edu.in/secure-login"),
    ]

    st.markdown("#### Included scenarios")
    st.dataframe(
        pd.DataFrame(demo_cases, columns=["Scenario", "Test intent", "URL string"]),
        use_container_width=True,
        hide_index=True,
    )

    if st.button("▶ Run full demo suite", type="primary", use_container_width=True):
        demo_rows = []
        progress = st.progress(0, text="Starting WebShield checks…")
        for index, (scenario, intent, test_url) in enumerate(demo_cases, start=1):
            try:
                response = requests.post(
                    BACKEND_URL,
                    json={"url": test_url, "page_analysis": {}},
                    timeout=20,
                )
                if response.ok:
                    result = response.json()
                    breakdown = result.get("risk_breakdown", {})
                    demo_rows.append({
                        "Scenario": scenario,
                        "Expected behaviour": intent,
                        "Detected level": result.get("risk_level", result.get("status", "UNKNOWN")),
                        "Hybrid risk": result.get("risk_score"),
                        "Random Forest": breakdown.get("ml_score"),
                        "CNN + BiLSTM": breakdown.get("dl_score"),
                        "Domain risk": breakdown.get("domain_risk"),
                        "Page telemetry": "Available" if result.get("page_analysis_available") else "Not provided in URL-only test",
                        "Top signals": "; ".join((result.get("reasons") or [])[:3]) or "No structural signals returned",
                        "URL": test_url,
                    })
                else:
                    demo_rows.append({"Scenario": scenario, "Expected behaviour": intent, "Detected level": f"API error {response.status_code}", "URL": test_url})
            except requests.RequestException as exc:
                demo_rows.append({"Scenario": scenario, "Expected behaviour": intent, "Detected level": "BACKEND UNAVAILABLE", "Top signals": str(exc), "URL": test_url})
            progress.progress(index / len(demo_cases), text=f"Checked {index}/{len(demo_cases)} scenarios")

        progress.empty()
        results_df = pd.DataFrame(demo_rows)
        st.session_state["webshield_demo_results"] = results_df
        load_history.clear()
        df = load_history()

    if "webshield_demo_results" in st.session_state:
        results_df = st.session_state["webshield_demo_results"]
        successful = results_df[results_df.get("Hybrid risk", pd.Series(dtype=float)).notna()] if "Hybrid risk" in results_df else pd.DataFrame()
        c1, c2, c3 = st.columns(3)
        c1.metric("Scenarios completed", f"{len(successful)}/{len(demo_cases)}")
        if not successful.empty:
            c2.metric("Safe outcomes", int((successful["Detected level"] == "SAFE").sum()))
            c3.metric("Flagged outcomes", int(successful["Detected level"].isin(["SUSPICIOUS", "HIGH RISK"]).sum()))
        st.dataframe(results_df, use_container_width=True, hide_index=True)
        st.caption("Expected behaviour is a test intent, not a forced label. Review any surprising result before the live panel demo.")


# ============================================================
# THREAT MONITOR
# ============================================================

elif page == "🚨 Threat Monitor":

    page_header(
        "🚨 Threat Monitor",
        "Investigate websites detected during browsing"
    )

    if df.empty:

        st.info(
            "No threat data available."
        )

    else:

        c1, c2, c3 = st.columns(3)

        with c1:

            selected_status = st.selectbox(
                "Risk Level",
                [
                    "All",
                    "SAFE",
                    "SUSPICIOUS",
                    "HIGH RISK"
                ]
            )

        with c2:

            min_score = st.slider(
                "Minimum Risk Score",
                0,
                100,
                0
            )

        with c3:

            search = st.text_input(
                "Search Website"
            )

        filtered = df.copy()

        if selected_status != "All":

            filtered = filtered[
                filtered["status"]
                .astype(str)
                .str.upper()
                .str.strip()
                == selected_status
            ]

        filtered = filtered[
            filtered["risk_score"] >= min_score
        ]

        if search:

            filtered = filtered[
                filtered["url"]
                .astype(str)
                .str.contains(
                    search,
                    case=False,
                    na=False
                )
            ]

        st.write(
            f"Showing **{len(filtered)}** security events"
        )

        for _, row in (
            filtered
            .sort_values(
                "time",
                ascending=False
            )
            .iterrows()
        ):

            with st.container(border=True):

                c1, c2, c3 = st.columns(
                    [6, 1.5, 1.5]
                )

                with c1:

                    st.markdown(
                        f"**🌐 {row['url']}**"
                    )

                    st.caption(
                        str(row["time"])
                    )

                with c2:

                    st.metric(
                        "Risk",
                        f"{int(row['risk_score'])}%"
                    )

                with c3:

                    display_status(
                        row["status"]
                    )


# ============================================================
# ANALYTICS
# ============================================================

elif page == "📊 Analytics":

    page_header(
        "📊 Security Analytics",
        "Understand browsing risk patterns detected by WebShield"
    )

    if df.empty:

        st.info(
            "Analytics will appear after websites are analyzed."
        )

    else:

        c1, c2, c3 = st.columns(3)

        with c1:

            st.metric(
                "Average Risk",
                f"{df['risk_score'].mean():.1f}%"
            )

        with c2:

            st.metric(
                "Maximum Risk",
                f"{int(df['risk_score'].max())}%"
            )

        with c3:

            st.metric(
                "Unique Domains",
                df["url"]
                .astype(str)
                .apply(get_domain)
                .nunique()
            )

        st.divider()

        # --------------------------------------------------------
        # RISK SCORE DISTRIBUTION
        # --------------------------------------------------------

        st.subheader(
            "Risk Score Distribution"
        )

        histogram = pd.cut(
            df["risk_score"],
            bins=[
                -1,
                20,
                40,
                60,
                80,
                100
            ],
            labels=[
                "0–20",
                "21–40",
                "41–60",
                "61–80",
                "81–100"
            ]
        )

        histogram_data = (
            histogram
            .value_counts()
            .sort_index()
        )

        st.bar_chart(
            histogram_data,
            height=350
        )

        # --------------------------------------------------------
        # SECURITY CLASSIFICATION
        # --------------------------------------------------------

        st.subheader(
            "Security Classification"
        )

        status_counts = (
            df["status"]
            .astype(str)
            .str.upper()
            .value_counts()
        )

        st.bar_chart(
            status_counts,
            height=300
        )

        # --------------------------------------------------------
        # HIGHEST RISK WEBSITES
        # --------------------------------------------------------

        st.subheader(
            "Highest Risk Websites"
        )

        risky = (
            df.sort_values(
                "risk_score",
                ascending=False
            )
            .head(10)
            [
                [
                    "url",
                    "risk_score",
                    "status"
                ]
            ]
            .copy()
        )

        risky.columns = [
            "Website",
            "Risk Score",
            "Status"
        ]

        risky["Risk Score"] = (
            risky["Risk Score"]
            .astype(int)
            .astype(str)
            + "%"
        )

        st.dataframe(
            risky,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # ========================================================
        # THREAT INFRASTRUCTURE OVERVIEW
        #
        # IMPORTANT FIX:
        # This section is now INSIDE the Analytics elif block.
        # ========================================================

        st.subheader(
            "🌍 Threat Infrastructure Overview"
        )

        st.caption(
            "Infrastructure distribution of recently analyzed websites"
        )

        infrastructure_rows = []

        for _, row in df.tail(50).iterrows():

            url = str(
                row["url"]
            )

            info = get_infrastructure_intelligence(
                url
            )

            if info:

                infrastructure_rows.append(
                    {
                        "Website": url,
                        "IP": info.get(
                            "ip"
                        ),
                        "Country": info.get(
                            "country"
                        ),
                        "ASN": info.get(
                            "asn"
                        ),
                        "Organization": info.get(
                            "organization"
                        ),
                        "Domain Age": info.get(
                            "domain_age_days"
                        )
                    }
                )

        if infrastructure_rows:

            infrastructure_df = pd.DataFrame(
                infrastructure_rows
            )

            st.dataframe(
                infrastructure_df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "Infrastructure intelligence will appear "
                "after websites are analyzed."
            )


# ============================================================
# ML VS DL COMPARISON
# ============================================================

elif page == "🤖 ML vs DL Comparison":

    page_header(
        "🤖 ML vs DL Comparison",
        "Compare phishing probabilities returned by the two models for your saved scans (not model accuracy)"
    )

    if df.empty:

        st.info(
            "No scan history available yet. Run a few URL scans first."
        )

    else:

        ml_values = pd.to_numeric(
            df.get("ml_score", pd.Series(dtype=float)),
            errors="coerce"
        ).fillna(0)

        dl_values = pd.to_numeric(
            df.get("dl_score", pd.Series(dtype=float)),
            errors="coerce"
        ).fillna(0)

        model_values = pd.to_numeric(
            df.get("model_score", pd.Series(dtype=float)),
            errors="coerce"
        ).fillna(0)

        st.subheader("🧠 Model Comparison")

        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric("🤖 Random Forest", f"{ml_values.mean():.2f}%")

        with c2:
            st.metric("🧠 CNN + BiLSTM", f"{dl_values.mean():.2f}%")

        with c3:
            st.metric("⚡ Combined Model", f"{model_values.mean():.2f}%")

        comparison_df = pd.DataFrame({
            "Model": ["Random Forest", "CNN + BiLSTM"],
            "Average Phishing Probability": [
                ml_values.mean(),
                dl_values.mean()
            ]
        })

        st.bar_chart(
            comparison_df.set_index("Model"),
            height=300
        )

        st.divider()

        st.subheader("📊 Scan-by-Scan Model Comparison")

        chart_df = pd.DataFrame({
            "URL": df.get("url", pd.Series(dtype=str)).astype(str),
            "Random Forest": ml_values,
            "CNN + BiLSTM": dl_values,
            "Combined Model": model_values
        })

        st.dataframe(
            chart_df,
            use_container_width=True,
            hide_index=True
        )

        difference = (ml_values - dl_values).abs()

        st.metric(
            "Average ML–DL Difference",
            f"{difference.mean():.2f}%"
        )

        st.caption(
            "Values are based on saved scan history. Random Forest is the traditional ML model, while CNN + BiLSTM is the deep-learning model."
        )


# ============================================================
# DETECTION INTELLIGENCE
# ============================================================

elif page == "🧠 Detection Intelligence":

    page_header(
        "🧠 Detection Intelligence",
        "Understand how WebShield evaluates suspicious websites"
    )

    c1, c2 = st.columns(2)

    with c1:

        with st.container(border=True):

            st.markdown(
                "### 🤖 Machine Learning"
            )

            st.write(
                "The machine-learning model analyzes URL features "
                "and estimates the probability that a website "
                "is associated with phishing."
            )

    with c2:

        with st.container(border=True):

            st.markdown(
                "### 🔗 URL Analysis"
            )

            st.write(
                "WebShield checks URL length, suspicious keywords, "
                "hyphens, subdomains, IP addresses and other "
                "structural indicators."
            )

    c1, c2 = st.columns(2)

    with c1:

        with st.container(border=True):

            st.markdown(
                "### 🌐 Domain Intelligence"
            )

            st.write(
                "Domains are compared with trusted domains and "
                "checked for suspicious structural characteristics."
            )

    with c2:

        with st.container(border=True):

            st.markdown(
                "### 📄 Page Analysis"
            )

            st.write(
                "The Chrome extension examines forms, password "
                "fields, iframes, external links and form actions."
            )

    st.divider()

    st.subheader(
        "WebShield Risk Model"
    )

    model_data = pd.DataFrame(
        {
            "Detection Layer": [
                "ML/DL Ensemble",
                "URL Analysis",
                "Domain Risk",
                "Page Analysis"
            ],
            "Weight": [
                30,
                25,
                15,
                30
            ]
        }
    )

    st.bar_chart(
        model_data.set_index(
            "Detection Layer"
        ),
        height=300
    )

    st.info(
        "WebShield combines multiple independent signals "
        "instead of relying on a single classifier."
    )


# ============================================================
# SYSTEM STATUS
# ============================================================

elif page == "⚙️ System Status":

    page_header(
        "⚙️ System Status",
        "WebShield infrastructure and component health"
    )

    backend_online = backend_status()
    health_payload = {}
    if backend_online:
        try:
            health_response = requests.get(HEALTH_URL, timeout=3)
            health_payload = health_response.json() if health_response.ok else {}
        except (requests.RequestException, ValueError):
            health_payload = {}

    c1, c2, c3 = st.columns(3)

    with c1:

        if backend_online:

            st.success(
                "🟢 Flask Backend\n\nOnline"
            )

        else:

            st.error(
                "🔴 Flask Backend\n\nOffline"
            )

    with c2:

        if not df.empty:

            st.success(
                "🟢 Threat History\n\nConnected"
            )

        else:

            st.warning(
                "🟠 Threat History\n\nNo records"
            )

    with c3:
        model_states = health_payload.get("models", {})
        all_models_ready = bool(model_states) and all(model_states.values())
        if all_models_ready:
            st.success("🟢 ML + DL Models\n\nLoaded")
        else:
            st.error("🔴 Model status\n\nCheck backend logs")

    st.divider()

    st.subheader(
        "WebShield Architecture"
    )

    architecture = [
        (
            "1",
            "🌐 Browser",
            "Website visited by user"
        ),
        (
            "2",
            "🧩 Chrome Extension",
            "Collects webpage signals"
        ),
        (
            "3",
            "⚡ Flask API",
            "Processes security request"
        ),
        (
            "4",
            "🤖 ML Model",
            "Predicts phishing probability"
        ),
        (
            "5",
            "🔎 Risk Engine",
            "Combines detection layers"
        ),
        (
            "6",
            "📊 Security Dashboard",
            "Displays security intelligence"
        )
    ]

    for number, title, description in architecture:

        with st.container(border=True):

            c1, c2, c3 = st.columns(
                [0.5, 2, 6]
            )

            with c1:

                st.markdown(
                    f"### {number}"
                )

            with c2:

                st.markdown(
                    f"**{title}**"
                )

            with c3:

                st.caption(
                    description
                )

    st.divider()

    st.subheader(
        "Component Health"
    )

    component_data = pd.DataFrame(
        {
            "Component": [
                "Flask Backend",
                "Machine Learning",
                "URL Analysis",
                "Domain Analysis",
                "Page Analysis",
                "Chrome Extension",
                "Threat History"
            ],
            "Status": [
                "ONLINE" if backend_online else "OFFLINE",
                "ACTIVE",
                "ACTIVE",
                "ACTIVE",
                "ACTIVE",
                "CONNECTED",
                "CONNECTED"
            ]
        }
    )

    st.dataframe(
        component_data,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.caption(
        f"WebShield Security Center • "
        f"Last dashboard refresh: "
        f"{datetime.now().strftime('%H:%M:%S')}"
    )