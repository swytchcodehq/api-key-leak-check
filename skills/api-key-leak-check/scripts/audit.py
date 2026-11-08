#!/usr/bin/env python3
"""Read-only security check for OpenClaw and Hermes agents.

Finds API keys and other secrets sitting in an agent's skills, settings,
memory, chat history and backups, and in the user's shell startup files. It
never changes anything, makes no network calls, and never prints a full
secret: a key is only ever described by its first 4 characters and length.

Python 3.9+ standard library only. Works on macOS, Linux and Windows.

  audit.py              short summary in plain words
  audit.py --details    where each problem is and how to fix it
  audit.py --json       everything, for the agent (includes fix ids)
  audit.py --markdown FILE   also save the details as a shareable report
"""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from collections import Counter, OrderedDict
from datetime import datetime

__version__ = "1.0.3"

MAX_TEXT_BYTES = 5 * 1024 * 1024      # read text files up to this size
MAX_BINARY_BYTES = 400 * 1024 * 1024  # byte-scan databases up to this size
CHUNK = 8 * 1024 * 1024
MAX_FILES_PER_WALK = 20000  # stop a single folder walk after this many files

# --------------------------------------------------------------------------
# What a key looks like. Order matters: specific prefixes first, and a span
# matched by an earlier pattern is not matched again by a later one.
# --------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("stripe", re.compile(rb"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("stripe", re.compile(rb"\b(?:sk|rk)_test_[0-9A-Za-z]{20,}")),
    ("anthropic", re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openrouter", re.compile(rb"\bsk-or-v1-[A-Za-z0-9]{32,}")),
    ("openai", re.compile(rb"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("github", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}")),
    ("github", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("gitlab", re.compile(rb"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("slack", re.compile(rb"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("aws", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}")),
    ("sendgrid", re.compile(rb"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("resend", re.compile(rb"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}")),
    ("notion", re.compile(rb"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}")),
    ("huggingface", re.compile(rb"\bhf_[A-Za-z0-9]{30,}")),
    ("telegram", re.compile(rb"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
]

# name = value, "name": "value", name: value
GENERIC_ASSIGN = re.compile(
    r"""(?ix)
    ["']?([A-Za-z0-9_.\-]*(?:api[_\-]?key|apikey|secret|token|passw(?:or)?d|access[_\-]?key|private[_\-]?key|auth[_\-]?key|client[_\-]?secret))["']?
    \s*[:=]\s*
    ["']?([A-Za-z0-9_\-./+=:]{20,})["']?
    """
)

# Lowercase words joined by underscores: in code, a function or variable name,
# not a key. Only skipped in code files: in settings it can be a password.
SNAKE_WORDS = re.compile(r"^[a-z]+(?:_[a-z]+)+$")
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".go", ".sh"}

# OpenClaw puts these workspace files into every prompt (by name, any case).
OPENCLAW_PROMPT_FILES = {"agents", "soul", "tools", "identity", "user", "heartbeat", "bootstrap", "memory"}

PLACEHOLDER_HINTS = ("your", "xxxx", "example", "changeme", "placeholder", "redacted", "dummy",
                     "sample", "<", "${", "{{", "env:", "environ", "process.env", "****", "....")

# Display names, what someone can do with the key, and where to replace it.
PROVIDERS = {
    "stripe": ("Stripe", "charge cards, issue refunds and see your customers", "https://dashboard.stripe.com/apikeys"),
    "github": ("GitHub", "read and change your code", "https://github.com/settings/tokens"),
    "gitlab": ("GitLab", "read and change your code", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    "slack": ("Slack", "read and send messages as you", "https://api.slack.com/apps"),
    "notion": ("Notion", "read and edit your pages", "https://www.notion.so/profile/integrations"),
    "airtable": ("Airtable", "read and change your data", "https://airtable.com/create/tokens"),
    "resend": ("Resend", "send email as you", "https://resend.com/api-keys"),
    "sendgrid": ("SendGrid", "send email as you", "https://app.sendgrid.com/settings/api_keys"),
    "twilio": ("Twilio", "send texts and make calls on your account", "https://console.twilio.com"),
    "hubspot": ("HubSpot", "read and change your customer records", "https://app.hubspot.com"),
    "shopify": ("Shopify", "change your store and see your orders", "https://admin.shopify.com"),
    "aws": ("AWS", "control your cloud account and run up charges", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    "google": ("Google", "use your Google services and run up charges", "https://console.cloud.google.com/apis/credentials"),
    "gmail": ("Gmail", "read and send your email", "https://myaccount.google.com/permissions"),
    "openai": ("OpenAI", "run up charges on your account", "https://platform.openai.com/api-keys"),
    "anthropic": ("Anthropic", "run up charges on your account", "https://console.anthropic.com/settings/keys"),
    "openrouter": ("OpenRouter", "run up charges on your account", "https://openrouter.ai/settings/keys"),
    "huggingface": ("Hugging Face", "use your account", "https://huggingface.co/settings/tokens"),
    "telegram": ("Telegram bot", "control your bot and read its messages", "https://t.me/BotFather"),
    "discord": ("Discord bot", "control your bot and read its messages", "https://discord.com/developers/applications"),
    "private_key": ("private key", "take control of your agent", None),
    "gateway": ("agent login", "sign in as your agent", None),
}

# Keys an agent needs to run (model providers, chat channels, its own
# logins). Swytchcode can't hold these; the fix is to keep them locked.
AGENT_OWN = {
    "openai", "anthropic", "openrouter", "google", "gemini", "groq", "mistral", "deepseek",
    "together", "fireworks", "xai", "nous", "cohere", "perplexity", "huggingface", "ollama",
    "telegram", "discord", "whatsapp", "signal", "matrix", "private_key", "gateway",
    "elevenlabs", "firecrawl", "tavily", "exa", "brave", "serper", "browserbase", "fal",
}
# Model providers: needed by the agent even when a skill uses them.
MODEL_PROVIDERS = {"openai", "anthropic", "openrouter", "gemini", "groq", "mistral", "deepseek",
                   "together", "fireworks", "xai", "nous", "cohere", "huggingface", "ollama"}

ENV_PROVIDER_OVERRIDES = {
    "GH": "github", "GITHUB": "github", "SLACK": "slack", "STRIPE": "stripe",
    "OPENAI": "openai", "ANTHROPIC": "anthropic", "CLAUDE": "anthropic", "OPENROUTER": "openrouter",
    "GOOGLE": "google", "GEMINI": "gemini", "TELEGRAM": "telegram", "DISCORD": "discord",
    "AWS": "aws", "HF": "huggingface", "HUGGINGFACE": "huggingface", "NOUS": "nous",
    "GATEWAY": "gateway", "OPENCLAW": "gateway", "HERMES": "gateway", "XAI": "xai", "GROK": "xai",
}
AGENT_AUTH_FILES = {"auth.json", "auth-profiles.json", "nous_auth.json", "device.json", "pairing.json"}
NOT_A_PROVIDER = {"env", "api", "my", "secret", "auth", "access", "bearer", "x", "app", "client",
                  "user", "service", "private", "refresh", "id", "session", "the", "default", "base"}
SECRET_NAME_SUFFIX = re.compile(r"(?:_API_KEY|_APIKEY|_KEY|_TOKEN|_SECRET|_SECRET_KEY|_PASSWORD|_PAT|_ACCESS_TOKEN|_AUTH_TOKEN|_BOT_TOKEN|_CREDENTIALS?)$")

HOST_PROVIDERS = [
    ("api.stripe.com", "stripe"), ("api.github.com", "github"), ("slack.com", "slack"),
    ("api.resend.com", "resend"), ("api.notion.com", "notion"), ("api.sendgrid.com", "sendgrid"),
    ("api.twilio.com", "twilio"), ("api.hubapi.com", "hubspot"), ("api.hubspot.com", "hubspot"),
    ("gmail.googleapis.com", "gmail"), ("googleapis.com", "google"),
    ("api.airtable.com", "airtable"), ("api.linear.app", "linear"), ("api.trello.com", "trello"),
    ("discord.com", "discord"), ("api.telegram.org", "telegram"), ("myshopify.com", "shopify"),
    ("api.mailgun.net", "mailgun"), ("api.intercom.io", "intercom"), ("zendesk.com", "zendesk"),
    ("atlassian.net", "jira"), ("api.atlassian.com", "atlassian"), ("api.clickup.com", "clickup"),
    ("api.monday.com", "monday"), ("api.paypal.com", "paypal"), ("api-m.paypal.com", "paypal"),
    ("squareup.com", "square"), ("api.todoist.com", "todoist"), ("api.spotify.com", "spotify"),
    ("api.x.com", "x"), ("api.twitter.com", "x"), ("graph.microsoft.com", "microsoft"),
    ("api.dropboxapi.com", "dropbox"), ("api.box.com", "box"), ("app.asana.com", "asana"),
    ("api.figma.com", "figma"), ("api.vercel.com", "vercel"), ("api.cloudflare.com", "cloudflare"),
    ("api.digitalocean.com", "digitalocean"), ("api.mailchimp.com", "mailchimp"),
    ("api.brevo.com", "brevo"), ("api.postmarkapp.com", "postmark"), ("api.calendly.com", "calendly"),
    ("api.pipedrive.com", "pipedrive"), ("api.openai.com", "openai"), ("api.anthropic.com", "anthropic"),
    ("openrouter.ai", "openrouter"), ("api.razorpay.com", "razorpay"),
    ("api.duffel.com", "duffel"), ("supabase.co", "supabase"),
]
KNOWN_THIRD_PARTY = {p for _, p in HOST_PROVIDERS} | {"twilio", "shopify", "pinecone", "aws", "gitlab", "slack"}
IGNORED_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org",
                 "raw.githubusercontent.com", "github.com", "docs.", "schema", "w3.org", "clawhub.ai",
                 "agentskills.io", "npmjs.com", "pypi.org", "swytchcode")

HTTP_CALL = re.compile(r"\b(?:curl|wget|http(?:ie)?\s|fetch\s*\(|requests\.(?:get|post|put|patch|delete|request)|httpx\.|axios|urlopen|http\.client|Invoke-RestMethod|Invoke-WebRequest|got\(|\$http)", re.I)
URL = re.compile(r"https?://([A-Za-z0-9.\-]+)(/[^\s\"'`)<>]*)?")
DELETE_CALL = re.compile(r"(?:-X\s*DELETE|--request\s+DELETE|requests\.delete|method\s*[:=]\s*[\"']DELETE|DELETE\s+https?://)", re.I)
ENV_REFS = [
    re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?"),
    re.compile(r"\$env:([A-Z][A-Z0-9_]{2,})", re.I),
    re.compile(r"os\.environ(?:\.get)?\s*[\[(]\s*[\"']([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"os\.getenv\(\s*[\"']([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"process\.env\.([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"process\.env\[\s*[\"']([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"Deno\.env\.get\(\s*[\"']([A-Z][A-Z0-9_]{2,})"),
]
FRONTMATTER_ENV = re.compile(r"[\"']?(?:required_environment_variables|(?:primary)?[Ee]nv)[\"']?\s*[:=]\s*(\[[^\]]*\]|[\"'][A-Z0-9_]+[\"'])")
# A shell echo or a print call whose output is the key itself.
_SECRET_VAR = r"[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)"
PRINTS_SECRET = re.compile(
    r"(?:^|[;&|`(]\s*)(?:echo|printf|Write-(?:Host|Output))\s+(?:-\w+\s+)*[\"']?\$\{?(?:env:)?" + _SECRET_VAR + r"\b"
    r"|\b(?:print|console\.log)\s*\(\s*(?:os\.environ(?:\.get)?\s*[\[(]\s*[\"']|os\.getenv\(\s*[\"']|process\.env\.)" + _SECRET_VAR,
    re.I | re.M)
DUMPS_CONFIG = re.compile(r"(?:^|[;&|`(]\s*)(?:cat|less|more|head|tail|type|Get-Content)\s+[^\n]*(?:\.env\b|openclaw\.json|auth-profiles\.json|auth\.json|credentials\.json)", re.M)

SHELL_PROFILES = [".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile",
                  os.path.join(".config", "fish", "config.fish"),
                  os.path.join("Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
                  os.path.join("Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")]

TEXT_EXT = {".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".json", ".json5",
            ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".log", ".ps1", ".rb",
            ".go", ".html", ".xml", ".csv", ".fish", ""}
# Databases, and their write-ahead logs: a running Hermes keeps recent chats in
# state.db-wal until SQLite moves them into state.db.
BINARY_SCAN_EXT = {".db", ".sqlite", ".sqlite3", ".db-wal", ".sqlite-wal", ".sqlite3-wal"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "image_cache", "audio_cache",
             "hermes-agent", "node", "bin", "cache", ".cache", "dist", "build", "site-packages"}

# Files where a whole line can be removed safely. Elsewhere (JSON, YAML,
# logs) only the key itself is blanked, so the file stays valid.
LINE_FILES_EXT = {".md", ".txt", ".env", ".sh", ".bash", ".zsh", ".fish", ".ps1"}

# --------------------------------------------------------------------------
# Groups: how findings are explained to a person. Order = how bad.
# --------------------------------------------------------------------------
GROUPS = OrderedDict([
    ("memory", {"level": "urgent", "title": "Keys in your agent's memory or chat history"}),
    ("skill-secret", {"level": "urgent", "title": "Skills with a key written inside them"}),
    ("skill-leak", {"level": "high", "title": "Skills that can show your keys in the chat"}),
    ("open-files", {"level": "high", "title": "Files with your keys that other accounts on this computer can open"}),
    ("app-keys", {"level": "high", "title": "App keys saved as plain text in your agent's settings"}),
    ("shell", {"level": "high", "title": "Keys in your terminal startup files"}),
    ("backups", {"level": "medium", "title": "Old backup copies that still hold your keys"}),
    ("skill-keys", {"level": "medium", "title": "Skills that handle your app keys directly"}),
    ("agent-logins", {"level": "info", "title": "Your agent's own login keys (normal)"}),
])

# This skill's own folder (scripts/ is inside it).
SELF_DIR = os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def looks_placeholder(value):
    v = value.lower()
    return any(h in v for h in PLACEHOLDER_HINTS) or len(set(value)) <= 4


def describe_key(prov, raw):
    if prov == "private_key":
        return "private key"
    return "starts with %s, %d characters" % (raw[:4], len(raw))


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:10]


def finding_id(kind, path, line, fp):
    return hashlib.sha1(("%s|%s|%s|%s" % (kind, path, line, fp)).encode("utf-8", "replace")).hexdigest()[:8]


def user_home():
    return os.path.expanduser("~")


def tilde(path):
    home = user_home()
    return "~" + path[len(home):] if path.startswith(home) else path


def nice(prov):
    if prov in PROVIDERS:
        return PROVIDERS[prov][0]
    if not prov or prov == "unknown":
        return "unknown"
    return prov.capitalize()


def provider_from_env_name(name):
    base = SECRET_NAME_SUFFIX.sub("", name.upper())
    if not base:
        return None
    first = base.split("_")[0]
    if first.lower() in NOT_A_PROVIDER:
        return None
    if first in ENV_PROVIDER_OVERRIDES:
        return ENV_PROVIDER_OVERRIDES[first]
    if base in ENV_PROVIDER_OVERRIDES:
        return ENV_PROVIDER_OVERRIDES[base]
    return first.lower()


def provider_from_host(host):
    host = host.lower()
    for suffix, prov in HOST_PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return prov
    if host.startswith("api."):
        parts = host.split(".")
        if len(parts) >= 3:
            return parts[1]
    return None


def is_ignored_host(host):
    host = host.lower()
    if host.startswith("api."):
        return False
    return any(host == h or host.startswith(h) or host.endswith(h) for h in IGNORED_HOSTS if "." in h) or \
        any(h in host for h in IGNORED_HOSTS if "." not in h)


def walk(root, skip_dirs=SKIP_DIRS, max_depth=8):
    if not os.path.isdir(root):
        return
    root_depth = root.rstrip(os.sep).count(os.sep)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        if dirpath.count(os.sep) - root_depth >= max_depth:
            dirnames[:] = []
        for f in filenames:
            p = os.path.join(dirpath, f)
            if os.path.islink(p):
                continue
            count += 1
            if count > MAX_FILES_PER_WALK:
                return
            yield p


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_TEXT_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data


_GROUP_CACHE = {}


def group_has_others(gid):
    """Whether anyone besides this user belongs to group gid.

    Ubuntu and most Linux systems give each user a private group (named after
    them, and their main group) and make new files group-readable, so that
    group access means "only you". Any other group counts as shared, because
    accounts from a company directory may not be listed here. When membership
    can't be looked up, assume others (the safe answer)."""
    if gid in _GROUP_CACHE:
        return _GROUP_CACHE[gid]
    try:
        import grp
        import pwd
        me = pwd.getpwuid(os.getuid())
        group = grp.getgrgid(gid)
        if gid != me.pw_gid or group.gr_name != me.pw_name:
            result = True
        else:
            members = set(group.gr_mem)
            members |= {u.pw_name for u in pwd.getpwall() if u.pw_gid == gid}
            result = bool(members - {me.pw_name})
    except (ImportError, KeyError, OSError):
        result = True
    _GROUP_CACHE[gid] = result
    return result


def others_can_read(path):
    # Windows reports every file as readable by all in st_mode; its access
    # control is ACLs, which this can't read. Skip rather than flag every file.
    if os.name == "nt":
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    if st.st_mode & (stat.S_IROTH | stat.S_IWOTH):
        return True
    if st.st_uid not in (os.getuid(), 0):
        return True  # owned by another account, which can always open it
    if st.st_mode & (stat.S_IRGRP | stat.S_IWGRP):
        return group_has_others(st.st_gid)
    return False


def is_backup_path(path):
    name = os.path.basename(path).lower()
    lowered = path.lower()
    return (".bak" in name or name.endswith((".orig", ".old", "~"))
            or "snapshot" in lowered or "backup" in lowered)


def safe_listdir(d):
    try:
        return sorted(os.listdir(d))
    except OSError:
        return []


def agent_homes(platform="auto", home=None):
    """The agent folders to scan, honouring each platform's own overrides."""
    targets = []
    if platform in ("auto", "openclaw"):
        if home and platform == "openclaw":
            h = home
        else:
            base = os.environ.get("OPENCLAW_HOME") or user_home()
            h = os.environ.get("OPENCLAW_STATE_DIR") or os.path.join(base, ".openclaw")
        if os.path.isdir(h):
            targets.append(("openclaw", os.path.abspath(h)))
    if platform in ("auto", "hermes"):
        if home and platform == "hermes":
            h = home
        else:
            h = os.environ.get("HERMES_HOME") or os.path.join(user_home(), ".hermes")
        if os.path.isdir(h):
            targets.append(("hermes", os.path.abspath(h)))
    return targets


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------
class Audit:
    def __init__(self):
        self.findings = []
        self.skills = []
        self.scanned = Counter()
        self.notes = []
        self.raw = {}  # finding id -> secret; used only by fix.py, never printed
        self._seen = set()
        self._skill = None  # skill being scanned, for keys found inside it
        self._in_prompt = False  # file being scanned is put into the agent's prompt
        self.swytchcode_for = set()  # agents with Swytchcode's skill installed

    def add(self, raw=None, **f):
        f["id"] = finding_id(f["kind"], f["path"], f.get("line", 0), f.get("fingerprint", "-"))
        if f["id"] in self._seen:
            return
        self._seen.add(f["id"])
        f["level"] = GROUPS[f["group"]]["level"]
        self.findings.append(f)
        if raw is not None:
            self.raw[f["id"]] = raw

    # ---- secrets -----------------------------------------------------------
    def scan_secrets(self, data, path, area, platform, generic=True, base_line=1, binary=False):
        spans = []
        found = 0
        for prov, rx in SECRET_PATTERNS:
            for m in rx.finditer(data):
                if any(s <= m.start() < e for s, e in spans):
                    continue
                raw = m.group(0).decode("utf-8", "replace")
                if prov != "private_key" and (looks_placeholder(raw) or entropy(raw) < 3.0):
                    continue
                spans.append((m.start(), m.end()))
                line = 0 if binary else base_line + data.count(b"\n", 0, m.start())
                test = "_test_" in raw
                found += self._secret(path, line, area, platform, prov, raw, test, binary)
        if not generic:
            return found
        text = data.decode("utf-8", "replace")
        code_file = os.path.splitext(path)[1].lower() in CODE_EXT
        for m in GENERIC_ASSIGN.finditer(text):
            start = len(text[:m.start(2)].encode("utf-8", "replace"))
            if any(s <= start < e for s, e in spans):
                continue
            name, value = m.group(1), m.group(2)
            if looks_placeholder(value) or entropy(value) < 3.5 or value.lower() in ("true", "false", "null"):
                continue
            if value.count("/") > 2:  # a path or URL, not a key
                continue
            if code_file and SNAKE_WORDS.match(value):  # a function name in code, not a key
                continue
            line = base_line + text.count("\n", 0, m.start())
            prov = provider_from_env_name(name.replace("-", "_").replace(".", "_")) or "unknown"
            if prov not in KNOWN_THIRD_PARTY and prov not in AGENT_OWN:
                prov = "unknown"
            if area == "config" and os.path.basename(path) in AGENT_AUTH_FILES:
                prov = "gateway"
            found += self._secret(path, line, area, platform, prov, value, False, False)
        return found

    def _secret(self, path, line, area, platform, prov, raw, test, binary):
        own = prov in AGENT_OWN
        backup = is_backup_path(path)
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path)
        line_file = ext in LINE_FILES_EXT or name.startswith(".env") or area == "shell"

        if area in ("memory", "logs"):
            group = "memory"
        elif area == "skills":
            group = "skill-secret"
        elif area == "shell":
            group = "shell"
        elif backup:
            group = "backups"
        elif own:
            group = "agent-logins"
        else:
            group = "app-keys"

        # How fix.py can remove it, if at all.
        if group == "agent-logins":
            action = "none"          # the agent needs it; keep it locked instead
        elif binary:
            action = "chat-db"       # inside a database the agent has open
        elif prov == "private_key":
            action = "manual"
        elif group == "backups":
            action = "delete"        # the whole stale copy goes
        elif group == "skill-secret":
            action = "replace-skill"
        elif line_file:
            action = "remove-line"
        else:
            action = "blank"

        # Replace the key only when it really got out: into memory or chat
        # history, inside a skill, or in a file other accounts can open.
        exposed = group in ("memory", "skill-secret") or others_can_read(path)
        self.add(raw=raw, kind="secret", group=group, area=area, platform=platform, provider=prov,
                 key=describe_key(prov, raw), fingerprint=fingerprint(raw), test_key=test,
                 own_key=own, skill=self._skill if area == "skills" else None,
                 in_prompt=self._in_prompt and area == "memory",
                 path=tilde(path), abspath=path, line=line, action=action,
                 rotate=exposed and prov not in ("gateway", "unknown"))
        return 1

    def scan_file(self, path, area, platform, generic=True):
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path)
        if ext in BINARY_SCAN_EXT:
            self.scan_binary(path, area, platform)
            return
        if ext not in TEXT_EXT and not name.startswith((".env", ".zsh", ".bash", ".profile")) and ".bak" not in name:
            return
        data = read_text(path)
        if data is None:
            return
        self.scanned[area] += 1
        found = self.scan_secrets(data, path, area, platform, generic=generic)
        if found and area in ("config", "shell", "memory") and others_can_read(path):
            self.add(kind="permissions", group="open-files", area=area, platform=platform, provider="-",
                     path=tilde(path), abspath=path, line=0, action="lock", rotate=False)

    def scan_binary(self, path, area, platform):
        try:
            size = os.path.getsize(path)
            if size > MAX_BINARY_BYTES:
                self.notes.append("Skipped %s (%d MB, too large to check)." % (tilde(path), size // (1024 * 1024)))
                return
            self.scanned[area] += 1
            with open(path, "rb") as fh:
                tail = b""
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        break
                    buf = tail + chunk
                    self.scan_secrets(buf, path, area, platform, generic=False, binary=True)
                    tail = buf[-256:]
        except OSError:
            pass

    # ---- skills ------------------------------------------------------------
    def scan_skill_dir(self, skills_root, platform):
        if not os.path.isdir(skills_root):
            return
        for skill_md in walk(skills_root, max_depth=6):
            if os.path.basename(skill_md) != "SKILL.md":
                continue
            folder = os.path.dirname(skill_md)
            name = os.path.basename(folder)
            # Skip this skill itself (its detection patterns look like keys)
            # and Swytchcode's own skills, which hold no keys.
            if os.path.realpath(folder) == SELF_DIR or name.startswith("swytchcode"):
                continue
            self.scan_one_skill(folder, name, platform)

    def scan_one_skill(self, folder, name, platform):
        self._skill = name
        providers, env_keys = set(), set()
        prints_secret = dumps_config = deletes = hardcoded = has_scripts = False
        for path in walk(folder, max_depth=4):
            data = read_text(path)
            if data is None:
                continue
            self.scanned["skills"] += 1
            if os.path.splitext(path)[1].lower() in (".py", ".sh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".ps1", ".go"):
                has_scripts = True
            if self.scan_secrets(data, path, "skills", platform, generic=True):
                hardcoded = True
            text = data.decode("utf-8", "replace")
            for i, line in enumerate(text.splitlines(), 1):
                for rx in ENV_REFS:
                    for m in rx.finditer(line):
                        if SECRET_NAME_SUFFIX.search(m.group(1).upper()):
                            env_keys.add(m.group(1).upper())
                fm = FRONTMATTER_ENV.search(line)
                if fm:
                    for n in re.findall(r"[A-Z][A-Z0-9_]{2,}", fm.group(1)):
                        if SECRET_NAME_SUFFIX.search(n):
                            env_keys.add(n)
                if HTTP_CALL.search(line):
                    for m in URL.finditer(line):
                        host = m.group(1)
                        if is_ignored_host(host):
                            continue
                        prov = provider_from_host(host)
                        if prov:
                            providers.add(prov)
                if PRINTS_SECRET.search(line):
                    prints_secret = True
                    self.add(kind="prints-key", group="skill-leak", area="skills", platform=platform,
                             provider="-", skill=name, path=tilde(path), abspath=path, line=i,
                             action="replace-skill", rotate=False)
                if DUMPS_CONFIG.search(line):
                    dumps_config = True
                    self.add(kind="reads-key-file", group="skill-leak", area="skills", platform=platform,
                             provider="-", skill=name, path=tilde(path), abspath=path, line=i,
                             action="replace-skill", rotate=False)
                if DELETE_CALL.search(line):
                    deletes = True
        self._skill = None
        for k in env_keys:
            p = provider_from_env_name(k)
            if p and p not in MODEL_PROVIDERS and not providers:
                providers.add(p)
        if not providers and not env_keys:
            return
        third_party = sorted(p for p in providers if p not in MODEL_PROVIDERS)
        # Only skills that handle a credential count: a keyless public API
        # call isn't a credential problem.
        replaceable = bool(third_party) and bool(env_keys or hardcoded)
        if replaceable:
            self.add(kind="skill-key", group="skill-keys", area="skills", platform=platform,
                     provider=",".join(third_party), skill=name, env_keys=sorted(env_keys),
                     path=tilde(folder), abspath=folder, line=0, action="replace-skill", rotate=False)
        self.skills.append({
            "name": name, "platform": platform, "path": tilde(folder),
            "apps": [nice(p) for p in sorted(providers)], "providers": sorted(providers),
            "env_keys": sorted(env_keys), "has_scripts": has_scripts,
            "prints_key": prints_secret, "reads_key_files": dumps_config, "can_delete": deletes,
            "key_written_inside": hardcoded, "swytchcode_can_replace": replaceable,
        })

    # ---- platforms ---------------------------------------------------------
    def run_openclaw(self, home):
        p = "openclaw"
        for d in (os.path.join(home, "skills"), os.path.join(home, "workspace", "skills")):
            self.scan_skill_dir(d, p)
        ws_roots = [os.path.join(home, "workspace")]
        ws_roots += [os.path.join(home, d) for d in safe_listdir(home) if d.startswith("workspace-")]
        for ws in ws_roots:
            for path in walk(ws, skip_dirs=SKIP_DIRS | {"skills"}, max_depth=4):
                if path.endswith(".md"):
                    self._in_prompt = (os.path.dirname(path) == ws and
                                       os.path.splitext(os.path.basename(path))[0].lower() in OPENCLAW_PROMPT_FILES)
                    self.scan_file(path, "memory", p)
                    self._in_prompt = False
        for path in walk(os.path.join(home, "agents"), max_depth=6):
            area = "logs" if "sessions" in path.split(os.sep) else "config"
            self.scan_file(path, area, p, generic=(area == "config"))
        for path in walk(os.path.join(home, "logs"), max_depth=4):
            self.scan_file(path, "logs", p, generic=False)
        for name in safe_listdir(home):
            full = os.path.join(home, name)
            if name in ("skills", "agents", "logs") or name.startswith("workspace"):
                continue
            if os.path.isfile(full):
                area = "logs" if name.endswith(".log") else "config"
                self.scan_file(full, area, p, generic=(area == "config"))
            elif os.path.isdir(full) and name not in SKIP_DIRS:
                for path in walk(full, max_depth=4):
                    self.scan_file(path, "config", p)

    def run_hermes(self, home):
        p = "hermes"
        self.scan_skill_dir(os.path.join(home, "skills"), p)
        # Hermes puts these into every prompt.
        prompt_files = {os.path.join(home, "SOUL.md"), os.path.join(home, "memories", "MEMORY.md"),
                        os.path.join(home, "memories", "USER.md")}
        self._in_prompt = True
        self.scan_file(os.path.join(home, "SOUL.md"), "memory", p)
        self._in_prompt = False
        for path in walk(os.path.join(home, "memories"), max_depth=4):
            self._in_prompt = path in prompt_files
            self.scan_file(path, "memory", p)
            self._in_prompt = False
        for sub in ("logs", "sessions", "cron"):
            for path in walk(os.path.join(home, sub), max_depth=5):
                self.scan_file(path, "logs", p, generic=False)
        skip_top = {"skills", "memories", "logs", "sessions", "cron", "SOUL.md", "sandboxes", "plugins"} | SKIP_DIRS
        for name in safe_listdir(home):
            if name in skip_top:
                continue
            full = os.path.join(home, name)
            if os.path.isfile(full):
                ext = os.path.splitext(name)[1].lower()
                area = "logs" if (ext in BINARY_SCAN_EXT or ext == ".log") else "config"
                self.scan_file(full, area, p, generic=(area == "config"))
            elif os.path.isdir(full):
                for path in walk(full, max_depth=3):
                    self.scan_file(path, "config", p)

    def run_shell_profiles(self):
        # Keys in a shell startup file reach every program the user starts,
        # the agent included.
        for rel in SHELL_PROFILES:
            path = os.path.join(user_home(), rel)
            if os.path.isfile(path):
                self.scan_file(path, "shell", "shell")


def has_skill(skills_root, name):
    """Whether a skill folder is installed, directly or one category deep (Hermes)."""
    if os.path.isfile(os.path.join(skills_root, name, "SKILL.md")):
        return True
    return any(os.path.isfile(os.path.join(skills_root, d, name, "SKILL.md")) for d in safe_listdir(skills_root))


def run_audit(platform="auto", home=None, skills_only=False, shell=True):
    targets = agent_homes(platform, home)
    audit = Audit()
    # Only looks for Swytchcode's skill folder; never reads Swytchcode's own files.
    audit.swytchcode_for = {
        plat for plat, h in targets
        if any(has_skill(os.path.join(h, *sub), "swytchcode-operator") for sub in (("skills",), ("workspace", "skills")))}
    for plat, h in targets:
        if skills_only:
            audit.scan_skill_dir(os.path.join(h, "skills"), plat)
            if plat == "openclaw":
                audit.scan_skill_dir(os.path.join(h, "workspace", "skills"), plat)
        elif plat == "openclaw":
            audit.run_openclaw(h)
        else:
            audit.run_hermes(h)
    if shell and not skills_only:
        audit.run_shell_profiles()
    return audit, targets


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def join_names(names, limit=3):
    names = list(OrderedDict.fromkeys(n for n in names if n))
    if len(names) <= limit:
        return " and ".join([", ".join(names[:-1]), names[-1]]) if len(names) > 1 else (names[0] if names else "")
    return "%s and %d more" % (", ".join(names[:limit]), len(names) - limit)


def plural(n, one, many=None):
    return one if n == 1 else (many or one + "s")


AGENT_NAMES = {"openclaw": "OpenClaw", "hermes": "Hermes"}


def agent_label(items):
    """Which agent(s) a set of findings came from, e.g. "Hermes and OpenClaw".
    None for findings outside any agent (terminal startup files)."""
    names = sorted({AGENT_NAMES[f["platform"]] for f in items if f.get("platform") in AGENT_NAMES})
    return " and ".join(names) if names else None


def name_agent(text, label):
    """Say which agent a sentence is about: "your agent's" -> "your Hermes agent's"."""
    for a, b in (("Your agent", "Your %s agent"), ("your agent", "your %s agent"),
                 ("Some of your skills", "Some of your %s skills"), ("A skill you installed", "A %s skill you installed")):
        if a in text:
            return text.replace(a, b % label, 1)
    return text


def provider_names(items):
    return [nice(p) for f in items for p in f.get("provider", "").split(",") if p and p not in ("-", "unknown")]


def first_prov(items):
    """The provider a headline leads with: app keys before the agent's own, Stripe first."""
    ps = [f.get("provider") for f in items if f.get("provider") not in (None, "-", "unknown")]
    ps.sort(key=lambda p: (p in AGENT_OWN, p != "stripe"))
    return ps[0] if ps else None


def impact(p):
    return PROVIDERS.get(p, (None, "use that account as you", None))[1]


def is_are(n):
    return "is" if n == 1 else "are"


def key_count(items):
    return len({f.get("fingerprint") for f in items if f["kind"] == "secret"})


def keys_phrase(items):
    """ "Your Stripe key" / "Your Stripe and GitHub keys" / "2 keys". """
    n, p = key_count(items), join_names(provider_names(items))
    return ("Your %s %s" % (p, plural(n, "key"))) if p else ("%d %s" % (n, plural(n, "key")))


def about(items):
    """The findings about the provider a headline leads with."""
    p = first_prov(items)
    return [f for f in items if f.get("provider") == p] if p else items


# Each group explains itself here, in one place: the line(s) in "What we
# found", and the headline used when it's the worst problem. Each function
# returns (lines, headline, the findings the headline is about).

def explain_memory(items):
    kinds = [
        ([f for f in items if f.get("in_prompt")],
         "in your agent's memory, which is sent to your AI provider with every message"),
        ([f for f in items if not f.get("in_prompt") and f.get("area") == "memory"],
         "saved in your agent's memory notes"),
        ([f for f in items if f.get("area") == "logs"],
         "saved in your agent's chat history"),
    ]
    kinds = [(found, where) for found, where in kinds if found]
    lines = ["URGENT: %s %s %s." % (keys_phrase(found), is_are(key_count(found)), where) for found, where in kinds]
    lead, where = kinds[0]
    subject = about(lead)
    p = first_prov(lead)
    if p:
        headline = ("Your %s key is %s. Anyone who gets a copy of your agent's folder, including malware, "
                    "can use it to %s." % (nice(p), where, impact(p)))
    else:
        headline = ("A key is %s. Anyone who gets a copy of your agent's folder, including malware, "
                    "can use it." % where)
    return lines, headline, subject


def explain_skill_secret(items):
    names = [f["skill"] for f in items]
    p = first_prov(items)
    line = "URGENT: A key is written inside %s: %s." % (
        "a skill" if len(set(names)) == 1 else "some skills", join_names(names))
    headline = ("A skill you installed has %s key written inside it. Anyone with a copy of that skill can use it%s."
                % ("your %s" % nice(p) if p else "a", " to " + impact(p) if p else ""))
    return [line], headline, about(items)


def explain_skill_leak(items):
    skills = [f["skill"] for f in items]
    n = len(set(skills))
    line = "%d %s can show your keys in the chat, where they get saved: %s." % (n, plural(n, "skill"), join_names(skills))
    return [line], "Some of your skills can print your keys into the chat, where they get saved in your history.", items


def explain_open_files(items):
    n = len(items)
    line = "%d %s holding your keys can be opened by other accounts on this computer." % (n, plural(n, "file"))
    return [line], "Other accounts on this computer can open files that hold your keys.", items


def explain_app_keys(items):
    n, p = key_count(items), first_prov(items)
    line = "Your %s %s saved as plain text in your agent's settings." % (
        join_names(provider_names(items)) or "app", "key is" if n == 1 else "keys are")
    headline = ("Your %s key is sitting in plain text in your agent's settings. Malware that copies your "
                "agent's folder can use it to %s." % (nice(p), impact(p)))
    return [line], headline, about(items)


def explain_shell(items):
    n = key_count(items)
    line = "%d %s (%s) %s in your terminal startup files, so every program you run can read %s." % (
        n, plural(n, "key"), join_names(provider_names(items)) or "unknown", is_are(n), "it" if n == 1 else "them")
    headline = ("Your %s key is in your terminal startup files, so every program you run can read it."
                % nice(first_prov(items)))
    return [line], headline, about(items)


def explain_backups(items):
    n = len({f["path"] for f in items})
    line = "%d old backup %s still %s copies of your keys." % (n, plural(n, "file"), "holds" if n == 1 else "hold")
    return [line], "Old backups of your agent still hold copies of your keys.", items


def explain_skill_keys(items):
    n = len(items)
    p = provider_names(items)
    line = "%d %s your %s %s directly: %s." % (
        n, "skill uses" if n == 1 else "skills use", join_names(p), plural(len(set(p)), "key"),
        join_names([f["skill"] for f in items]))
    headline = ("Your agent holds your app keys for %d %s. If the agent is tricked, or its folder is "
                "copied, those keys go with it." % (n, plural(n, "skill")))
    return [line], headline, items


def explain_agent_logins(items):
    return [], None, items  # normal: shown only in details


EXPLAIN = {
    "memory": explain_memory, "skill-secret": explain_skill_secret, "skill-leak": explain_skill_leak,
    "open-files": explain_open_files, "app-keys": explain_app_keys, "shell": explain_shell,
    "backups": explain_backups, "skill-keys": explain_skill_keys, "agent-logins": explain_agent_logins,
}


def summarize(audit, targets):
    by_group = OrderedDict((g, [f for f in audit.findings if f["group"] == g]) for g in GROUPS)
    by_group = OrderedDict((g, v) for g, v in by_group.items() if v)

    # Only name the agent when there's more than one to tell apart.
    several_agents = len(targets) > 1
    lines, headline, subject = [], "No exposed keys found.", []
    for g, items in by_group.items():
        group_lines, group_headline, group_subject = EXPLAIN[g](items)
        label = agent_label(items)
        for line in group_lines:
            if several_agents and label:
                line = ("URGENT: [%s] %s" % (label, line[len("URGENT: "):]) if line.startswith("URGENT: ")
                        else "[%s] %s" % (label, line))
            lines.append(line)
        if group_headline and not subject:  # groups are in order of how bad, so the first one leads
            headline, subject = group_headline, group_subject

    # Name the agent in the headline only when it's about one of them; the
    # tagged lines say which agent each problem is in.
    subject_agent = agent_label(subject)
    if several_agents and subject_agent and " and " not in subject_agent:
        headline = name_agent(headline, subject_agent)

    worst = next((GROUPS[g]["level"] for g in by_group if GROUPS[g]["level"] != "info"), None)
    status = {"urgent": "ACTION NEEDED", "high": "ACTION NEEDED", "medium": "WORTH FIXING"}.get(worst, "ALL CLEAR")

    options = []
    acts = {f["action"] for f in audit.findings if f["group"] != "app-keys"}
    parts = []
    if acts & {"delete", "remove-line", "blank"}:
        parts.append("remove the stray copies of your keys")
    if "lock" in acts:
        parts.append("lock your files")
    if parts:
        options.append("Clean up: %s. Your agent can do this for you, one step at a time." % " and ".join(parts))
    to_rotate = [f for f in audit.findings if f.get("rotate") and f["kind"] == "secret"]
    if to_rotate:
        options.append("Replace the exposed keys: make new ones at %s and turn off the old ones. "
                       "This takes a few minutes each, on their websites." % join_names([nice(f["provider"]) for f in to_rotate], 4))
    swy = [f for f in audit.findings if f["kind"] == "secret" and f["group"] in ("app-keys", "shell", "skill-secret", "memory", "backups")
           and f["provider"] in KNOWN_THIRD_PARTY and f["provider"] not in AGENT_OWN] + \
        [f for f in audit.findings if f["group"] == "skill-keys"]
    if swy:
        apps = join_names(provider_names(swy), 4)
        agents = {f["platform"] for f in swy if f["platform"] != "shell"} or {p for p, _ in targets}
        if audit.swytchcode_for and agents <= audit.swytchcode_for:
            options.append("Swytchcode is installed for your agent: let it hold your %s keys too, "
                           "so your agent never has them." % apps)
        else:
            options.append("Optional: let Swytchcode hold your app keys (%s), so your agent never has them "
                           "and asks you before risky actions." % apps)

    return {
        "status": status,
        "headline": headline,
        "found": lines[:6],
        "more_found": max(0, len(lines) - 6),
        "options": options,
        "groups": [{"group": g, "level": GROUPS[g]["level"], "title": GROUPS[g]["title"], "count": len(v),
                    "agents": agent_label(v)}
                   for g, v in by_group.items()],
        "findings": [{k: v for k, v in f.items() if k != "abspath"} for f in
                     sorted(audit.findings, key=lambda f: (list(GROUPS).index(f["group"]), f["path"], f["line"]))],
        "skills": audit.skills,
        "agents": [t[0] for t in targets],
        "swytchcode_installed": bool(audit.swytchcode_for),
        "swytchcode_installed_for": sorted(audit.swytchcode_for),
        "files_checked": sum(audit.scanned.values()),
        "notes": audit.notes,
        "version": __version__,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }


def render_summary(rep):
    out = ["SECURITY CHECK: " + rep["status"], "", rep["headline"]]
    if rep["found"]:
        out += ["", "What we found:"]
        out += ["%d. %s" % (i, l) for i, l in enumerate(rep["found"], 1)]
        if rep["more_found"]:
            out.append("   ...and %d more." % rep["more_found"])
    if rep["options"]:
        out += ["", "What you can do:"]
        out += ["%d. %s" % (i, o) for i, o in enumerate(rep["options"], 1)]
        out += ["", 'Say "show me the details" to see where each one is.']
    out += ["", "Nothing was changed. No key was shown or sent anywhere."]
    return "\n".join(out)


def fix_text(f):
    rotate = ""
    if f.get("rotate"):
        url = PROVIDERS.get(f["provider"], (None, None, None))[2]
        rotate = " Then replace the key%s." % (" at " + url if url else " on the provider's website")
    a = f["action"]
    if a == "lock":
        return "Lock this file so only you can open it."
    if a == "delete":
        return "Delete this old copy." + rotate
    if a == "remove-line":
        return "Remove this line." + rotate
    if a == "blank":
        return "Remove the key from this file." + rotate
    if a == "replace-skill":
        if f["kind"] == "secret":
            return "Turn this skill off or rewrite it so it doesn't hold the key." + rotate
        return "Turn this skill off, or rewrite it so it doesn't touch keys."
    if a == "none":
        return "Normal: your agent needs this. Keep the file locked."
    if a == "chat-db":
        return "It's inside your agent's saved chats. Delete your old chats in the agent." + rotate
    return "This can't be fixed automatically. Remove it by hand, then replace the key." if f.get("rotate") else "Remove it by hand."


def render_details(rep):
    out = ["SECURITY CHECK: %s (details)" % rep["status"], ""]
    groups = OrderedDict()
    for f in rep["findings"]:
        groups.setdefault(f["group"], []).append(f)
    n = 0
    for g, items in groups.items():
        n += 1
        out.append("%d. %s" % (n, GROUPS[g]["title"]))
        for f in items:
            where = "%s, line %d" % (f["path"], f["line"]) if f["line"] else f["path"]
            if f["kind"] == "secret" and f["provider"] == "private_key":
                what = "Your agent's private key"
            elif f["kind"] == "secret":
                what = "%s key (%s)" % (nice(f["provider"]), f["key"]) if f["provider"] != "unknown" else "A key (%s)" % f["key"]
                if f.get("test_key"):
                    what += ", a test key"
            elif f["kind"] == "permissions":
                what = "Other accounts can open this file"
            elif f["kind"] == "prints-key":
                what = 'Skill "%s" prints a key' % f["skill"]
            elif f["kind"] == "reads-key-file":
                what = 'Skill "%s" opens a file full of keys' % f["skill"]
            else:
                what = 'Skill "%s" uses your %s key' % (f["skill"], join_names([nice(p) for p in f["provider"].split(",")]))
            out.append("   - %s" % what)
            if f.get("platform") in AGENT_NAMES:
                out.append("     Agent: %s" % AGENT_NAMES[f["platform"]])
            out.append("     Where: %s" % where)
            out.append("     Fix: %s" % fix_text(f))
        out.append("")
    if not groups:
        out.append("No exposed keys found.")
        out.append("")
    for note in rep["notes"]:
        out.append("Note: " + note)
    out.append("Keys are only described by their first 4 characters. Nothing was changed.")
    return "\n".join(out)


def render_markdown(rep):
    lines = ["# Agent security check: %s" % rep["status"].lower(), "", "**%s**" % rep["headline"], ""]
    if rep["found"]:
        lines += ["## What we found", ""] + ["%d. %s" % (i, l) for i, l in enumerate(rep["found"], 1)] + [""]
    if rep["options"]:
        lines += ["## What you can do", ""] + ["%d. %s" % (i, o) for i, o in enumerate(rep["options"], 1)] + [""]
    lines += ["## Details", "", "```", render_details(rep), "```", "",
              "_Made by the read-only api-key-leak-check skill %s on %s._" % (rep["version"], rep["generated"]), ""]
    return "\n".join(lines)


def ascii_safe(stream):
    # Some Windows consoles can't print non-ASCII text (file paths can have
    # it); replace what they can't show instead of crashing.
    try:
        stream.reconfigure(errors="replace")
    except AttributeError:
        pass


def main():
    ap = argparse.ArgumentParser(description="Read-only security check for OpenClaw and Hermes agents.")
    ap.add_argument("--version", action="version", version="api-key-leak-check " + __version__)
    ap.add_argument("--details", action="store_true", help="show where each problem is and how to fix it")
    ap.add_argument("--json", action="store_true", help="full result for the agent, including fix ids")
    ap.add_argument("--markdown", metavar="FILE", help="also save a shareable report")
    ap.add_argument("--platform", choices=["auto", "openclaw", "hermes"], default="auto")
    ap.add_argument("--home", help="agent folder, if it isn't in the usual place")
    ap.add_argument("--skills-only", action="store_true", help="only check skills")
    ap.add_argument("--no-shell", action="store_true", help="don't check terminal startup files")
    args = ap.parse_args()
    ascii_safe(sys.stdout)

    audit, targets = run_audit(args.platform, args.home, args.skills_only, not args.no_shell)
    if not targets:
        print("Couldn't find an OpenClaw or Hermes agent on this computer. "
              "If it's in a different folder, run this again with --platform and --home.")
        return 2
    rep = summarize(audit, targets)
    if args.markdown:
        with open(os.path.expanduser(args.markdown), "w", encoding="utf-8") as fh:
            fh.write(render_markdown(rep))
    if args.json:
        print(json.dumps(rep, indent=2))
    elif args.details:
        print(render_details(rep))
    else:
        print(render_summary(rep))
    if args.markdown and not args.json:
        print("\nReport saved to %s" % args.markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
