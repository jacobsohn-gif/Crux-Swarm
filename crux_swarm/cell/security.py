"""3-Layer Context Security Firewall, Shell Unwrapper & 4-Tier Privilege-Clamped PolicyEngine.

Provides full Crucible security parity inside every Symmetric `Crux-Cell`:
1. Child-process environment secret scrubbing (`scrub_child_environment`).
2. Strict workspace path-boundary verification + protected file/credential guards (`.env`, `*.pem`, `.git/hooks`, `.mcp.json`).
3. Multi-pattern high-entropy secret token redaction (`redact_cell_secrets`).
4. Shell-chain & wrapper unwrapping (`sudo`, `env`, `timeout`, `sh -c`, `&&`, `||`, `|`) + non-overridable
   catastrophic command detector (`rm -rf /`, `mkfs`, `dd of=/dev/...`, forkbombs).
5. Declarative TOML 4-Tier `CellPolicyEngine` (`admin > user > workspace > extension`) with extension privilege clamping.
"""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import os
import pathlib
import re
import shlex
from typing import Iterable, Literal

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

PolicyDecisionLiteral = Literal["ALLOW", "ASK_USER", "DENY"]

SENSITIVE_ENV_SUBSTRINGS: tuple[str, ...] = (
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
    "BEARER",
    "COOKIE",
    "AUTH",
)

SAFE_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "PWD",
        "EDITOR",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOPATH",
        "UV_CACHE_DIR",
    }
)

DEFAULT_DENIED_FILE_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "credentials.json",
    ".credentials.json",
    "application_default_credentials.json",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "kubeconfig",
)

DEFAULT_ALLOWED_EXCEPTIONS: tuple[str, ...] = (
    ".env.example",
    ".env.sample",
    ".env.template",
)

PROTECTED_WORKSPACE_WRITE_PATHS: tuple[str, ...] = (
    ".git/config",
    ".git/hooks",
    ".ush/hooks.json",
    ".ush/policies.toml",
    ".mcp.json",
    ".gemini/settings.json",
    ".claude/settings.json",
)

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}"),
    re.compile(r"sk-litellm-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),
    re.compile(r"AQ\.[0-9A-Za-z._-]{24,}"),
    re.compile(r"ya29\.[0-9A-Za-z._-]{24,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,255}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{24,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{20,}=*"),
)

HIGH_RISK_CMD_RE = re.compile(
    r"\b(rm\s+-rf|git\s+push\s+--force|git\s+reset\s+--hard|drop\s+table|gcloud\s+projects\s+delete|kubectl\s+delete)\b",
    re.IGNORECASE,
)

FORKBOMB_RE = re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;")
RAW_DISK_OF_RE = re.compile(r"^of=/dev/(?:disk|rdisk|sd|nvme|mmcblk|vd)")
SHELL_WRAPPERS: frozenset[str] = frozenset({"sudo", "env", "command", "nohup", "nice", "time", "stdbuf", "timeout"})
SUBSHELL_LAUNCHERS: frozenset[str] = frozenset({"sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/bin/zsh"})

TIER_WEIGHTS: dict[str, int] = {"admin": 400, "user": 300, "workspace": 200, "extension": 100}


def redact_cell_secrets(text: str) -> str:
    """Scrubs high-entropy API keys and bearer tokens before prompt, DAG, or ledger ingestion."""
    out = text
    for rx in SECRET_PATTERNS:
        if "bearer" in rx.pattern.lower():
            out = rx.sub(r"\1[REDACTED_SECRET]", out)
        else:
            out = rx.sub("[REDACTED_SECRET]", out)
    return out


def scrub_child_environment(
    base_env: dict[str, str] | None = None,
    explicit_allowlist: Iterable[str] = (),
    extra_overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Strips secret env vars (`*KEY*`, `*SECRET*`, `*TOKEN*`, etc.) and sets anti-hang CLI guards."""
    src = base_env if base_env is not None else dict(os.environ)
    allow = set(SAFE_ENV_ALLOWLIST) | set(explicit_allowlist)
    clean: dict[str, str] = {}
    for k, v in src.items():
        uk = k.upper()
        if k in allow:
            clean[k] = v
            continue
        if any(tok in uk for tok in SENSITIVE_ENV_SUBSTRINGS):
            continue
        clean[k] = v
    clean.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_EDITOR": "true",
            "PAGER": "cat",
            "GIT_PAGER": "cat",
            "DEBIAN_FRONTEND": "noninteractive",
            "CI": clean.get("CI", "true"),
        }
    )
    if extra_overrides:
        clean.update(extra_overrides)
    return clean


def _strip_quoted_literals(command: str) -> str:
    out: list[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if ch == "\\" and not in_sq and i + 1 < n:
            i += 2
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            i += 1
            continue
        if ch == '"' and not in_sq:
            in_dq = not in_dq
            i += 1
            continue
        if not in_sq and not in_dq:
            out.append(ch)
        i += 1
    return "".join(out)


def unwrap_shell_commands(command: str, _depth: int = 0) -> list[str]:
    """Splits chained shell commands (`&&`, `||`, `;`, `|`) and unwraps `sudo`/`env`/`sh -c` wrappers."""
    if not command or _depth > 4:
        return [command.strip()] if command else []
    raw_segments = [s.strip() for s in re.split(r"(?:&&|\|\||;|\||\n)+", command) if s.strip()]
    normalized: list[str] = []
    for seg in raw_segments:
        try:
            tokens = shlex.split(seg)
        except ValueError:
            normalized.append(seg)
            continue
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if "=" in tok and not tok.startswith("-") and not tok.startswith("$"):
                idx += 1
                continue
            if tok in SHELL_WRAPPERS:
                wrapper = tok
                idx += 1
                while idx < len(tokens) and tokens[idx].startswith("-"):
                    flag = tokens[idx]
                    idx += 1
                    if flag in ("-u", "-g", "-C", "-n", "-k", "-s") and idx < len(tokens):
                        idx += 1
                if wrapper == "timeout" and idx < len(tokens):
                    idx += 1
                continue
            break
        rem_tokens = tokens[idx:]
        rem = " ".join(rem_tokens).strip()
        if rem:
            normalized.append(rem)
        if rem_tokens:
            head = rem_tokens[0]
            if head == "eval" and len(rem_tokens) > 1:
                normalized.extend(unwrap_shell_commands(" ".join(rem_tokens[1:]), _depth=_depth + 1))
            elif head in SUBSHELL_LAUNCHERS and "-c" in rem_tokens[1:]:
                c_pos = rem_tokens.index("-c", 1)
                if c_pos + 1 < len(rem_tokens):
                    normalized.extend(unwrap_shell_commands(rem_tokens[c_pos + 1], _depth=_depth + 1))
    return normalized or [command.strip()]


def is_catastrophic_command(command: str) -> bool:
    """Detects catastrophic destructive commands (`rm -rf /`, `mkfs`, `dd of=/dev/...`, forkbombs)."""
    if FORKBOMB_RE.search(_strip_quoted_literals(command)):
        return True
    for seg in unwrap_shell_commands(command):
        try:
            tokens = shlex.split(seg)
        except ValueError:
            continue
        if not tokens:
            continue
        head = pathlib.PurePosixPath(tokens[0]).name
        if head == "mkfs" or head.startswith("mkfs."):
            if len(tokens) > 1:
                return True
        if head == "dd" and any(RAW_DISK_OF_RE.search(t) for t in tokens[1:]):
            return True
        if head == "rm":
            has_rec = any(
                t in ("--recursive", "--no-preserve-root") or (t.startswith("-") and not t.startswith("--") and ("r" in t or "R" in t))
                for t in tokens[1:]
            )
            targets = [re.sub(r"/+", "/", t) for t in tokens[1:] if not t.startswith("-")]
            if has_rec and any(t in ("/", "/*") for t in targets):
                return True
    return False


@dataclass(frozen=True)
class PolicyRule:
    tier: str  # admin | user | workspace | extension
    tool_pattern: str
    decision: PolicyDecisionLiteral
    priority: int = 100
    command_prefixes: tuple[str, ...] = ()
    command_regex: str | None = None
    reason: str = ""

    @property
    def sort_key(self) -> tuple[int, int]:
        return (TIER_WEIGHTS.get(self.tier, 100), self.priority)


class CellSecurityGuard:
    """Per-cell 3-layer security firewall (Workspace Sandbox + Secret Guard + 4-Tier Policy Gate)."""

    def __init__(self, workspace_root: pathlib.Path) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self._rules: list[PolicyRule] = []
        self.clamped_warnings: list[str] = []

    def add_policy_rule(self, rule: PolicyRule) -> bool:
        if rule.tier == "extension" and rule.decision not in ("DENY", "ASK_USER"):
            self.clamped_warnings.append(
                f"Ignored extension policy attempting `{rule.decision}` on `{rule.tool_pattern}` (privilege-clamped)."
            )
            return False
        self._rules.append(rule)
        return True

    def load_policy_toml(self, toml_text: str, *, tier: str = "workspace") -> int:
        if tomllib is None:
            return 0
        data = tomllib.loads(toml_text)
        loaded = 0
        for raw in data.get("rule", []):
            dec = str(raw.get("decision", "")).upper().strip()
            if tier == "extension" and dec not in ("DENY", "ASK_USER"):
                self.clamped_warnings.append(f"Dropped extension rule `{dec}` (privilege-clamped).")
                continue
            if dec not in ("ALLOW", "ASK_USER", "DENY"):
                continue
            prefixes = raw.get("commandPrefix", [])
            if isinstance(prefixes, str):
                prefixes = [prefixes]
            rule = PolicyRule(
                tier=tier,
                tool_pattern=str(raw.get("toolName", "*")),
                decision=dec,  # type: ignore[arg-type]
                priority=int(raw.get("priority", 100)),
                command_prefixes=tuple(str(p) for p in prefixes),
                command_regex=raw.get("commandRegex"),
                reason=str(raw.get("reason", f"{tier} policy rule")),
            )
            if self.add_policy_rule(rule):
                loaded += 1
        return loaded

    def validate_path(self, raw_path: str, *, write: bool = False) -> pathlib.Path:
        candidate = pathlib.Path(raw_path)
        if not candidate.is_absolute():
            candidate = (self.workspace_root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if not candidate.is_relative_to(self.workspace_root):
            raise PermissionError(
                f"Crux-Cell SecurityFirewall blocked path outside workspace: {raw_path!r}"
            )
        rel_posix = candidate.relative_to(self.workspace_root).as_posix()
        name = candidate.name
        if name not in DEFAULT_ALLOWED_EXCEPTIONS:
            for pat in DEFAULT_DENIED_FILE_PATTERNS:
                if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_posix, pat):
                    raise PermissionError(
                        f"Crux-Cell SecurityFirewall blocked access to sensitive credential file: {rel_posix!r}"
                    )
        if write:
            for prot in PROTECTED_WORKSPACE_WRITE_PATHS:
                if rel_posix == prot or rel_posix.startswith(prot + "/"):
                    raise PermissionError(
                        f"Crux-Cell SecurityFirewall blocked write to protected control path: {rel_posix!r}"
                    )
        return candidate

    def check_command_policy(self, command: str, *, tool_name: str = "exec_pty") -> tuple[PolicyDecisionLiteral, str]:
        if is_catastrophic_command(command):
            return "DENY", f"Blocked catastrophic destructive shell command: `{command}`"

        segments = unwrap_shell_commands(command)
        sorted_rules = sorted(self._rules, key=lambda r: r.sort_key, reverse=True)
        for seg in segments:
            for rule in sorted_rules:
                if not fnmatch.fnmatch(tool_name, rule.tool_pattern):
                    continue
                if rule.command_prefixes and not any(
                    seg == p or seg.startswith(p + " ") for p in rule.command_prefixes
                ):
                    continue
                if rule.command_regex and not re.search(rule.command_regex, seg):
                    continue
                return rule.decision, rule.reason

        for seg in segments:
            if HIGH_RISK_CMD_RE.search(seg):
                return "ASK_USER", f"High-impact shell command requires human confirmation: `{command}`"
        return "ALLOW", "Command permitted by cell policy."
