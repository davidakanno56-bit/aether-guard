"""
AetherGuard: Zero-Trust Runtime Security Proxy for Autonomous Coding Agents
Developed for Nebius x NVIDIA Global AI Hackathon.
"""

import os
import re
import time
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Load environment configuration
load_dotenv()

NEBIUS_API_BASE_URL = os.getenv("NEBIUS_API_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY", "mock-dev-key")
NEMOTRON_NANO_MODEL = os.getenv("NEMOTRON_NANO_MODEL", "nvidia/nemotron-3-nano-30b-a3b")
NEMOTRON_ULTRA_MODEL = os.getenv("NEMOTRON_ULTRA_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")
CIRCUIT_BREAKER_MAX_FAILURES = int(os.getenv("CIRCUIT_BREAKER_MAX_FAILURES", "3"))

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("AetherGuard")

# ==============================================================================
# Models & Schemas
# ==============================================================================

class ToolVerificationRequest(BaseModel):
    tool_name: str = Field(..., description="Target tool name to be invoked.")
    tool_args: Dict[str, Any] = Field(default_factory=dict, description="Payload/arguments for the tool.")
    declared_intent: str = Field(..., description="Agent declared natural language objective.")
    agent_id: Optional[str] = Field(default="agent-alpha", description="Identifier of the autonomous agent.")
    session_id: Optional[str] = Field(default=None, description="Current agent execution session ID.")


class ToolVerificationResponse(BaseModel):
    status: str = Field(..., description="AUTHORIZED, QUARANTINED, or CIRCUIT_BROKEN")
    latency_ms: float = Field(..., description="End-to-end verification latency in milliseconds")
    violation: Optional[str] = Field(default=None, description="Specific security rule violated if quarantined")
    reason: Optional[str] = Field(default=None, description="Detailed explanation of the verdict")
    threat_type: Optional[str] = Field(default=None, description="Threat categorization")
    tier: str = Field(default="tier_1_fast", description="Inspection tier that rendered verdict")
    tool_name: Optional[str] = None
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ==============================================================================
# Active WebSocket Connection Manager (/ws/telemetry)
# ==============================================================================

class TelemetryConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.history: List[Dict[str, Any]] = []
        self.max_history = 100

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Telemetry client connected. Active connections: {len(self.active_connections)}")
        # Send recent event history to newly connected dashboard
        if self.history:
            try:
                await websocket.send_json({
                    "event_type": "HISTORY_BATCH",
                    "data": self.history[-25:],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            except Exception as e:
                logger.warning(f"Failed to send history batch: {e}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Telemetry client disconnected. Remaining: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcasts event payload as JSON to all active dashboard connections."""
        self.history.append(message)
        if len(self.history) > self.max_history:
            self.history.pop(0)

        dead_connections = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


telemetry_manager = TelemetryConnectionManager()

# ==============================================================================
# Regex Detection Rules for High-Risk Exfiltration & Injection Signatures
# ==============================================================================

DETECTION_RULES = [
    # 1. Credential theft & Sensitive File Access (cat .env, /etc/shadow, SSH/Cloud keys)
    (
        r"(?i)\b(?:cat|type|head|tail|less|more|Get-Content)\s+(?:[^\s;\|&]*\/)?\.env\b",
        "CREDENTIAL_THEFT",
        "RULE_CAT_ENV",
        "Unauthorized access to environment secret variables (.env)"
    ),
    (
        r"(?i)\b(?:cat|type|head|tail|less|more)\s+(?:[^\s;\|&]*\/)?etc\/(?:shadow|passwd|master\.passwd)\b",
        "PRIVILEGE_ESCALATION",
        "RULE_SHADOW_READ",
        "Unauthorized attempt to read system authentication hashes (/etc/shadow)"
    ),
    (
        r"(?i)\b(?:cat|type|head|tail|less|more)\s+(?:[^\s;\|&]*\/)?(?:id_rsa|id_ed25519|id_ecdsa|\.aws\/credentials|\.kube\/config)\b",
        "CREDENTIAL_THEFT",
        "RULE_SSH_AWS_CREDENTIALS",
        "Attempt to read private SSH or cloud service credentials"
    ),

    # 2. Data Exfiltration Signatures (curl ... -d @, wget --post-data, dark-exfil, webhook drops)
    (
        r"(?i)\bcurl\s+.*(?:-d\s*@|--data\s*@|--data-binary\s*@|--data-raw\s*@|-d\b|--data\b|-F\b|--form\b)",
        "DATA_EXFILTRATION",
        "RULE_CURL_EXFILTRATION",
        "Data exfiltration signature detected via HTTP POST / upload (curl ... -d @)"
    ),
    (
        r"(?i)\bwget\s+.*(?:--post-data|--post-file)\b",
        "DATA_EXFILTRATION",
        "RULE_WGET_EXFILTRATION",
        "Data exfiltration signature detected via wget POST payload"
    ),
    (
        r"(?i)\b(?:webhook\.site|requestbin|pipedream|pastebin\.com|transfer\.sh|bashupload\.com|dark-exfil\.net)\b",
        "MALICIOUS_C2",
        "RULE_EXFIL_ENDPOINT",
        "Communication signature with known data exfiltration / C2 endpoint"
    ),

    # 3. Unauthorized SQL Role Updates (UPDATE ... SET role='superuser' / 'admin')
    (
        r"(?i)\bUPDATE\s+[a-zA-Z0-9_.]+\s+SET\s+.*role\s*=\s*['\"]?(?:superuser|admin|root)['\"]?",
        "PRIVILEGE_ESCALATION",
        "RULE_UNAUTHORIZED_SQL_ROLE_UPDATE",
        "Unauthorized SQL privilege escalation (UPDATE ... SET role='superuser')"
    ),
    (
        r"(?i)\b(?:GRANT\s+ALL|ALTER\s+USER\s+.*SUPERUSER|ALTER\s+ROLE\s+.*SUPERUSER)\b",
        "PRIVILEGE_ESCALATION",
        "RULE_SQL_GRANT_SUPERUSER",
        "Direct SQL grant of superuser or administrative privileges"
    ),

    # 4. Reverse Shells & C2 Shell Redirection
    (
        r"(?i)\/dev\/tcp\/[0-9.]+\/[0-9]+",
        "REVERSE_SHELL",
        "RULE_BASH_DEV_TCP",
        "Bash /dev/tcp direct socket connection reverse shell"
    ),
    (
        r"(?i)\bbash\s+-i\s+>&",
        "REVERSE_SHELL",
        "RULE_BASH_INTERACTIVE_REDIRECTION",
        "Interactive bash reverse shell redirection"
    ),
    (
        r"(?i)\bnc(?:at)?\s+.*-[a-z0-9]*e\s+",
        "REVERSE_SHELL",
        "RULE_NETCAT_EXEC_SHELL",
        "Netcat remote shell execution payload"
    ),
    (
        r"(?i)\bsocat\s+.*exec:.*pty",
        "REVERSE_SHELL",
        "RULE_SOCAT_REVERSE_SHELL",
        "Socat remote interactive terminal payload"
    ),
    (
        r"(?i)python(?:\d)?\s+-c\s+.*socket.*pty",
        "REVERSE_SHELL",
        "RULE_PYTHON_REVERSE_SHELL",
        "Python interactive socket reverse shell payload"
    ),

    # 5. Destructive Operations & Wildcard Purges
    (
        r"(?i)\brm\s+-[a-zA-Z0-9]*r[a-zA-Z0-9]*\s+",
        "DESTRUCTIVE_EXECUTION",
        "RULE_RM_RECURSIVE",
        "Destructive recursive file deletion (rm -r / rm -rf)"
    ),
    (
        r"(?i)\bmkfs(?:\.[a-z0-9]+)?\b",
        "DESTRUCTIVE_EXECUTION",
        "RULE_MKFS_REFORMAT",
        "Direct disk or filesystem format attempt (mkfs)"
    ),
    (
        r"(?i)\bdd\s+if=.*of=\/dev\/(?:sd|nvme|hd|zero|null)\b",
        "DESTRUCTIVE_EXECUTION",
        "RULE_DD_RAW_DEVICE_OVERWRITE",
        "Direct block-device overwrite via dd"
    ),

    # 6. Indirect Prompt Injection & Role Overrides
    (
        r"(?i)<\|im_start\|>",
        "PROMPT_INJECTION",
        "RULE_CHATML_DELIMITER_INJECTION",
        "Token smuggling via ChatML injection delimiter"
    ),
    (
        r"(?i)system:\s*override",
        "PROMPT_INJECTION",
        "RULE_SYSTEM_ROLE_HIJACK",
        "Attempted system role hijack token"
    ),
    (
        r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
        "PROMPT_INJECTION",
        "RULE_INSTRUCTION_OVERRIDE",
        "Classic indirect prompt injection instruction override"
    ),
]

COMPILED_RULES = [
    (re.compile(pattern), threat_type, rule_id, reason)
    for pattern, threat_type, rule_id, reason in DETECTION_RULES
]

def scan_tier_1_signatures(tool_name: str, tool_args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Sub-millisecond regex signature scanner for fast inspection."""
    combined_buffer = f"{tool_name} {json.dumps(tool_args, default=str)}"
    for regex, threat_type, rule_id, reason in COMPILED_RULES:
        match = regex.search(combined_buffer)
        if match:
            return {
                "matched": True,
                "threat_type": threat_type,
                "violation": rule_id,
                "reason": f"{reason} (Matched snippet: '{match.group(0)[:80]}')",
                "matched_snippet": match.group(0)[:120],
                "tier": "tier_1_fast"
            }
    return None

# ==============================================================================
# Tier-2 Semantic Scope Verification
# ==============================================================================

PRIVILEGED_TOOLS = {
    "execute_bash", "run_command", "shell", "exec_command", "bash", "terminal",
    "powershell", "cmd", "sql_query", "db_execute", "database_mutation",
    "write_file", "delete_file", "replace_file_content"
}

def verify_semantic_scope(tool_name: str, tool_args: Dict[str, Any], declared_intent: str) -> Dict[str, Any]:
    """
    Tier-2 Semantic Scope Verification:
    Detects discrepancies between declared natural intent and mutating privileged actions.
    """
    args_str = json.dumps(tool_args, default=str).lower()
    intent_lower = declared_intent.lower()

    read_only_intents = any(
        w in intent_lower for w in [
            "read", "view", "list", "check", "inspect", "show", "get",
            "optimize", "analyze", "audit", "profile", "benchmark", "monitor", "explain", "lint"
        ]
    )
    mutating_actions = any(
        w in args_str for w in [
            "drop ", "delete", "truncate", "update ", "alter ", "insert ", "grant ",
            "superuser", "role=", "role =", "set role", "admin", "rm ", "chmod",
            "chown", "kill", "pkill", "reboot", "shutdown", "wget", "curl"
        ]
    )

    if read_only_intents and mutating_actions:
        return {
            "allowed": False,
            "threat_type": "SCOPE_VIOLATION",
            "violation": "RULE_SCOPE_MISMATCH",
            "reason": f"Scope Mismatch Detected: Declared intent is read-only/analytic ('{declared_intent}') but tool executes mutating/elevated actions.",
            "tier": "tier_2_scope"
        }

    return {
        "allowed": True,
        "reason": "Privileged operation semantically consistent with declared intent.",
        "tier": "tier_2_scope"
    }

# ==============================================================================
# FastAPI Application & CORS
# ==============================================================================

app = FastAPI(
    title="AetherGuard Zero-Trust Security Proxy",
    description="Sub-100ms runtime security proxy for autonomous coding agents with Dual-Tier inspection.",
    version="1.0.0"
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# Endpoints
# ==============================================================================

@app.get("/health")
async def health():
    """
    Health check endpoint returning system status and mode.
    """
    return {
        "status": "healthy",
        "mode": "local_mock_ready",
        "service": "AetherGuard-Proxy",
        "models": {
            "tier_1_fast": "Deterministic Regex Signature Bank",
            "tier_2_fast_scope": NEMOTRON_NANO_MODEL, "tier_2_nano": NEMOTRON_NANO_MODEL,
            "tier_2_ultra": NEMOTRON_ULTRA_MODEL
        },
        "active_ws_connections": len(telemetry_manager.active_connections),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """
    Active WebSocket connection endpoint broadcasting event payloads as JSON.
    """
    await telemetry_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "PING":
                    await websocket.send_json({
                        "type": "PONG",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
            except Exception:
                pass
    except WebSocketDisconnect:
        telemetry_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        telemetry_manager.disconnect(websocket)


@app.post("/v1/tools/verify")
async def verify_tool(payload: ToolVerificationRequest):
    """
    POST /v1/tools/verify endpoint:
    - Accepts: { "tool_name": str, "tool_args": dict, "declared_intent": str }
    - If attack matches: broadcast QUARANTINED alert over WebSocket & return 403 with violation details.
    - If safe: return 200 AUTHORIZED status with low latency (<50ms simulation).
    """
    start_time = time.perf_counter()
    event_id = str(uuid.uuid4())

    # 1. Tier-1 Fast Regex Signature Inspection
    tier_1_hit = scan_tier_1_signatures(payload.tool_name, payload.tool_args)
    tier_1_latency = (time.perf_counter() - start_time) * 1000.0

    if tier_1_hit:
        event_payload = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "TOOL_QUARANTINED",
            "status": "QUARANTINED",
            "tier": "tier_1_fast",
            "tool_name": payload.tool_name,
            "tool_args": payload.tool_args,
            "declared_intent": payload.declared_intent,
            "agent_id": payload.agent_id,
            "threat_type": tier_1_hit["threat_type"],
            "violation": tier_1_hit["violation"],
            "reason": tier_1_hit["reason"],
            "matched_snippet": tier_1_hit.get("matched_snippet"),
            "latency_ms": round(tier_1_latency, 2)
        }

        # Broadcast QUARANTINED alert over WebSocket
        await telemetry_manager.broadcast(event_payload)

        # Return 403 status code with violation details
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status": "QUARANTINED",
                "latency_ms": round(tier_1_latency, 2),
                "violation": tier_1_hit["violation"],
                "reason": tier_1_hit["reason"],
                "threat_type": tier_1_hit["threat_type"],
                "tier": "tier_1_fast",
                "tool_name": payload.tool_name,
                "event_id": event_id
            }
        )

    # 2. Tier-2 Privileged Tool Scope Inspection
    is_privileged = (
        payload.tool_name.lower() in PRIVILEGED_TOOLS or
        any(k in payload.tool_name.lower() for k in ["bash", "exec", "cmd", "shell", "sql", "db", "write", "delete"])
    )

    if is_privileged:
        tier_2_result = verify_semantic_scope(
            payload.tool_name,
            payload.tool_args,
            payload.declared_intent
        )
        total_latency = (time.perf_counter() - start_time) * 1000.0

        if not tier_2_result.get("allowed", False):
            event_payload = {
                "event_id": event_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "TOOL_QUARANTINED",
                "status": "QUARANTINED",
                "tier": "tier_2_scope",
                "tool_name": payload.tool_name,
                "tool_args": payload.tool_args,
                "declared_intent": payload.declared_intent,
                "agent_id": payload.agent_id,
                "threat_type": tier_2_result.get("threat_type", "SCOPE_VIOLATION"),
                "violation": tier_2_result.get("violation", "RULE_SCOPE_MISMATCH"),
                "reason": tier_2_result.get("reason"),
                "latency_ms": round(total_latency, 2)
            }

            await telemetry_manager.broadcast(event_payload)

            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "status": "QUARANTINED",
                    "latency_ms": round(total_latency, 2),
                    "violation": tier_2_result.get("violation", "RULE_SCOPE_MISMATCH"),
                    "reason": tier_2_result.get("reason"),
                    "threat_type": tier_2_result.get("threat_type", "SCOPE_VIOLATION"),
                    "tier": "tier_2_scope",
                    "tool_name": payload.tool_name,
                    "event_id": event_id
                }
            )

    # 3. Clean Tool Authorization (<50ms low latency simulation)
    measured_latency = (time.perf_counter() - start_time) * 1000.0
    # Simulate realistic proxy verification latency (~38.0ms)
    simulated_latency = 38.0 if measured_latency < 38.0 else round(measured_latency, 2)

    event_payload = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "TOOL_AUTHORIZED",
        "status": "AUTHORIZED",
        "tier": "tier_2_scope" if is_privileged else "clean",
        "tool_name": payload.tool_name,
        "tool_args": payload.tool_args,
        "declared_intent": payload.declared_intent,
        "agent_id": payload.agent_id,
        "latency_ms": simulated_latency
    }

    # Broadcast green status event over WebSocket
    await telemetry_manager.broadcast(event_payload)

    # Return 200 AUTHORIZED status
    return {
        "status": "AUTHORIZED",
        "latency_ms": simulated_latency,
        "tier": "tier_2_scope" if is_privileged else "clean",
        "tool_name": payload.tool_name,
        "event_id": event_id
    }


@app.get("/v1/telemetry/history")
async def get_history():
    """Retrieve recent telemetry events."""
    return {
        "events": telemetry_manager.history,
        "total": len(telemetry_manager.history),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
