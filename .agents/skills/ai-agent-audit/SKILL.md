---
name: ai-agent-audit
description: Security audit for AI agent endpoints (Claude Desktop/Code, MCP servers, plugins, extensions)
type: skill
---

# AI Agent Security Audit

Comprehensive security auditing methodology for AI agent endpoints, focusing on Claude Desktop, Claude Code, MCP servers, plugins, extensions, and autonomous execution features.

> **Origin:** Based on CLAUDIT-SEC methodology — read-only audit tool for Claude Desktop/Code configuration analysis.

---

## 🎯 Routing & Detection

### Detectar Claude Desktop/Code no Alvo

```bash
# Process detection (local machine)
pgrep -i "Claude"
pgrep -i "claude-code"

# macOS paths
ls -la ~/Library/Application\ Support/Claude/
ls -la ~/.claude/

# Windows paths
dir "%APPDATA%\Claude"
dir "%USERPROFILE%\.claude"

# Network indicators (remote assessment)
# MCP servers often expose HTTP endpoints on specific ports
nmap -p 8897,8080,3000 target -sV
```

### Sinais de Alerta
- [ ] Processo "Claude" em execução
- [ ] Diretórios de configuração presentes
- [ ] MCP servers ativos (verificar portas 8897, 8080, 3000)
- [ ] Scheduled tasks relacionadas ao Claude
- [ ] Plugin hooks com shell commands

### Ação Imediata
```bash
# Se Claude detectado → ATIVAR ai-agent-audit skill
# Executar audit completo com claudit-sec
./claude_audit.sh --json > ai_agent_audit.json

# Se MCP server detectado → Enumerar endpoints
curl -sk http://target:8897/mcp
```

---

## 1. Desktop & Cowork Settings Audit (PTES 2.5)

### 1.1 Keep-Awake Configuration

**File:** `claude_desktop_config.json` → `preferences.keepAwakeEnabled`

```bash
# macOS check
jq '.preferences.keepAwakeEnabled' ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Risk assessment
if keepAwakeEnabled == true:
    # Machine never sleeps → increased attack surface
    # Network reachable for longer periods
    # Physical access window extended
```

**Severity:** WARN — Overriding system power management

### 1.2 Autonomous Execution Flags

**Files:** 
- `claude_desktop_config.json` → `preferences.coworkScheduledTasksEnabled`
- `cowork_settings.json` → various autonomous flags

```bash
# Check master switch for autonomous tasks
jq '.preferences.coworkScheduledTasksEnabled' claude_desktop_config.json

# Check Code Desktop scheduled tasks
jq '.preferences.ccdScheduledTasksEnabled' claude_desktop_config.json

# Check web search enabled
jq '.webSearchEnabled' cowork_settings.json

# Check browser use enabled
jq '.browserUseEnabled' cowork_settings.json
```

**Severity:** WARN — Autonomous AI execution requires governance review

### 1.3 Network Mode & Egress Policy

**File:** `config.json`, `local_*.json`

```bash
# Check network mode (isolated vs unrestricted)
jq '.networkMode' config.json

# Check egress allowed domains
jq '.egressAllowedDomains' local_*.json

# CRITICAL if egress == ["*"] (unrestricted)
# HIGH if egress includes sensitive domains
```

**Risk Assessment:**
| Egress Policy | Severity |
|---------------|----------|
| `["*"]` | CRITICAL — Unrestricted outbound |
| Includes `*` wildcards | HIGH — Broad egress |
| Specific domains only | MEDIUM — Review each domain |
| Empty/none | LOW — Restricted |

---

## 2. MCP Server Audit (PTES 2.5.4)

### 2.1 MCP Server Enumeration

**File:** `claude_desktop_config.json` → `mcpServers`

```bash
# List all configured MCP servers
jq '.mcpServers | keys[]' claude_desktop_config.json

# Extract server details
jq '.mcpServers | to_entries[] | {
    name: .key,
    command: .value.command,
    args: .value.args,
    env_keys: (.value.env | keys)
}' claude_desktop_config.json
```

### 2.2 Command & Argument Analysis

```bash
# Redact sensitive patterns from args
# Patterns to redact: sk-*, key=*, token=*, secret=*, password=*

# Extract and analyze commands
for server in $(jq '.mcpServers | keys[]' claude_desktop_config.json -r); do
    echo "=== Server: $server ==="
    jq -r ".mcpServers[\"$server\"].command" claude_desktop_config.json
    jq -r ".mcpServers[\"$server\"].args[]" claude_desktop_config.json 2>/dev/null
    
    # Check for dangerous patterns
    # - npx with untrusted packages
    # - python with remote scripts
    # - curl | bash patterns
    # - Direct shell execution
done
```

### 2.3 Environment Variable Keys

```bash
# List env var KEY NAMES only (never values)
jq '.mcpServers | to_entries[] | {
    server: .key,
    env_keys: (.value.env | keys)
}' claude_desktop_config.json

# High-risk env var patterns
# - *_API_KEY, *_SECRET, *_TOKEN
# - AWS_*, AZURE_*, GCP_*
# - DATABASE_URL, CONNECTION_STRING
```

### 2.4 MCP Server Risk Scoring

| Indicator | Severity | Rationale |
|-----------|----------|-----------|
| Command executes remote code | CRITICAL | `curl | bash`, `wget | sh` |
| Unscoped npm/npx packages | HIGH | Supply chain risk |
| Cloud credentials in env | HIGH | AWS, Azure, GCP keys |
| Database connection strings | HIGH | Direct data access |
| Local file system access | MEDIUM | Potential data exfil |
| Network access enabled | MEDIUM | Lateral movement |

---

## 3. Plugin Audit (PTES 2.5.4)

### 3.1 Plugin Enumeration

**Files:**
- `cowork_plugins/installed_plugins.json`
- `remote_cowork_plugins/manifest.json`
- `cowork_plugins/cache/*/`

```bash
# List installed plugins
jq '.plugins[] | {
    name: .name,
    version: .version,
    author: .author,
    scope: .scope,
    description: .description
}' installed_plugins.json

# Count skills per plugin
for plugin_dir in cowork_plugins/cache/*/*/; do
    plugin_name=$(basename "$plugin_dir")
    skill_count=$(find "$plugin_dir/skills" -name "SKILL.md" 2>/dev/null | wc -l)
    echo "$plugin_name: $skill_count skills"
done
```

### 3.2 Plugin Hook Analysis

**File:** `hooks/hooks.json` in plugin directories

```bash
# Find all plugin hooks
find cowork_plugins -name "hooks.json" -exec jq -r '
    .hooks | to_entries[] | 
    "\(.key): \(.value[].command)"
' {} \;

# High-risk hook events
# - PreToolUse: Executes before tool calls
# - PostToolUse: Executes after tool calls  
# - OnInstall: Executes on plugin install
# - OnStartup: Executes on Claude startup

# CRITICAL: Shell commands in hooks
# Look for: bash, sh, zsh, powershell, cmd.exe
```

### 3.3 Plugin Risk Indicators

| Finding | Severity | Action |
|---------|----------|--------|
| Hook with shell command | CRITICAL | Review command intent |
| Unknown/unverified author | HIGH | Research author reputation |
| Broad tool permissions | HIGH | Review tool grants |
| Network egress in plugin | MEDIUM | Check destination domains |
| File system access | MEDIUM | Review allowed paths |

---

## 4. Extension (DXT) Audit (PTES 2.5.4)

### 4.1 Extension Enumeration

**File:** `extensions-installations.json`

```bash
# List all installed extensions
jq '.extensions[] | {
    name: .name,
    version: .version,
    author: .author,
    signed: .isSigned,
    signatureStatus: .signatureStatus
}' extensions-installations.json

# Check for unsigned extensions
jq '.extensions[] | select(.isSigned == false)' extensions-installations.json
```

### 4.2 Dangerous Tool Grants

```bash
# Extensions with dangerous tools
DANGEROUS_TOOLS="execute_javascript write_file edit_file run_command execute_sql"

for tool in $DANGEROUS_TOOLS; do
    echo "=== Extension with $tool ==="
    jq --arg tool "$tool" '.extensions[] | 
        select(.tools[] | contains($tool)) | 
        {name: .name, version: .version}' extensions-installations.json
done
```

### 4.3 Extension Settings Audit

**Directory:** `Claude Extensions Settings/*.json`

```bash
# Check allowed directories per extension
for settings_file in "Claude Extensions Settings"/*.json; do
    echo "=== $(basename "$settings_file") ==="
    jq '.allowedDirectories[]' "$settings_file" 2>/dev/null
    
    # High-risk directories
    # - Home directory (~)
    # - System directories (/etc, /System)
    # - Credential stores (.ssh, .gnupg, Keychains)
done
```

### 4.4 Extension Risk Matrix

| Tool Grant | Risk Level | Potential Impact |
|------------|------------|------------------|
| `execute_javascript` | CRITICAL | XSS, DOM manipulation, credential theft |
| `write_file` | CRITICAL | Malware drop, config modification |
| `edit_file` | HIGH | Code injection, config tampering |
| `run_command` | CRITICAL | Arbitrary command execution |
| `execute_sql` | HIGH | Database manipulation, data exfil |

---

## 5. Extension Governance Audit (PTES 3.3)

### 5.1 Blocklist/Allowlist Status

**Files:**
- `extensions-blocklist.json`
- `config.json` → `extensionAllowlist`

```bash
# Check if blocklist exists and has entries
if [[ -f extensions-blocklist.json ]]; then
    blocklist_count=$(jq '.blocklist | length' extensions-blocklist.json)
    echo "Blocklist entries: $blocklist_count"
else
    echo "WARN: No blocklist found"
fi

# Check allowlist status
jq '.extensionAllowlist' config.json
# If enabled: only allowlisted extensions can run
# If disabled: any extension can run (higher risk)
```

### 5.2 Governance Gaps

| Finding | Severity | Recommendation |
|---------|----------|----------------|
| No blocklist present | MEDIUM | Implement blocklist |
| Allowlist disabled | MEDIUM | Enable allowlist |
| Empty blocklist | LOW | Review and populate |
| Wildcard allowlist entries | HIGH | Remove wildcards |

---

## 6. Skills Audit (PTES 2.5.4)

### 6.1 Skill Path Enumeration

```bash
# User skills (source: "user")
SKILL_PATHS=(
    "$HOME/Documents/Claude/Scheduled/*/SKILL.md"
    "$HOME/skills-plugin/*/*/skills/*/SKILL.md"
    "$HOME/.skills/skills/*/SKILL.md"
    "$HOME/.claude/skills/*/SKILL.md"
)

# Installed plugin skills (source: "plugin")
PLUGIN_SKILL_PATHS=(
    "<session>/remote_cowork_plugins/*/skills/*/SKILL.md"
    "<session>/cowork_plugins/cache/*/*/*/skills/*/SKILL.md"
    "$HOME/.claude/plugins/marketplaces/*/{plugins,external_plugins}/*/skills/*/SKILL.md"
)

# Count and catalog skills
for path_pattern in "${SKILL_PATHS[@]}" "${PLUGIN_SKILL_PATHS[@]}"; do
    for skill_file in $path_pattern; do
        [[ -f "$skill_file" ]] || continue
        
        # Extract frontmatter
        name=$(grep -A1 "^name:" "$skill_file" | tail -1 | cut -d: -f2 | tr -d ' ')
        desc=$(grep -A1 "^description:" "$skill_file" | tail -1 | cut -d: -f2-)
        
        echo "Skill: $name"
        echo "Path: $skill_file"
        echo "Description: $desc"
        echo "---"
    done
done
```

### 6.2 Skill Content Analysis

```bash
# Parse skill frontmatter
parse_skill_frontmatter() {
    local file="$1"
    local content=$(cat "$file" 2>/dev/null)
    
    # Check for frontmatter delimiters
    if [[ "$content" == "---"* ]]; then
        # Extract name, description, type
        local fm=$(echo "$content" | sed -n '2,/^---/{/^---/!p;}')
        
        echo "$fm" | while IFS=: read -r key value; do
            case "$key" in
                name) skill_name="$value" ;;
                description) skill_desc="$value" ;;
                type) skill_type="$value" ;;
            esac
        done
    fi
}

# Risk indicators in skills
# - Shell commands (bash, sh, curl, wget)
# - File operations (write, edit, delete)
# - Network calls (HTTP requests, API calls)
# - Credential handling
```

### 6.3 Scheduled Task Skills

```bash
# Skills in Scheduled directory have autonomous execution
scheduled_skills="$HOME/Documents/Claude/Scheduled"

if [[ -d "$scheduled_skills" ]]; then
    count=$(find "$scheduled_skills" -name "SKILL.md" | wc -l)
    echo "Scheduled skills (autonomous execution): $count"
    
    # List each scheduled skill
    find "$scheduled_skills" -name "SKILL.md" -exec sh -c '
        echo "=== {} ==="
        grep -E "^(name|description):" "$1"
    ' sh {} \;
fi
```

---

## 7. Scheduled Tasks Audit (PTES 2.5.4)

### 7.1 Task Enumeration

**File:** `scheduled-tasks.json`

```bash
# List all scheduled tasks
jq '.tasks[] | {
    id: .id,
    name: .name,
    cron: .cronExpression,
    enabled: .enabled,
    skillName: .skillName,
    skillDescription: .skillDescription
}' scheduled-tasks.json

# Check if scheduled tasks are globally enabled
jq '.preferences.coworkScheduledTasksEnabled' claude_desktop_config.json
```

### 7.2 Cron Expression Analysis

```bash
# Translate cron to human-readable
# Format: minute hour day month weekday

cron_to_english() {
    local cron="$1"
    local minute=$(echo "$cron" | awk '{print $1}')
    local hour=$(echo "$cron" | awk '{print $2}')
    
    if [[ "$minute" == "0" && "$hour" == "0" ]]; then
        echo "Daily at midnight"
    elif [[ "$minute" == "0" ]]; then
        echo "Hourly at minute $minute"
    elif [[ "$hour" == "*" ]]; then
        echo "Every $minute minutes"
    else
        echo "At minute $minute, hour $hour"
    fi
}

# High-frequency tasks (potential concern)
jq -r '.tasks[] | select(.cronExpression | test("^[*0-9,/-]{1,10} [*0-9,/-]{1,10} ")) | 
    "\(.name): \(.cronExpression)"' scheduled-tasks.json
```

### 7.3 Scheduled Task Risk Assessment

| Frequency | Severity | Rationale |
|-----------|----------|-----------|
| Every minute | HIGH | Rapid autonomous execution |
| Hourly | MEDIUM | Frequent autonomous actions |
| Daily | LOW | Standard automation |
| Weekly/Monthly | INFO | Minimal concern |

---

## 8. Connector Audit (PTES 2.5.4)

### 8.1 Connector Enumeration

**File:** `local_*.json` → `remoteMcpServersConfig`

```bash
# List all connectors
jq '.remoteMcpServersConfig[] | {
    name: .name,
    type: .type,  # web, desktop, not_connected
    egressAllowedDomains: .egressAllowedDomains,
    disabledMcpTools: .disabledMcpTools
}' local_*.json

# Check for OAuth-authenticated connectors
jq '.remoteMcpServersConfig[] | select(.authType == "oauth")' local_*.json
```

### 8.2 Egress Domain Analysis

```bash
# Extract all allowed egress domains
jq -r '.remoteMcpServersConfig[].egressAllowedDomains[]?' local_*.json | sort -u

# CRITICAL: Unrestricted egress
jq '.remoteMcpServersConfig[] | select(.egressAllowedDomains == ["*"])' local_*.json

# HIGH: Wildcard subdomains
jq -r '.remoteMcpServersConfig[].egressAllowedDomains[]?' local_*.json | grep '\*\.'
```

### 8.3 Disabled Tools Analysis

```bash
# List explicitly disabled MCP tools
jq -r '.remoteMcpServersConfig[].disabledMcpTools[]?' local_*.json

# Check if dangerous tools are NOT disabled
DANGEROUS_TOOLS="execute_javascript write_file edit_file run_command execute_sql"

for tool in $DANGEROUS_TOOLS; do
    if ! grep -q "$tool" <(jq -r '.remoteMcpServersConfig[].disabledMcpTools[]?' local_*.json); then
        echo "WARN: Dangerous tool NOT disabled: $tool"
    fi
done
```

---

## 9. Runtime State Audit (PTES 2.5.4)

### 9.1 Process Detection

```bash
# Check if Claude is running
if pgrep -i "Claude" > /dev/null; then
    echo "INFO: Claude process is running"
    pgrep -i "Claude" | xargs ps -p
else
    echo "INFO: Claude is not running"
fi

# Check for child processes
pgrep -i "Claude" | xargs pstree -p 2>/dev/null
```

### 9.2 Sleep Assertion Check

```bash
# macOS: Check if Claude is preventing sleep
pmset -g assertions | grep -i "claude"

# If found: Claude is actively preventing system sleep
# This indicates active autonomous execution
```

### 9.3 LaunchAgents / Startup

```bash
# macOS LaunchAgents
ls -la ~/Library/LaunchAgents/ | grep -i claude
launchctl list | grep -i claude

# Check crontab
crontab -l 2>/dev/null | grep -i claude

# Windows: Check startup
dir "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" | Select-String claude
```

### 9.4 Cookie Analysis

```bash
# Check for browser cookies
cookie_path="$HOME/Library/Application Support/Claude/Cookies"

if [[ -f "$cookie_path" ]]; then
    echo "INFO: Cookies file present"
    ls -la "$cookie_path"
    
    # Check permissions (should be restrictive)
    perms=$(stat -f "%A" "$cookie_path")
    if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        echo "WARN: Cookie file permissions too permissive: $perms"
    fi
fi
```

---

## 10. Dispatch Bridge Audit (PTES 2.5.4)

### 10.1 Dispatch Detection

**Files:** `local_*.json` → `hostLoopMode`, `bridge-state.json`

```bash
# Check hostLoopMode (dispatch acceptance)
jq '.hostLoopMode' local_*.json

# Count sessions accepting dispatch
dispatch_count=$(grep -l '"hostLoopMode"' local_*.json | wc -l)
echo "Sessions accepting dispatch: $dispatch_count"

# Check bridge-state.json for dispatch configuration
if [[ -f "bridge-state.json" ]]; then
    jq '.dispatch' bridge-state.json
fi
```

### 10.2 Dispatch Risk Assessment

| State | Severity | Meaning |
|-------|----------|---------|
| `hostLoopMode: "active"` | HIGH | Accepting mobile→desktop tasks |
| `bridge-state.dispatch: "configured"` | MEDIUM | Bridge configured |
| `bridge-state.dispatch: "on"` | HIGH | Bridge actively running |

---

## 11. Workspace/Multi-Session Audit (PTES 2.5.4)

### 11.1 Workspace Enumeration

```bash
# Find all session directories
find ~/Library/Application\ Support/Claude -type d -name "local-agent-mode-sessions"

# List workspaces (org directories)
for org_dir in ~/Library/Application\ Support/Claude/local-agent-mode-sessions/*/; do
    org_name=$(basename "$org_dir")
    session_count=$(find "$org_dir" -maxdepth 1 -type d | wc -l)
    
    echo "Workspace: $org_name"
    echo "Sessions: $((session_count - 1))"  # Subtract 1 for . or ..
    
    # Check for org indicators
    if [[ -f "$org_dir/remote_cowork_plugins/manifest.json" ]]; then
        echo "  - Has org-deployed plugins"
    fi
done
```

### 11.2 Cross-Session Risk

| Finding | Severity | Rationale |
|---------|----------|-----------|
| Multiple active sessions | MEDIUM | Larger attack surface |
| Org-deployed plugins | REVIEW | Centralized management (good) but supply chain risk |
| Dispatch bridge active | HIGH | Mobile can trigger desktop execution |

---

## 12. Claude Code Settings Audit (PTES 2.5.4)

### 12.1 Settings File Analysis

**File:** `~/.claude/settings.json`

```bash
# Read Claude Code settings
if [[ -f ~/.claude/settings.json ]]; then
    echo "=== Claude Code Settings ==="
    jq '.' ~/.claude/settings.json
    
    # Check for permission grants
    jq '.permissions' ~/.claude/settings.json 2>/dev/null
    
    # Check for MCP server configs
    jq '.mcpServers' ~/.claude/settings.json 2>/dev/null
fi
```

### 12.2 Allowed Tools Check

```bash
# Check allowedTools list
jq '.allowedTools[]' ~/.claude/settings.local.json 2>/dev/null

# Dangerous tools to flag
DANGEROUS_TOOLS="Bash Write Edit MultiEdit"

for tool in $DANGEROUS_TOOLS; do
    if jq -e ".allowedTools | index(\"$tool\")" ~/.claude/settings.local.json > /dev/null 2>&1; then
        echo "INFO: Dangerous tool allowed: $tool"
    fi
done
```

---

## 13. Consolidated Risk Scoring

### 13.1 Risk Calculation

```
Total Risk Score = Σ(Finding Severity × Weight)

Severity Weights:
- CRITICAL: 10 points
- HIGH: 5 points
- MEDIUM: 3 points
- LOW: 1 point
- INFO: 0 points
```

### 13.2 Risk Thresholds

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 0-20 | LOW | Standard monitoring |
| 21-50 | MEDIUM | Review recommended |
| 51-100 | HIGH | Immediate review required |
| 100+ | CRITICAL | Disable autonomous features |

### 13.3 Finding Categories

| Category | Count | Max Score |
|----------|-------|-----------|
| Autonomous Execution | _ | 30 |
| MCP Server Config | _ | 25 |
| Plugin/Hook Risk | _ | 20 |
| Extension Risk | _ | 15 |
| Network/Egress | _ | 10 |

---

## 14. Reporting Template

### 14.1 Executive Summary

```
AI AGENT SECURITY AUDIT
Target: [hostname/user]
Date: [timestamp]
Risk Score: [X]/100 ([LOW/MEDIUM/HIGH/CRITICAL])

Key Findings:
- [X] CRITICAL findings
- [X] HIGH findings  
- [X] MEDIUM findings
- [X] informational findings

Top Concerns:
1. [Most critical finding]
2. [Second concern]
3. [Third concern]
```

### 14.2 Technical Findings

```markdown
## Finding: [FINDING-ID]
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW/INFO]
**Category:** [Autonomous Execution / MCP / Plugin / Extension / Network]

**Description:**
[What was found]

**Evidence:**
[File path, JSON snippet, command output]

**Risk:**
[Why this matters - attack scenario]

**Recommendation:**
[How to remediate]
```

### 14.3 JSON Output (SIEM Integration)

```json
{
  "audit_type": "ai_agent_security",
  "target": {
    "hostname": "...",
    "user": "...",
    "timestamp": "..."
  },
  "risk_score": 0,
  "risk_level": "LOW",
  "findings": [
    {
      "severity": "WARN",
      "category": "autonomous_execution",
      "finding": "keepAwakeEnabled",
      "detail": "Claude preventing system sleep",
      "file": "claude_desktop_config.json"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  }
}
```

---

## 🔧 Integration with Existing Skills

### Trigger Routes

| Detection | Trigger Skill |
|-----------|---------------|
| pfSense detected | `pentest-pfsense` |
| cPanel/WHM detected | `pentest-exploitation` (CVE-2026-41940) |
| AWS credentials found | `pentest-post-exploitation` (WorstAssume) |
| MCP server with network access | `pentest-network-scanning` |
| Plugin hook with shell command | This skill + `pentest-exploitation` |

### MCP Tool Integration

```bash
# Use hexstrike-local for deeper analysis
airecon "analyze MCP server commands for injection vulnerabilities"

# Use pentestswarm-remote for campaign
airecon "start pentest campaign against AI agent endpoint"

# Use cve-mcp for vulnerability mapping
airecon "check CVEs for detected MCP server software"
```

---

## 🤖 AIRecon Integration

### Invocation Commands

```bash
# Full AI agent audit
airecon "AI agent security audit for Claude Desktop"

# MCP server enumeration
airecon "enumerate MCP servers and analyze commands"

# Plugin risk assessment
airecon "assess plugin security risks including hooks"

# Extension audit
airecon "audit Claude extensions for dangerous tools"

# Autonomous execution review
airecon "review scheduled tasks and autonomous execution settings"
```

### Auto-Skill Loading

| Keywords | Skills Loaded |
|----------|---------------|
| `claude audit`, `ai agent` | `ai-agent-audit.md` |
| `MCP server`, `mcpServers` | `ai-agent-audit.md`, `pentest-intelligence-gathering.md` |
| `plugin hook`, `extension` | `ai-agent-audit.md`, `llm-security-testing.md` |
| `scheduled task`, `autonomous` | `ai-agent-audit.md`, `pentest-post-exploitation.md` |

---

## References

- **CLAUDIT-SEC** — Claude Desktop/Code audit tool (macOS + Windows)
- **PTES Section 2.5** — External Footprinting (AI Agent Surface)
- **OWASP Top 10 for LLM** — AI-specific security concerns
- **MITRE ATLAS** — Adversarial Threat Landscape for AI Systems

---

## Ver Também

- `/pentest-intelligence-gathering` — OSINT para AI agents
- `/pentest-post-exploitation` — Persistência via AI agents
- `/llm-security-testing` — Testes de segurança para LLMs
- `/pentest-pfsense` — Se pfSense detectado durante audit
