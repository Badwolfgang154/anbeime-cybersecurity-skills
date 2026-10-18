"""IOC Extractor for Cyber Threat Spectrum skill."""

import argparse
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path.cwd()
TOOLS_DIR = REPO_ROOT / "tools"
REFERENCE_DIR = REPO_ROOT / "skills" / "cyber-threat-spectrum" / "cyber-threat-spectrum" / "references"
SKIP_REFERENCE_NAMES = {"report-template"}

IOC_CATEGORIES = {"file", "network", "process", "command", "registry", "log", "behavior"}
VALID_TYPES = {
    "ipv4", "ipv6", "ip", "domain", "url", "sha256", "sha1", "md5",
    "path", "registry", "event_id", "command", "behavior", "evidence",
}
EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "msi", "scr", "hta",
    "pif", "application", "vbe", "wsf", "jse", "wsh", "cpl", "msc",
}
PATTERN_TYPE_MAP = {
    "hash": ("sha256", "file"),
    "ip": ("ip", "network"),
    "ipv4": ("ipv4", "network"),
    "ipv6": ("ipv6", "network"),
    "domain": ("domain", "network"),
    "url": ("url", "network"),
    "event_id": ("event_id", "log"),
}
EVENT_ID_CONTEXT = re.compile(
    r"(?:event logs|security|sysmon|audit|evtx|log id|eID|event ID|Event ID)[^.]{0,30}?(\d{2,5})",
    re.IGNORECASE,
)
TYPE_TO_CATEGORY = {
    "ipv4": "network", "ipv6": "network", "ip": "network",
    "domain": "network", "url": "network",
    "sha256": "file", "sha1": "file", "md5": "file",
    "path": "file", "registry": "registry", "event_id": "log", "command": "command",
}


def normalize_value(value, ioc_type):
    if ioc_type in ("sha256", "sha1", "md5"):
        return value.lower()
    if ioc_type in ("ipv4", "ipv6", "ip"):
        return str(ipaddress.ip_address(value))
    if ioc_type == "domain":
        return value.lower().strip(".")
    return value.strip()


def is_valid_domain(value):
    value = value.strip().lower()
    if not value or "." not in value:
        return False
    if len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.match(r"^[a-z0-9-]+$", label):
            return False
    tld = labels[-1]
    # TLD deve ser alfabético, sem limite de comprimento
    if not tld.isalpha():
        return False
    if tld in EXECUTABLE_EXTENSIONS:
        return False
    return True


def is_valid_path(value):
    """Valida caminho real (Windows absoluto, UNC, Unix absoluto, relativo)."""
    v = value.strip()
    if not v or len(v) > 260:
        return False
    # Windows absoluto com drive letter (C:\\ ou C:/)
    if re.match(r"^[A-Za-z]:", v):
        # Caracteres proibidos (não incluir ':' pois é usado no drive letter)
        if re.search(r'[<>?""?*]', v):
            return False
        # C:\ ou C:/ não são caminhos válidos (sem componentes)
        if len(re.findall(r"[\\/]", v)) == 1:
            return False
        # No Windows, os caminhos usam \\ (barra invertida) como separador
        # Mas também aceitamos / como separador (compatibilidade)
        if not re.match(r"^[A-Za-z]:(?:[\\/][^/:*?\"<>|]*)+$", v):
            return False
        # Verificar que cada componente não contém caracteres proibidos
        parts = re.split(r"[\\/]", v)
        for part in parts[1:]:  # ignorar o drive letter
            if not part or re.search(r'[<>:""?*]', part):
                return False
        return True
    # UNC: \\server\share
    if re.match(r"^\\\\\\[^\\\\/:*?\"<>|\r\n]+\\\\[^\\\\/:*?\"<>|\r\n]+$", v):
        return True
    # Unix absoluto: >= 2 componentes
    if v.startswith("/"):
        parts = [p for p in v.split("/") if p]
        return len(parts) >= 2
    # Relativo com componente de diretório
    if "/" in v:
        parts = [p for p in v.split("/") if p]
        return len(parts) >= 1
    return False


def is_valid_registry(value):
    """Valida chave de registro (ex.: HKLM\\SOFTWARE\\... etc.).

    Espera-se o formato 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'.
    O projeto aceita apenas aliases abreviados (HKLM, HKCU, HKCR, HKU, HKCC);
    nomes completos de 16 caracteres (HKEY_LOCAL_MACHINE etc.) não são aceitos.
    """
    # Validar raiz conhecida (HKLM, HKCU, HKCR, HKU, HKCC) seguida de separador
    m = re.match(r"^(HKLM|HKCU|HKCR|HKU|HKCC)([\\\\/])", value)
    if not m:
        return False
    root = m.group(1)
    if root not in {"HKLM", "HKCU", "HKCR", "HKU", "HKCC"}:
        return False
    # Caracteres proibidos em toda a string
    # (\ é o separador válido, não é proibido; / também é aceito como separador)
    if re.search(r'[:*?"<>|]', value):
        return False
    # Pelo menos um componente após a raiz
    rest = value[4:]
    # Remover o primeiro separador
    if rest[0] in "\\/":
        rest = rest[1:]
    if not rest:
        return False
    # Verificar componentes: nenhum vazio (nenhum \\ duplicado, nenhum final com \\)
    if "\\" in rest and rest.endswith("\\"):
        return False
    components = rest.split("\\")
    if any(c == "" for c in components):
        return False
    return True


def is_event_id_context(text, start, end):
    """Verifica se o número está em contexto de fonte de eventos."""
    before = text[max(0, start - 60):start]
    if re.search(r"T\d+\.?\d*$", before):
        return False
    window = text[max(0, start - 150):min(len(text), end + 150)]
    return bool(EVENT_ID_CONTEXT.search(window))


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hash(ioc_type, value):
    value = value.strip().lower()
    if ioc_type == "sha256":
        return bool(re.match(r"^[a-f0-9]{64}$", value))
    if ioc_type == "sha1":
        return bool(re.match(r"^[a-f0-9]{40}$", value))
    if ioc_type == "md5":
        return bool(re.match(r"^[a-f0-9]{32}$", value))
    return False


def is_valid_url(value):
    value = value.strip()
    if not value:
        return False
    # Apenas esquemas http/https são aceitos
    if not re.match(r"^https?://", value):
        return False
    if "//" not in value:
        return False
    rest = value.split("//", 1)[1]
    host_port = rest.split("/", 1)[0]
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        if not port.isdigit():
            return False
    else:
        host = host_port
    if not re.match(r"^[A-Za-z0-9.-]+$", host):
        return False
    if len(host) > 253:
        return False
    return is_valid_domain(host)


def is_valid_event_id(value):
    """Valida ID de evento: número decimal sem zeros à esquerda, 0-65535."""
    if not value or not isinstance(value, str):
        return False
    # Validar formato: números decimais sem zeros à esquerda
    if not re.match(r"^[0-9]+$", value):
        return False
    # Não aceita zeros à esquerda
    if value != str(int(value)):
        return False
    try:
        num = int(value)
    except (ValueError, TypeError):
        return False
    # Event IDs válidos: 0-65535
    return 0 <= num <= 65535


def register_patterns():
    """Registra padrões de extração (hash, IP, domain, url, path, registry, command, event_id)."""
    pats = {}
    pats["hash"] = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
    pats["ipv4"] = re.compile(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b")
    pats["ipv6"] = re.compile(r"\b([A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\[?([A-Fa-f0-9:]+)\]")
    pats["domain"] = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b")
    pats["url"] = re.compile(r"\b(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/[^\s]*)?\b")
    pats["path"] = re.compile(r"(?<![a-zA-Z]):([\\/][^\s<>:\"|?*]*)")
    pats["registry"] = re.compile(r"HKLM|HKCU|HKCR|HKEY_[A-Z]+")
    pats["command"] = re.compile(r"(\b(?:cmd|powershell|net|reg|sc|winrm|WMIC)\b.+)", re.IGNORECASE)
    pats["event_id"] = re.compile(r"\b(\d{2,5})\b")
    return pats


PATTERNS = register_patterns()


KNOWN_IOCS = {
    "adware": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Unwanted pop-ups", "category": "behavior", "source": "adware", "description": "Pop-ups indesejados"},
            {"type": "behavior", "value": "CPU mining behavior", "category": "behavior", "source": "adware", "description": "Comportamento de mineração de CPU/GPU"},
        ],
        "evidence": [
            {"type": "evidence", "value": "Browser homepage reset without user action", "category": "evidence", "source": "adware", "description": "Homepage do navegador reiniciada sem ação do usuário"},
        ],
    },
    "botnet": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Beaconing patterns — periodic, low-frequency outbound", "category": "behavior", "source": "botnet", "description": "Padrões de beaconing — saída periódica, baixa frequência"},
            {"type": "behavior", "value": "DNS tunneling", "category": "behavior", "source": "botnet", "description": "DNS tunneling"},
            {"type": "behavior", "value": "IRC/P2P-like traffic", "category": "behavior", "source": "botnet", "description": "Tráfego IRC/P2P"},
            {"type": "behavior", "value": "High child-process count; processes spawning multiple shell instances", "category": "behavior", "source": "botnet", "description": "Alta contagem de processos filhos; processos espawning múltiplas instâncias de shell"},
        ],
        "evidence": [],
    },
    "default": {
        "iocs": [],
        "behaviors": [],
        "evidence": [
            {"type": "evidence", "value": "Suspicious child process", "category": "evidence", "source": "default", "description": "Processo filho suspeito"},
            {"type": "evidence", "value": "Unusual outbound connection", "category": "evidence", "source": "default", "description": "Conexão de saída incomum"},
        ],
    },
    "fileless": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "PowerShell/WMI child processes with encoded content", "category": "behavior", "source": "fileless", "description": "Processos filho PowerShell/WMI com conteúdo codificado"},
            {"type": "behavior", "value": "Outbound connections during script execution", "category": "behavior", "source": "fileless", "description": "Conexões de saída durante execução de scripts"},
        ],
        "evidence": [
            {"type": "command", "value": "PowerShell script block logging (4104)", "category": "command", "source": "fileless", "description": "Script block logging do PowerShell habilitado (configuração de monitoramento, não IOC malicioso)"},
            {"type": "event_id", "value": "4104", "category": "log", "source": "fileless", "description": "Observação de log: script block logging habilitado (não é indicador de comprometimento)"},
        ],
    },
    "keylogger": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Low-level keyboard hooks", "category": "behavior", "source": "keylogger", "description": "Hook de teclado de baixo nível"},
            {"type": "behavior", "value": "Keystroke data exfiltrating to external destination", "category": "behavior", "source": "keylogger", "description": "Dados de digitação sendo exfiltrados para um destino externo"},
        ],
        "evidence": [
            {"type": "evidence", "value": "Clipboard content captured", "category": "evidence", "source": "keylogger", "description": "Conteúdo de clipboard capturado"},
        ],
    },
    "ransomware": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "vssadmin delete shadows", "category": "behavior", "source": "ransomware", "description": "Comando para excluir shadows"},
            {"type": "behavior", "value": "wbadmin delete", "category": "behavior", "source": "ransomware", "description": "Comando para excluir backup"},
            {"type": "behavior", "value": "Pre-encryption data exfiltration", "category": "behavior", "source": "ransomware", "description": "Exfiltração de dados antes da criptografia (double extortion)"},
            {"type": "behavior", "value": "Sudden mass renames", "category": "behavior", "source": "ransomware", "description": "Renomeação em massa de arquivos"},
            {"type": "behavior", "value": "New file extensions (.locked, .encrypted)", "category": "behavior", "source": "ransomware", "description": "Padrão de extensões: novos arquivos adquiriram extensões .locked/.encrypted"},
            {"type": "behavior", "value": "Ransom notes (.html or .txt)", "category": "behavior", "source": "ransomware", "description": "Padrão de notas de resgate criadas no host"},
        ],
        "evidence": [],
    },
    "rootkit": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Processes not visible in Task Manager but consuming resources", "category": "behavior", "source": "rootkit", "description": "Processos invisíveis no Gerenciador de Tarefas consumindo recursos"},
            {"type": "behavior", "value": "Connections not visible in netstat", "category": "behavior", "source": "rootkit", "description": "Conexões invisíveis no netstat"},
        ],
        "evidence": [
            {"type": "evidence", "value": "Files inaccessible via File Explorer but exist on disk", "category": "evidence", "source": "rootkit", "description": "Arquivos inacessíveis via Explorer mas presentes no disco"},
        ],
    },
    "spyware": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Unknown processes reading clipboard/documents", "category": "behavior", "source": "spyware", "description": "Processos desconhecidos lendo clipboard e documentos"},
            {"type": "behavior", "value": "Unusual outbound data transfers to single destination", "category": "behavior", "source": "spyware", "description": "Transferências de dados de saída anormais para um destino único"},
            {"type": "behavior", "value": "Browser extensions from unknown publishers", "category": "behavior", "source": "spyware", "description": "Padrão: extensões de navegador de editores desconhecidos"},
        ],
        "evidence": [],
    },
    "trojan-rat": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Unexpected child processes with unknown certs", "category": "behavior", "source": "trojan-rat", "description": "Processos filhos inesperados com certificados desconhecidos"},
            {"type": "behavior", "value": "Persistent low-volume outbound to unknown IPs/domains", "category": "behavior", "source": "trojan-rat", "description": "Conexões persistentes de baixo volume para IPs/domains desconhecidos"},
        ],
        "evidence": [
            {"type": "registry", "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "category": "registry", "source": "trojan-rat", "description": "Chave de persistência legítima do Windows — observação, não IOC malicioso sem valor suspeito associado"},
        ],
    },
    "virus": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Unexpected child process after host exit", "category": "behavior", "source": "virus", "description": "Processo filho inesperado após execução do hospedeiro"},
        ],
        "evidence": [
            {"type": "registry", "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "category": "registry", "source": "virus", "description": "Chave de persistência legítima do Windows — observação, não IOC malicioso sem valor suspeito associado"},
            {"type": "evidence", "value": "PE header anomalies", "category": "evidence", "source": "virus", "description": "Anomalias no cabeçalho PE de arquivos executáveis"},
        ],
    },
    "worm": {
        "iocs": [],
        "behaviors": [
            {"type": "behavior", "value": "Unusual child processes scanning ports", "category": "behavior", "source": "worm", "description": "Processos filhos inusualmente varredores de ports"},
            {"type": "behavior", "value": "High volume of outbound scans to multiple hosts", "category": "behavior", "source": "worm", "description": "Alta volume de varreduras de saída para múltiplos hosts"},
        ],
        "evidence": [
            {"type": "evidence", "value": "Mass file creation in temp/system dirs", "category": "evidence", "source": "worm", "description": "Criação em massa de arquivos em diretórios temporários/sistema"},
            {"type": "registry", "value": "HKLM\\System\\CurrentControlSet\\Services\\smss", "category": "registry", "source": "worm", "description": "Artefato do sistema: serviço smss do Windows (não é IOC malicioso)"},
        ],
    },
}


def validate_ioc_record(record, family):
    """Valida consistência e compatibilidade de um registro de IOC."""
    errors = []
    required = {"type", "value", "category", "source", "description"}
    missing = required - set(record.keys())
    if missing:
        errors.append(f"missing fields: {sorted(missing)}")

    ioc_type = record.get("type")
    if ioc_type not in VALID_TYPES:
        errors.append(f"invalid type {ioc_type!r}")

    if ioc_type in VALID_TYPES and record.get("value") is not None:
        value = record["value"]
        if ioc_type == "domain" and not is_valid_domain(value):
            errors.append(f"domain not valid: {value!r}")
        elif ioc_type in ("ipv4", "ipv6", "ip"):
            if not is_valid_ip(value):
                errors.append(f"ip not valid: {value!r}")
        elif ioc_type in ("sha256", "sha1", "md5"):
            if not is_valid_hash(ioc_type, value):
                errors.append(f"hash not valid for {ioc_type}: {value!r}")
        elif ioc_type == "url":
            if not is_valid_url(value):
                errors.append(f"url not valid: {value!r}")
        elif ioc_type == "event_id":
            if not is_valid_event_id(value):
                errors.append(f"event_id out of range (1-65535): {value!r}")
        elif ioc_type == "registry":
            if not is_valid_registry(value):
                errors.append(f"registry not valid: {value!r}")
        elif ioc_type == "path":
            if not is_valid_path(value):
                errors.append(f"path not valid: {value!r}")

    expected = TYPE_TO_CATEGORY.get(ioc_type)
    if expected and record.get("category") != expected:
        errors.append(
            f"category {record.get('category')!r} != expected {expected!r} for type {ioc_type!r} (family {family})"
        )

    if not record.get("source"):
        errors.append("empty source")
    if not record.get("description"):
        errors.append("empty description")

    return errors


def extract_iocs_from_ref(ref_path):
    """Extrai IOCs, comportamentos e evidências de um arquivo de referência."""
    iocs = []
    behaviors = []
    evidence = []
    try:
        text = ref_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {"iocs": [], "behaviors": [], "evidence": [], "source": ref_path.stem}

    family = ref_path.stem

    # 1) Padrões: hashes, IPs, domínios, caminhos, event_ids
    for pattern_name, pattern in PATTERNS.items():
        if pattern_name in ("path", "registry", "command", "event_id"):
            continue
        ioc_type, ioc_category = PATTERN_TYPE_MAP[pattern_name]
        for match in pattern.finditer(text):
            value = match.group(1).strip()
            if pattern_name == "domain" and not is_valid_domain(value):
                continue
            iocs.append({
                "type": ioc_type,
                "value": value,
                "category": ioc_category,
                "source": family,
                "description": f"MATCH_PATTERN:{pattern_name}",
            })

    # Extrai IDs de eventos como observações/evidências (não IOCs concretos)
    # Exige contexto explícito (event logs, security, sysmon, audit, evtx, log id, eID, event ID)
    for match in PATTERNS["event_id"].finditer(text):
        value = match.group(1).strip()
        if is_event_id_context(text, match.start(), match.end()):
            evidence.append({
                "type": "event_id",
                "value": value,
                "category": "log",
                "source": family,
                "description": f"Evento detectado no log: {value} (observação de detecção, não IOC malicioso)",
            })

    # 2) Caminhos
    for match in PATTERNS["path"].finditer(text):
        path = match.group(1).strip()
        if is_valid_path(path):
            iocs.append({
                "type": "path",
                "value": path,
                "category": "file",
                "source": family,
                "description": "Caminho de arquivo/diretório detectado na descrição",
            })

    # 3) IOCs e comportamentos conhecidos via mapeamento
    fam_map = KNOWN_IOCS.get(family, KNOWN_IOCS["default"])
    iocs.extend(fam_map["iocs"])
    behaviors.extend(fam_map["behaviors"])
    evidence.extend(fam_map["evidence"])

    # 4) Deduplicação: chave = (type, value_normalizado, source)
    # Aplica-se a todos os registros (todas as categorias) para remover duplicatas
    seen = set()
    iocs_list = []
    behaviors_list = []
    evidence_list = []

    # Processar IOCs
    for ioc in iocs:
        key = (ioc["type"], normalize_value(ioc["value"], ioc["type"]), ioc["source"])
        if key not in seen:
            seen.add(key)
            iocs_list.append(ioc)

    # Processar behaviors
    for b in behaviors:
        key = (b.get("type", "behavior"), normalize_value(b.get("value", ""), "behavior"), b.get("source", family))
        if key not in seen:
            seen.add(key)
            behaviors_list.append(b)

    # Processar evidence
    for e in evidence:
        key = (e.get("type", "evidence"), normalize_value(e.get("value", ""), "evidence"), e.get("source", family))
        if key not in seen:
            seen.add(key)
            evidence_list.append(e)

    return {"iocs": iocs_list, "behaviors": behaviors_list, "evidence": evidence_list, "source": family}


def build_ioc_report(family=None):
    """Constrói o relatório com separação de IOCs, comportamentos e evidências."""
    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "ioc_extractor",
        "schema_version": "2.0.0",
        "summary": {
            "families_analyzed": 0,
            "total_iocs": 0,
            "total_behaviors": 0,
            "total_evidence": 0,
            "total_observations": 0,
        },
        "families": [],
    }

    candidates = sorted(REFERENCE_DIR.glob("*.md")) if family is None else [REFERENCE_DIR / f"{family}.md"]
    families = [p for p in candidates if p.stem not in SKIP_REFERENCE_NAMES]

    for ref_path in families:
        result = extract_iocs_from_ref(ref_path)
        for rec in result["iocs"] + result["behaviors"] + result["evidence"]:
            errs = validate_ioc_record(rec, ref_path.stem)
            if errs:
                raise ValueError(f"{ref_path.stem}: {errs[0]}")

        ioc_count = len(result["iocs"])
        behavior_count = len(result["behaviors"])
        evidence_count = len(result["evidence"])
        total_observations = ioc_count + behavior_count + evidence_count
        report["summary"]["families_analyzed"] += 1
        report["summary"]["total_iocs"] += ioc_count
        report["summary"]["total_behaviors"] += behavior_count
        report["summary"]["total_evidence"] += evidence_count
        report["summary"]["total_observations"] += total_observations

        report["families"].append({
            "family": ref_path.stem,
            "reference": str(ref_path.relative_to(REPO_ROOT)),
            "ioc_count": ioc_count,
            "behavior_count": behavior_count,
            "evidence_count": evidence_count,
            "total_observations": total_observations,
            "iocs": result["iocs"],
            "behaviors": result["behaviors"],
            "evidence": result["evidence"],
        })

    return report


def format_splunk(report):
    """Gera string no formato Splunk. Apenas IOCs concretos."""
    lines = []
    for fam in report["families"]:
        for ioc in fam["iocs"]:
            line = "|".join([
                fam["family"],
                ioc["category"],
                ioc["type"],
                ioc["value"],
                ioc["description"],
                fam["reference"],
            ])
            lines.append(line)
    return "\n".join(lines)


def format_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="IOC Extractor for Cyber Threat Spectrum skill")
    parser.add_argument("--family", "-f", help="Extrair apenas uma família (ex: ransomware)")
    parser.add_argument("--format", "-o", choices=["json", "splunk", "all"], default="json", help="Formato de saída")
    parser.add_argument("--all", "-a", action="store_true", help="Extrair todas as famílias (padrão)")
    args = parser.parse_args()

    report = build_ioc_report(args.family if args.family else None)

    if args.format in ("json", "all"):
        print("=== JSON ===")
        print(format_json(report))

    if args.format in ("splunk", "all"):
        print("\n=== SPLUNK (CSV-style) ===")
        print(format_splunk(report))

    out_name = "ioc_report_splunk" if args.format == "splunk" else "ioc_report.json"
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(format_splunk(report) if args.format == "splunk" else format_json(report))
    print(f"\nArquivo salvo: {out_name}")


if __name__ == "__main__":
    main()
