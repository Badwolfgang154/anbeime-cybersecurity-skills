#!/usr/bin/env python3
"""IOC Extractor — extrai indicadores de comprometimento (IOCs) dos referências
da skill Cyber Threat Spectrum Analysis e os exporta para uso com SIEM/EDR.

Uso:
    python ioc_extractor.py
    python ioc_extractor.py --family ransomware
    python ioc_extractor.py --format splunk --family ransomware
    python ioc_extractor.py --all --format json

Usuários de SIEM:
    • Splunk: importar o JSON via "search predeft X | table *" ou carregar via UI
    • Sigma: converte o JSON para regras Sigma (.yml)
    • Elastic: importar via "ingest _index_manager" ou usar o JSON como payload
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DIR = REPO_ROOT / "skills" / "cyber-threat-spectrum" / "cyber-threat-spectrum" / "references"

# Agrupamentos de IOC usados por SIEM/EDR (baseado na norma MITRE ATT&CK)
IOC_CATEGORIES = {
    "file": {
        "name": "File Artifacts",
        "description": "Arquivos, hashes e caminhos de exclusão ou modificação",
    },
    "registry": {
        "name": "Registry Keys",
        "description": "Chaves de registro associadas a persistência ou configuração",
    },
    "process": {
        "name": "Process Artifacts",
        "description": "Processos, comandos e comportamentos de processo",
    },
    "network": {
        "name": "Network Artifacts",
        "description": "Conectividades, endpoints e padrões de transporte",
    },
    "command": {
        "name": "Command Line",
        "description": "Linhas de comando e scripts executados",
    },
    "log": {
        "name": "Log Artifacts",
        "description": "Eventos e logs de sistema relevantes",
    },
}

# Padrões de match para detectar IOC em texto cru
PATTERNS = {
    "sha256": re.compile(r"\b([a-fA-F0-9]{64})\b"),
    "sha1": re.compile(r"\b([a-fA-F0-9]{40})\b"),
    "md5": re.compile(r"\b([a-fA-F0-9]{32})\b"),
    "ipv4": re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE),
    "path": re.compile(r"\b((?:[A-Za-z]:\\[\\w./\-]+|[\\/][\w./\-]+))\b"),
    "registry": re.compile(r"\b(?:HKLM|HKCR|HKCU|HKU|HKCC)\.(?:SOFTWARE|SYSTEM|WOW64...|CURRENT_USER)[\\/]*(?:[A-Z]:[A-Z0-9._-]+)+", re.IGNORECASE),
    "command": re.compile(r"\b(?:vssadmin delete shadows|wbadmin delete|net stop|copy .*\\Windows\\System32\\.*|powershell.*IEX|Invoke-WebRequest.*IEX|cmd\.exe.*reg )\b", re.IGNORECASE),
    "event_id": re.compile(r"\b([0-9]{4}|[0-9]{3})\b"),
}

# Mapeamento direto de famílias para IOCs que não são computados via regex
KNOWN_IOCS = {
    "virus": [
        {"type": "file", "value": "PE header anomalies", "category": "file", "description": "Anomalias no cabeçalho PE de arquivos executáveis"},
        {"type": "process", "value": "Unexpected child process after host exit", "category": "process", "description": "Processo filho inesperado após execução do hospedeiro"},
        {"type": "registry", "value": "Run keys pointing to infected file paths", "category": "registry", "description": "Chaves Run apontando para arquivos infectados"},
    ],
    "worm": [
        {"type": "process", "value": "Unusual child processes scanning ports", "category": "process", "description": "Processos filhos inusualmente varredores de ports"},
        {"type": "network", "value": "High volume of outbound scans to multiple hosts", "category": "network", "description": "Alta volume de varreduras de saída para múltiplos hosts"},
        {"type": "file", "value": "Mass file creation in temp/system dirs", "category": "file", "description": "Criação em massa de arquivos em diretórios temporários/sistema"},
        {"type": "registry", "value": "Newly created self-replication services", "category": "registry", "description": "Serviços recém-criados para autofagia"},
    ],
    "trojan-rat": [
        {"type": "process", "value": "Unexpected child processes with unknown certs", "category": "process", "description": "Processos filhos inesperados com certificados desconhecidos"},
        {"type": "network", "value": "Persistent low-volume outbound to unknown IPs/domains", "category": "network", "description": "Conexões Persistentes de baixo volume para IPs/domains desconhecidos"},
        {"type": "registry", "value": "Run keys / scheduled tasks loading the trojan", "category": "registry", "description": "Chaves Run ou tarefas agendadas carregando o trojan"},
    ],
    "ransomware": [
        {"type": "file", "value": "New file extensions (.locked, .encrypted)", "category": "file", "description": "Novas extensões em arquivos (.locked, .encrypted, etc.)"},
        {"type": "file", "value": "Sudden mass renames", "category": "file", "description": "Renomeação em massa de arquivos"},
        {"type": "process", "value": "vssadmin delete shadows", "category": "process", "description": "Comando para excluir shadows"},
        {"type": "process", "value": "wbadmin delete", "category": "process", "description": "Comando para excluir backup"},
        {"type": "file", "value": "Ransom notes (.html or .txt)", "category": "file", "description": "Notas de resgate (.html ou .txt)"},
        {"type": "network", "value": "Pre-encryption data exfiltration", "category": "network", "description": "Exfiltração de dados antes da criptografia (double extortion)"},
    ],
    "spyware": [
        {"type": "process", "value": "Unknown processes reading clipboard/documents", "category": "process", "description": "Processos desconhecidos lendo clipboard e documentos"},
        {"type": "network", "value": "Unusual outbound data transfers to single destination", "category": "network", "description": "Transferências de dados de saída anormais para um destino único"},
        {"type": "file", "value": "Browser extensions from unknown publishers", "category": "file", "description": "Extensões de navegador de editores desconhecidos"},
    ],
    "adware": [
        {"type": "browser", "value": "Unwanted pop-ups", "category": "file", "description": "Pop-ups indesejados"},
        {"type": "file", "value": "Browser homepage reset without user action", "category": "file", "description": "Homepage do navegador reiniciada sem ação do usuário"},
        {"type": "process", "value": "CPU mining behavior", "category": "process", "description": "Comportamento de mineração de CPU/GPU"},
    ],
    "rootkit": [
        {"type": "process", "value": "Processes not visible in Task Manager but consuming resources", "category": "process", "description": "Processos invisíveis no Gerenciador de Tarefas consumindo recursos"},
        {"type": "network", "value": "Connections not visible in netstat", "category": "network", "description": "Conexões invisíveis no netstat"},
        {"type": "file", "value": "Files inaccessible via File Explorer but exist on disk", "category": "file", "description": "Arquivos inacessíveis via Explorer mas presentes no disco"},
    ],
    "fileless": [
        {"type": "process", "value": "PowerShell/WMI child processes with encoded content", "category": "process", "description": "Processos filho PowerShell/WMI com conteúdo codificado"},
        {"type": "command", "value": "PowerShell script block logging (4104)", "category": "log", "description": "Script block logging do PowerShell (event 4104)"},
        {"type": "network", "value": "Outbound connections during script execution", "category": "network", "description": "Conexões de saída durante execução de scripts"},
    ],
    "keylogger": [
        {"type": "process", "value": "Low-level keyboard hooks", "category": "process", "description": "Hook de teclado de baixo nível"},
        {"type": "file", "value": "Clipboard content captured", "category": "file", "description": "Conteúdo de clipboard capturado"},
        {"type": "network", "value": "Keystroke data exfiltrating to external destination", "category": "network", "description": "Dados de digitação sendo exfiltrados para um destino externo"},
    ],
    "botnet": [
        {"type": "network", "value": "Beaconing patterns — periodic, low-frequency outbound", "category": "network", "description": "Padrões de beaconing — saída periódica, baixa frequência"},
        {"type": "network", "value": "DNS tunneling", "category": "network", "description": "DNS tunneling"},
        {"type": "network", "value": "IRC/P2P-like traffic", "category": "network", "description": "Tráfego IRC/P2P"},
        {"type": "process", "value": "High child-process count; processes spawning multiple shell instances", "category": "process", "description": "Alta contagem de processos filhos; processos espawning múltiplas instâncias de shell"},
    ],
    "default": [
        {"type": "file", "value": "New or modified executables on host", "category": "file", "description": "Executáveis novos ou modificados no host"},
        {"type": "process", "value": "Suspicious child process", "category": "process", "description": "Processo filho suspeito"},
        {"type": "network", "value": "Unusual outbound connection", "category": "network", "description": "Conexão de saída incomum"},
        {"type": "registry", "value": "Persistence mechanism detected", "category": "registry", "description": "Mecanismo de persistência detectado"},
    ],
}


def extract_iocs_from_ref(ref_path: Path) -> list[dict]:
    """Extrai IOCs de um arquivo de referência, combinando padrões regex e mapeamentos conhecidos."""
    iocs = []
    try:
        text = ref_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return iocs

    family = ref_path.stem  # nome do arquivo (sem .md)

    # 1) Extrair hashes
    for pattern_name, pattern in PATTERNS.items():
        if pattern_name in ("path", "registry", "command"):
            continue  # tratados separadamente
        for match in pattern.finditer(text):
            value = match.group(1)
            iocs.append({
                "type": pattern_name,
                "value": value.strip(),
                "category": pattern_name,
                "source": ref_path.stem,
                "description": f"MATCH_PATTERN:{pattern_name}",
            })

    # 2) Extrair domínios e IPs
    for pattern_name, pattern in [("domain", PATTERNS["domain"]), ("ipv4", PATTERNS["ipv4"])]:
        for match in pattern.finditer(text):
            iocs.append({
                "type": pattern_name,
                "value": match.group(1).strip(),
                "category": pattern_name,
                "source": ref_path.stem,
                "description": f"MATCH_PATTERN:{pattern_name}",
            })

    # 3) Extrair paths
    for match in PATTERNS["path"].finditer(text):
        path = match.group(1).strip()
        if len(path) < 3:
            continue
        iocs.append({
            "type": "path",
            "value": path,
            "category": "file",
            "source": ref_path.stem,
            "description": "Caminho de arquivo/holder detectado na descrição",
        })

    # 4) Extrair IOCs conhecidos via mapeamento
    iocs.extend(KNOWN_IOCS.get(family, KNOWN_IOCS["default"]))

    # 5) Deduplicação
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"], ioc["category"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)

    return unique


def build_ioc_report(family: str | None = None) -> dict:
    """Constrói o relatório de IOCs para todas as famílias ou uma específica."""
    report = {
        "generated_at": "2026-10-16T15:00:00Z",
        "tool": "ioc_extractor",
        "families": [],
    }

    families = sorted(REFERENCE_DIR.glob("*.md")) if family is None else [REFERENCE_DIR / f"{family}.md"]

    for ref_path in families:
        if not ref_path.exists():
            continue
        iocs = extract_iocs_from_ref(ref_path)
        report["families"].append({
            "family": ref_path.stem,
            "reference": str(ref_path.relative_to(REPO_ROOT)),
            "ioc_count": len(iocs),
            "iocs": iocs,
        })

    return report


def format_splunk(report: dict) -> str:
    """Gera uma string no formato Splunk CSV/light."""
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


def format_json(report: dict) -> str:
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

    # Salvar em arquivo
    out_name = "ioc_report_splunk" if args.format == "splunk" else "ioc_report.json"
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(format_splunk(report) if args.format == "splunk" else format_json(report))
    print(f"\nArquivo salvo: {out_name}")


if __name__ == "__main__":
    main()
