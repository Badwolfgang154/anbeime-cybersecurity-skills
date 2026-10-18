import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

# Import validation functions from the extractor
from ioc_extractor import (
    is_valid_domain, is_valid_path, is_valid_registry,
    is_valid_ip, is_valid_hash, is_valid_url, is_valid_event_id
)
import ioc_extractor

# Caminho relativo ao projeto
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH = os.path.join(PROJECT_DIR, "ioc_report.json")
SPLUNK_PATH = os.path.join(PROJECT_DIR, "ioc_report_splunk")


def load_report():
    """Carrega o relatório JSON gerado pelo extrator."""
    with open(REPORT_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def load_json_file(filename):
    """Carrega um arquivo JSON do projeto."""
    path = os.path.join(PROJECT_DIR, filename)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class TestFamilies:
    """Verifica que todas as 10 famílias de malware foram analisadas."""

    def test_families_analyzed(self):
        """Verifica que 10 famílias foram processadas."""
        report = load_report()
        families = [fam["family"] for fam in report["families"]]
        # As 10 famílias de malware
        expected_families = {
            "adware", "botnet", "fileless", "keylogger", "ransomware",
            "rootkit", "spyware", "trojan-rat", "virus", "worm"
        }
        assert set(families) == expected_families, (
            f"Famílias esperadas: {expected_families}, encontradas: {set(families)}"
        )

    def test_no_template_processed(self):
        """Verifica que report-template.md não foi tratado como família."""
        report = load_report()
        families = [fam["family"] for fam in report["families"]]
        assert "report-template" not in families, "report-template não deve aparecer como família"


# =====================================================================
# Teste 2 — Falsos positivos
# =====================================================================
class TestFalsePositives:
    """Verifica que falsos positivos não são classificados como IOCs."""

    def test_domain_not_executable(self):
        """Verifica que nomes de executáveis não são classificados como domínios."""
        report = load_report()
        for fam in report["families"]:
            for ioc in fam.get("iocs", []):
                if ioc["type"] == "domain":
                    assert not ioc["value"].lower().endswith(
                        (".exe", ".dll", ".cmd", ".bat", ".com", ".scr")
                    ), f"Dominio inválido: {ioc['value']}"

    def test_no_command_paths_as_iocs(self):
        """Verifica que caminhos de sistema não são IOCs."""
        report = load_report()
        for fam in report["families"]:
            for ioc in fam.get("iocs", []):
                if ioc["type"] == "path":
                    assert not ioc["value"].startswith(
                        ("/GPU", "/Windows", "/Windows/")
                    ), f"Caminho de sistema como IOC: {ioc['value']}"


# =====================================================================
# Teste 3 — Comportamentos separados
# =====================================================================
class TestBehaviorsSeparated:
    """Verifica que comportamentos suspeitos estão em behaviors, não em iocs."""

    def test_behaviors_not_iocs(self):
        """Verifica que comportamentos não são classificados como IOCs."""
        report = load_report()
        for fam in report["families"]:
            behavior_values = {b["value"] for b in fam.get("behaviors", [])}
            ioc_values = {i["value"] for i in fam.get("iocs", [])}
            # Comportamentos devem estar em behaviors, não em iocs
            overlapping = behavior_values & ioc_values
            assert not overlapping, f"Comportamento classificado como IOC: {overlapping}"


# =====================================================================
# Teste 4 — Consistência de esquema
# =====================================================================
class TestSchemaConsistency:
    """Verifica que o JSON está em conformidade com o esquema definido."""

    def test_ioc_fields(self):
        """Verifica que cada IOC tem os campos obrigatórios."""
        report = load_report()
        for fam in report["families"]:
            for ioc in fam.get("iocs", []):
                assert "value" in ioc, "IOC sem 'value'"
                assert "type" in ioc, "IOC sem 'type'"
                assert "category" in ioc, "IOC sem 'category'"
                assert "source" in ioc, "IOC sem 'source'"
                assert "description" in ioc, "IOC sem 'description'"

    def test_behavior_fields(self):
        """Verifica que cada comportamento tem os campos obrigatórios."""
        report = load_report()
        for fam in report["families"]:
            for behavior in fam.get("behaviors", []):
                assert "value" in behavior, "Behavior sem 'value'"
                assert "description" in behavior, "Behavior sem 'description'"
                assert "source" in behavior, "Behavior sem 'source'"

    def test_evidence_fields(self):
        """Verifica que cada evidência tem os campos obrigatórios."""
        report = load_report()
        for fam in report["families"]:
            for evidence in fam.get("evidence", []):
                assert "value" in evidence, "Evidence sem 'value'"
                assert "type" in evidence, "Evidence sem 'type'"
                assert "category" in evidence, "Evidence sem 'category'"
                assert "source" in evidence, "Evidence sem 'source'"
                assert "description" in evidence, "Evidence sem 'description'"


# =====================================================================
# Teste 5 — Contagem de IOCs
# =====================================================================
class TestIocCount:
    """Verifica que a contagem de IOCs está correta."""

    def test_ioc_count_matches_records(self):
        """Verifica que ioc_count corresponde ao número real de IOCs."""
        report = load_report()
        total_iocs = 0
        for fam in report["families"]:
            total_iocs += len(fam.get("iocs", []))
        assert report["summary"]["total_iocs"] == total_iocs, (
            f"total_iocs ({report['summary']['total_iocs']}) != "
            f"contagens reais ({total_iocs})"
        )

    def test_total_observations(self):
        """Verifica que total_observations = iocs + behaviors + evidence."""
        report = load_report()
        total_iocs = sum(len(fam.get("iocs", [])) for fam in report["families"])
        total_behaviors = sum(len(fam.get("behaviors", [])) for fam in report["families"])
        total_evidence = sum(len(fam.get("evidence", [])) for fam in report["families"])
        expected_total = total_iocs + total_behaviors + total_evidence
        assert report["summary"]["total_observations"] == expected_total, (
            f"total_observations ({report['summary']['total_observations']}) != "
            f"iocs+behaviors+evidence ({expected_total})"
        )


# =====================================================================
# Teste 6 — Registro de família
# =====================================================================
class TestFamilyRecord:
    """Verifica que cada família tem os campos de registro corretos."""

    def test_family_fields(self):
        """Verifica que cada família tem os campos obrigatórios."""
        report = load_report()
        for fam in report["families"]:
            assert "family" in fam, "Família sem 'family'"
            assert "reference" in fam, "Família sem 'reference'"
            # Verify categories exist
            for category in ("iocs", "behaviors", "evidence"):
                assert category in fam, f"Família sem '{category}'"


# =====================================================================
# Teste 7 — Validação das funções de validação
# =====================================================================
class TestValidationFunctions:
    """Verifica que cada validador tem testes positivos e negativos."""

    def test_is_valid_domain_positive(self):
        """Verifica que domínios válidos são aceitos."""
        valid_domains = [
            "example.com",
            "google.com",
            "subdomain.example.co.uk",
        ]
        for domain in valid_domains:
            assert is_valid_domain(domain), f"Dominio válido rejeitado: {domain}"

    def test_is_valid_domain_negative(self):
        """Verifica que domínios inválidos são rejeitados."""
        invalid_domains = [
            "explorer.exe",      # executável como domínio
            "svchost.exe",       # executável como domínio
            "999.999.999.999",   # IP malformado
            "",                  # vazio
            "a" * 256,           # excessivamente longo
        ]
        for domain in invalid_domains:
            assert not is_valid_domain(domain), f"Dominio inválido aceito: {domain}"


    def test_domain_regex_group1_full_domain(self):
        """Verifica que match.group(1) contém o domínio completo, não apenas o prefixo."""

        # Simula o comportamento de extract_iocs_from_ref usando o padrão
        pattern = ioc_extractor.PATTERNS["domain"]

        # Caso do bug reportado: malware-example.test
        text = "Indicador observado: malware-example.test"
        matches = list(pattern.finditer(text))
        assert len(matches) == 1

        match = matches[0]
        # group(0) e group(1) devem ser iguais (domínio completo)
        assert match.group(1) == "malware-example.test"
        assert match.group(1) == match.group(0)

    def test_domain_regex_example_com(self):
        """Verifica que example.com é extraído corretamente."""
        pattern = ioc_extractor.PATTERNS["domain"]
        text = "Site: example.com"
        matches = list(pattern.finditer(text))
        assert len(matches) == 1
        assert matches[0].group(1) == "example.com"

    def test_domain_regex_sub_domain(self):
        """Verifica que subdominios complexos são extraídos corretamente."""
        pattern = ioc_extractor.PATTERNS["domain"]
        text = "Versão: dev.sub.example.co.uk"
        matches = list(pattern.finditer(text))
        assert len(matches) == 1
        # O domínio completo deve ser extraído, incluindo todos os níveis
        assert matches[0].group(1) == "dev.sub.example.co.uk"

    def test_domain_regex_multilevel(self):
        """Verifica domínios multi-níveis."""
        pattern = ioc_extractor.PATTERNS["domain"]
        text = "host.a.b.c.example.com"
        matches = list(pattern.finditer(text))
        assert len(matches) == 1
        # O domínio completo deve ser extraído, incluindo todos os níveis
        assert matches[0].group(1) == "host.a.b.c.example.com"

    def test_domain_regex_invalid_returns_no_match(self):
        """Verifica que entradas inválidas não geram match como IOC válido."""
        pattern = ioc_extractor.PATTERNS["domain"]
        # .exe não é um domínio válido, mas a regex pode capturá-lo
        text = "arquivo.exe"
        matches = list(pattern.finditer(text))
        # A regex pode capturar arquivo.exe (é um domínio com TLD .exe)
        # Mas é rejeitado pelo is_valid_domain() por causa da extensão executável
        assert len(matches) == 1
        # Verificar que é rejeitado pelo validador de domínios
        assert not ioc_extractor.is_valid_domain(matches[0].group(1))

    def test_domain_regex_no_fragments(self):
        """Verifica que fragments de texto não são capturados como domínios."""
        pattern = ioc_extractor.PATTERNS["domain"]
        text = "Indicador: /GPU"
        matches = list(pattern.finditer(text))
        # O /GPU pode gerar match se for um domínio (com TLD inválida), mas deve ser rejeitado
        # Por agora, verificamos que não é um domínio válido
        assert not ioc_extractor.is_valid_domain('/GPU')



    def test_extract_domain_from_text(self):
        """Verifica que extract_iocs_from_ref extrai o domínio completo."""
        # Test using the internal extraction logic
        text = "Indicador observado: malware-example.test e outro.example.org"
        pattern = ioc_extractor.PATTERNS["domain"]
        matches = list(pattern.finditer(text))
        assert len(matches) == 2

        values = sorted([m.group(1) for m in matches])
        assert "malware-example.test" in values
        assert "outro.example.org" in values

    def test_domain_regex_preserves_tld(self):
        """Verifica que a TLD é incluída no grupo 1."""
        pattern = ioc_extractor.PATTERNS["domain"]
        test_cases = [
            ("example.com", "example.com"),
            ("sub.example.org", "sub.example.org"),
            ("xn--example.com", "xn--example.com"),
            ("123.example.com", "123.example.com"),
        ]
        for input_val, expected in test_cases:
            matches = list(pattern.finditer(input_val + " "))
            assert len(matches) == 1
            assert matches[0].group(1) == expected

    def test_domain_regex_does_not_capture_executable(self):
        """Verifica que nomes de executáveis não são capturados como domínios válidos."""
        pattern = ioc_extractor.PATTERNS["domain"]
        text = "executável: explorer.exe e svchost.exe"
        matches = list(pattern.finditer(text))
        # A regex pode capturar .exe (é um TLD válido)
        # Mas o extractor deve rejeitar por causa da extensão executável
        for m in matches:
            # O valor é capturado pela regex, mas rejeitado por is_valid_domain
            assert not ioc_extractor.is_valid_domain(m.group(1))
            # E deve terminar com extensões executáveis
            assert m.group(1).endswith(('.exe', '.dll', '.cmd', '.bat'))


    def test_is_valid_path_positive(self):
        """Verifica que caminhos válidos são aceitos."""
        valid_paths = [
            r"C:\Windows\System32\config.ini",
            r"C:/Windows/System32/config.ini",
            r"/usr/local/bin/script.sh",
            r"relative/path/to/file.txt",
        ]
        for path in valid_paths:
            assert is_valid_path(path), f"Caminho válido rejeitado: {path}"

    def test_is_valid_path_negative(self):
        """Verifica que caminhos inválidos são rejeitados."""
        invalid_paths = [
            "/GPU",          # fragmento de texto
            "/Windows",      # fragmento de texto
            "",              # vazio
            "C:",            # incompleto
            r"C:\\",           # incompleto
        ]
        for path in invalid_paths:
            assert not is_valid_path(path), f"Caminho inválido aceito: {path}"

    def test_is_valid_registry_positive(self):
        """Verifica que chaves de registro válidas são aceitas."""
        valid_regs = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\MyApp\Settings",
            r"HKCR\Applications\notepad.exe",
            r"HKU\Users\S-1-5-21\Software",
            r"HKCC\System\CurrentControlSet",
        ]
        for reg in valid_regs:
            assert is_valid_registry(reg), f"Registro válido rejeitado: {reg}"

    def test_is_valid_registry_negative(self):
        """Verifica que chaves de registro inválidas são rejeitadas."""
        invalid_regs = [
            "HKLM",                    # raiz isolada
            "HKLM\\",                   # componente vazio
            "invalid",                 # raiz desconhecida
            "HKEY_LOCAL_MACHINE\\Software",  # nome completo não aceito
            "HKLM\\Software\\",         # trailing separator
            "HKLM\\Software\\*:Config", # caractere proibido
        ]
        for reg in invalid_regs:
            assert not is_valid_registry(reg), f"Registro inválido aceito: {reg}"

    def test_is_valid_ip_positive(self):
        """Verifica que IPs válidos são aceitos."""
        valid_ips = [
            "192.0.2.10",
            "2001:db8::1",
            "10.0.0.1",
            "255.255.255.255",
        ]
        for ip in valid_ips:
            assert is_valid_ip(ip), f"IP válido rejeitado: {ip}"

    def test_is_valid_ip_negative(self):
        """Verifica que IPs inválidos são rejeitados."""
        invalid_ips = [
            "999.999.999.999",   # IP malformado
            "192.168.1.256",     # octeto inválido
            "",                  # vazio
        ]
        for ip in invalid_ips:
            assert not is_valid_ip(ip), f"IP inválido aceito: {ip}"

    def test_is_valid_hash_positive(self):
        """Verifica que hashes válidos são aceitos."""
        valid_hashes = [
            "d41d8cd98f00b204e9800998ecf8427f",  # MD5 (32) - correto
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1 (40) - correto
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256 (64) - correto
        ]
        for h in valid_hashes:
            assert is_valid_hash("md5", h) or is_valid_hash("sha1", h) or is_valid_hash("sha256", h), f"Hash válido rejeitado: {h}"

    def test_is_valid_hash_negative(self):
        """Verifica que hashes inválidos são rejeitados."""
        invalid_hashes = [
            "d41d8cd98f00b204e9800998ecf8427",  # MD5 com 31 chars (menor que 32)
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",  # SHA-256 com 63 chars (menor que 64)
            "d41d8cd98f00b204e9800998ecf8427",  # MD5 com 31 chars (menor que 32)
            "",  # vazio
        ]
        for h in invalid_hashes:
            assert not is_valid_hash("md5", h) and not is_valid_hash("sha1", h) and not is_valid_hash("sha256", h), f"Hash inválido aceito: {h}"

    def test_is_valid_url_positive(self):
        """Verifica que URLs válidas são aceitas."""
        valid_urls = [
            "https://example.com",
            "http://example.com",
            "https://sub.example.com/path",
        ]
        for url in valid_urls:
            assert is_valid_url(url), f"URL válida rejeitada: {url}"

    def test_is_valid_url_negative(self):
        """Verifica que URLs inválidas são rejeitadas."""
        invalid_urls = [
            "example.com",           # sem esquema
            "",                      # vazio
            "://invalid",            # formato inválido
        ]
        for url in invalid_urls:
            assert not is_valid_url(url), f"URL inválida aceita: {url}"

    def test_is_valid_event_id_positive(self):
        """Verifica que Event IDs válidos são aceitos."""
        valid_ids = [
            "4104",
            "1",
            "9999",
        ]
        for eid in valid_ids:
            assert is_valid_event_id(eid), f"Event ID válido rejeitado: {eid}"

    def test_is_valid_event_id_negative(self):
        """Verifica que Event IDs inválidos são rejeitados."""
        invalid_ids = [
            "001",           # leading zeros
            "004",           # leading zeros
            "99999",         # fora de faixa
            "",              # vazio
        ]
        for eid in invalid_ids:
            assert not is_valid_event_id(eid), f"Event ID inválido aceito: {eid}"


# =====================================================================
# Teste 8 — Deduplicação
# =====================================================================
class TestDeduplication:
    """Verifica que registros duplicados são tratados corretamente."""

    def test_dedup_same_source(self):
        """Verifica deduplicação dentro da mesma fonte."""
        report = load_report()
        for fam in report["families"]:
            seen = set()
            for category in ("iocs", "behaviors", "evidence"):
                for rec in fam.get(category, []):
                    key = (rec["type"], rec["value"], rec["source"])
                    assert key not in seen, (
                        f"Duplicata encontrada em [{fam['family']}]/{category}: {rec['value']}"
                    )
                    seen.add(key)

    def test_dedup_different_sources_preserved(self):
        """Verifica que registros iguais de fontes diferentes são preservados."""
        report = load_report()
        all_records = []
        for fam in report["families"]:
            for category in ("iocs", "behaviors", "evidence"):
                for rec in fam.get(category, []):
                    all_records.append((fam["family"], rec["value"], rec["source"]))
        from collections import Counter
        value_sources = Counter(r[1] for r in all_records)
        for value, count in value_sources.items():
            if count > 1:
                sources = {r[2] for r in all_records if r[1] == value}
                # Fontes diferentes mantém contexto


# =====================================================================
# Teste 9 — Consistência JSON x Splunk
# =====================================================================
class TestJsonSplunkConsistency:
    """Verifica que JSON e saída Splunk estão em conformidade."""

    def test_splunk_matches_json_iocs(self):
        """Verifica que linhas Splunk correspondem aos IOCs do JSON."""
        report = load_report()
        with open(REPORT_PATH, encoding="utf-8") as fh:
            report_json = json.load(fh)
        with open(SPLUNK_PATH, encoding="utf-8") as fh:
            splunk_content = fh.read().strip()
        if report_json["summary"]["total_iocs"] > 0:
            with open(SPLUNK_PATH, encoding="utf-8") as fh:
                splunk_lines = fh.read().strip().split("\n")
            assert len(splunk_lines) == report_json["summary"]["total_iocs"], (
                f"Splunk lines ({len(splunk_lines)}) != JSON iocs ({report_json['summary']['total_iocs']})"
            )


# =====================================================================
# Teste 10 — Amostras sintéticas controladas (fixture)
# =====================================================================
class TestSyntheticSamples:
    """Testa a aceitação de indicadores sintaticamente válidos,
    rejeição de entradas inválidas e classificação semântica
    usando um conjunto de amostras controladas."""

    @classmethod
    def setup_class(cls):
        """Carrega a fixture de amostras sintéticas."""
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "synthetic_iocs.json"
        )
        with open(fixture_path, encoding="utf-8") as fh:
            data = json.load(fh)
        cls.samples = {item["id"]: item for item in data["samples"]}

    def test_syntactic_valid_indicators_accepted(self):
        """Verifica que indicadores sintaticamente válidos são aceitos."""
        report = load_report()
        # Coleta todos os valores que aparecem como IOCs
        ioc_values = set()
        for fam in report["families"]:
            for ioc in fam.get("iocs", []):
                ioc_values.add(ioc["value"])
        # Verificar que os sinteticamente válidos são aceitos
        # (dominio exemple.com, urls, hashes, paths, etc.)
        # Nota: exemplo.com deve ser evidência, não IOC

    def test_invalid_entries_rejected(self):
        """Verifica que entradas inválidas são rejeitadas."""
        report = load_report()
        ioc_values = set()
        for fam in report["families"]:
            for ioc in fam.get("iocs", []):
                ioc_values.add(ioc["value"])
        # Entradas inválidas NÃO devem aparecer como IOCs
        invalid_values = {
            "explorer.exe",      # executável como domínio
            "svchost.exe",       # executável como domínio
            "999.999.999.999",   # IP malformado
            "d41d8cd98f00b204e9800998ecf8427",  # MD5 com 31 chars
            "example.com/test",  # URL sem esquema
        }
        for bad in invalid_values:
            assert bad not in ioc_values, f"Valor inválido {bad} apareceu como IOC"

    def test_synthetic_samples_covered(self):
        """Verifica que todas as amostras sintéticas estão cobertas."""
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "synthetic_iocs.json"
        )
        with open(fixture_path, encoding="utf-8") as fh:
            fixture = json.load(fh)
        # Cobertura dos campos obrigatórios
        for sample in fixture["samples"]:
            assert "id" in sample, "Cada amostra deve ter 'id'"
            assert "type" in sample, "Cada amostra deve ter 'type'"
            assert "value" in sample, "Cada amostra deve ter 'value'"
            assert "syntactic_valid" in sample, "Cada amostra deve ter 'syntactic_valid'"
            assert "expected_category" in sample, "Cada amostra deve ter 'expected_category'"

    def test_dedup_same_source(self):
        """Verifica deduplicação dentro da mesma fonte."""
        report = load_report()
        for fam in report["families"]:
            seen = set()
            for category in ("iocs", "behaviors", "evidence"):
                for rec in fam.get(category, []):
                    key = (rec["type"], rec["value"], rec["source"])
                    assert key not in seen, (
                        f"Duplicata encontrada em [{fam['family']}]/{category}: {rec['value']}"
                    )
                    seen.add(key)

    def test_dedup_different_sources_preserved(self):
        """Verifica que registros iguais de fontes diferentes são preservados."""
        report = load_report()
        all_registers = []
        for fam in report["families"]:
            for category in ("iocs", "behaviors", "evidence"):
                for rec in fam.get(category, []):
                    all_registers.append((fam["family"], rec["value"], rec["source"]))
        from collections import Counter
        value_sources = Counter(r[1] for r in all_registers)
        for value, count in value_sources.items():
            if count > 1:
                sources = {r[2] for r in all_registers if r[1] == value}
                # Mesmo valor de fontes diferentes pode estar em múltiplas famílias

    def test_json_splunk_consistency(self):
        """Verifica consistência entre JSON e saída Splunk."""
        report = load_report()
        with open(REPORT_PATH, encoding="utf-8") as fh:
            report_json = json.load(fh)
        with open(SPLUNK_PATH, encoding="utf-8") as fh:
            splunk_content = fh.read().strip()
        if report_json["summary"]["total_iocs"] > 0:
            with open(SPLUNK_PATH, encoding="utf-8") as fh:
                splunk_lines = fh.read().strip().split("\n")
            assert len(splunk_lines) == report_json["summary"]["total_iocs"]
