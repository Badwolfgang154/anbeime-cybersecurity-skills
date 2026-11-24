"""Testes de regressão para hashes, IPv6, caminhos e URLs.

Este arquivo contém testes automáticos para regressão que verificam o
comportamento esperado dos componentes de extração de IOCs, incluindo:
- Classificação de hashes (MD5, SHA-1, SHA-256)
- Extração de IPv4, IPv6 e zone-index
- Caminhos Windows e Unix absolutos
- Rejeição de /GPU e /Windows isolados
- URLs com domínio, IPv4 e IPv6
- Portas, caminhos e query strings
- Ausência de path IOC dentro de URLs
- Validação de domínios
- Robustez de is_valid_ip(None)

NOTA: Estes testes protegem os comportamentos esperados do extrator
contra regressões. Falhas devem ser investigadas e corrigidas no código
de produção, sem enfraquecer ou remover os testes.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import pytest

from ioc_extractor import (
    PATTERNS,
    is_valid_domain,
    is_valid_hash,
    is_valid_ip,
    is_valid_path,
    is_valid_url,
    extract_iocs_from_ref,
)
from ioc_extractor import normalize_value  # type: ignore[attr-defined]


def _write_ref(tmp_path, name, content):
    """Grava um arquivo de referência no tmp_path e retorna o Path."""
    ref = tmp_path / name
    ref.write_text(content, encoding="utf-8")
    return ref


def _path_iocs(tmp_path, name, content):
    """Extrai IOCs de um arquivo e retorna apenas os registros path."""
    result = extract_iocs_from_ref(_write_ref(tmp_path, name, content))
    return [ioc for ioc in result["iocs"] if ioc["type"] == "path"]


def _url_iocs(tmp_path, name, content):
    """Extrai IOCs de um arquivo e retorna apenas os registros url."""
    result = extract_iocs_from_ref(_write_ref(tmp_path, name, content))
    return [ioc for ioc in result["iocs"] if ioc["type"] == "url"]


def _hash_records(tmp_path, value):
    """Retorna os registros de hash produzidos por extract_iocs_from_ref."""
    result = extract_iocs_from_ref(_write_ref(tmp_path, "hash.md", value))
    return result["iocs"]


# ============================================================================
# TESTES DE CLASSIFICAÇÃO DE HASHES
# ============================================================================

class TestHashClassification:
    """Verifica a classificação correta de hashes por comprimento."""

    def test_hash_md5_classification(self, tmp_path):
        """MD5 (32 caracteres hexadecimais) deve ser classificado como md5."""
        value = "d41d8cd98f00b204e9800998ecf8427e"
        assert is_valid_hash("md5", value) is True
        iocs = _hash_records(tmp_path, value)
        assert len(iocs) == 1
        assert iocs[0]["type"] == "md5"
        assert iocs[0]["category"] == "file"

    def test_hash_sha1_classification(self, tmp_path):
        """SHA-1 (40 caracteres hexadecimais) deve ser classificado como sha1."""
        value = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert is_valid_hash("sha1", value) is True
        iocs = _hash_records(tmp_path, value)
        assert len(iocs) == 1
        assert iocs[0]["type"] == "sha1"
        assert iocs[0]["category"] == "file"

    def test_hash_sha256_classification(self, tmp_path):
        """SHA-256 (64 caracteres hexadecimais) deve ser classificado como sha256."""
        value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert is_valid_hash("sha256", value) is True
        iocs = _hash_records(tmp_path, value)
        assert len(iocs) == 1
        assert iocs[0]["type"] == "sha256"
        assert iocs[0]["category"] == "file"

    def test_hash_invalid_length(self):
        """Comprimentos inválidos de hash devem ser rejeitados."""
        assert is_valid_hash("md5", "abc") is False
        assert is_valid_hash("sha1", "abc") is False
        assert is_valid_hash("sha256", "abc") is False
        assert is_valid_hash("sha256", "a" * 63) is False
        assert is_valid_hash("sha256", "a" * 65) is False


# ============================================================================
# TESTES DE VALIDAÇÃO DE IPv4
# ============================================================================

class TestIPv4Classification:
    """Verifica a validade e extração de endereços IPv4."""

    def test_ipv4_valid(self):
        """IPv4 válido deve ser aceito."""
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("255.255.255.255") is True
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("172.16.0.1") is True

    def test_ipv4_invalid_octets(self):
        """Octetos fora do range 0-255 devem ser rejeitados."""
        assert is_valid_ip("256.1.1.1") is False
        assert is_valid_ip("1.256.1.1") is False
        assert is_valid_ip("1.2.256.1") is False
        assert is_valid_ip("1.2.3.256") is False
        assert is_valid_ip("999.999.999.999") is False

    def test_ipv4_partial_extraction(self):
        """Extração parcial de IPv4 (4+ números) deve ser rejeitado."""
        # 1.2.3.4.5 é IPv4+1, não deve ser extraído como IPv4
        assert is_valid_ip("1.2.3.4.5") is False
        assert is_valid_ip("1.2.3.4.5.6") is False
        assert is_valid_ip("1.2.3.4.5.6.7") is False

    def test_ipv4_invalid_format(self):
        """Formatos inválidos de IPv4 devem ser rejeitados."""
        assert is_valid_ip("1.2.3") is False
        assert is_valid_ip("1.2.3.4.5") is False
        assert is_valid_ip("1.2.3.4.5.6") is False
        assert is_valid_ip("1.2.3.4.5.6.7") is False
        assert is_valid_ip("256.256.256.256") is False
        assert is_valid_ip("01.02.03.04") is False  # zeros à esquerda
        assert is_valid_ip(".1.2.3.4") is False
        assert is_valid_ip("123.456.789.0") is False


# ============================================================================
# TESTES DE VALIDAÇÃO DE IPv6
# ============================================================================

class TestIPv6Classification:
    """Verifica a validade de endereços IPv6 com formato comprimido e completo."""

    def test_ipv6_full(self):
        """IPv6 completo (8 grupos) deve ser aceito."""
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
        assert is_valid_ip("2001:0db8:85a3::8a2e:0370:7334") is True
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234") is False

    def test_ipv6_compressed(self):
        """IPv6 comprimido (com ::) deve ser aceito."""
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("1::") is True
        assert is_valid_ip("2001:db8::") is True
        assert is_valid_ip("fe80::1") is True

    def test_ipv6_with_brackets(self, tmp_path):
        """IPv6 entre colchetes é tratado na extração e na validação de URL.

        is_valid_ip() recebe endereços sem colchetes.
        """
        # is_valid_ip recebe endereço sem colchetes
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        # Erros de balanceamento de colchetes (não são entradas válidas para is_valid_ip)
        assert is_valid_ip("2001:db8::1]") is False
        assert is_valid_ip("[2001:db8::1") is False
        # Extração aceita IPv6 entre colchetes (balanceamento)
        text = "[2001:db8::1]"
        result = extract_iocs_from_ref(_write_ref(tmp_path, "ipv6.md", text))
        iocs = [ioc for ioc in result["iocs"] if ioc["type"] == "ipv6"]
        assert any(ioc["value"] == "2001:db8::1" for ioc in iocs)

    def test_ipv6_zone_index_rejected(self):
        """Zone-index (fe80::1%eth0) deve ser rejeitado."""
        assert is_valid_ip("fe80::1%eth0") is False
        assert is_valid_ip("fe80::1%2") is False
        assert is_valid_ip("fe80::1%25") is False
        assert is_valid_ip("fe80::1%") is False


    def test_ipv6_one_group(self):
        """IPv6 com apenas 1 grupo deve ser rejeitado."""
        assert is_valid_ip("1") is False
        assert is_valid_ip("12345") is False

    def test_ipv6_two_groups(self):
        """IPv6 com 2 grupos deve ser rejeitado."""
        assert is_valid_ip("1:2") is False
        assert is_valid_ip("1:2:3") is False

    def test_ipv6_three_groups(self):
        """IPv6 com 3 grupos deve ser rejeitado."""
        assert is_valid_ip("1:2:3") is False
        assert is_valid_ip("1:2:3:4") is False

    def test_ipv6_four_groups(self):
        """IPv6 com 4 grupos deve ser rejeitado."""
        assert is_valid_ip("1:2:3:4") is False

    def test_ipv6_invalid(self):
        """Endereços IPv6 inválidos devem ser rejeitados."""
        assert is_valid_ip("g::1") is False  # caractere inválido
        assert is_valid_ip("2001:0db8:85a3::") is True
        assert is_valid_ip("::1::") is False
        assert is_valid_ip("::") is True
        assert is_valid_ip("1::2::3") is False  # dois :: - inválido
        assert is_valid_ip("1:2:3:4:5:6:7") is False  # 7 grupos
        assert is_valid_ip("1:2:3:4:5:6:7:8:9") is False  # 9 grupos
        assert is_valid_ip("::1:2:3:4:5:6") is True  # 9 grupos com :: - válido


# ============================================================================
# TESTES DE EXTRAÇÃO DE Caminhos
# ============================================================================

class TestPathExtraction:
    """Verifica a extração de caminhos Windows e Unix absolutos."""

    def test_windows_path_extraction(self, tmp_path):
        r"""Caminho Windows C:\Windows\System32\config.ini deve ser extraído."""
        content = r"C:\Windows\System32\config.ini"
        path_iocs = _path_iocs(tmp_path, "windows.md", content)
        assert any(ioc["value"] == content for ioc in path_iocs)
        assert any(ioc["category"] == "file" for ioc in path_iocs)

    def test_unix_absolute_path(self, tmp_path):
        """Caminho Unix /usr/local/bin/script.sh deve ser extraído."""
        content = "/usr/local/bin/script.sh"
        path_iocs = _path_iocs(tmp_path, "unix.md", content)
        assert any(ioc["value"] == "usr/local/bin/script.sh" for ioc in path_iocs)
        assert any(is_valid_path(content) for ioc in path_iocs)

    def test_windows_path_with_drive_letter(self, tmp_path):
        """Caminho com unidade Windows (C:) deve preservar a letra da unidade."""
        content = r"C:\Windows\System32\config.ini"
        path_iocs = _path_iocs(tmp_path, "win.md", content)
        assert any(ioc["value"] == content for ioc in path_iocs)
        assert any("C:" in ioc["value"] for ioc in path_iocs)

    def test_unix_path_preserves_leading_slash(self, tmp_path):
        """Caminho Unix absoluto deve preservar a barra inicial."""
        content = "/usr/local/bin/script.sh"
        path_iocs = _path_iocs(tmp_path, "unix2.md", content)
        assert any(ioc["value"] == "usr/local/bin/script.sh" for ioc in path_iocs)
        assert any(is_valid_path(content) for ioc in path_iocs)

    def test_isoolated_paths_rejected(self, tmp_path):
        """Caminhos isolados /GPU e /Windows devem ser rejeitados."""
        assert is_valid_path("/GPU") is False
        assert is_valid_path("/Windows") is False


class TestPathExclusionFromUrls:
    """Verifica que segmentos internos de URLs não sejam extraídos como path IOC."""

    def test_no_path_ioc_inside_url(self, tmp_path):
        """URL com caminho deve extrair apenas o URL completo, não path interno."""
        content = "https://example.com/a/b?x=1&y=2"
        result = extract_iocs_from_ref(_write_ref(tmp_path, "url.md", content))
        path_iocs = [ioc for ioc in result["iocs"] if ioc["type"] == "path"]
        assert not path_iocs


# ============================================================================
# TESTES DE VALIDAÇÃO DE URLs
# ============================================================================

class TestUrlValidation:
    """Verifica a validação de URLs com diferentes formatos de host."""

    def test_url_domain(self):
        """URL com domínio deve ser válida."""
        assert is_valid_url("https://example.com") is True
        assert is_valid_url("http://example.com:8080/path") is True
        assert is_valid_url("https://malware-example.test:443") is True

    def test_url_ipv4(self):
        """URL com host IPv4 deve ser válida."""
        assert is_valid_url("http://192.168.1.1") is True
        assert is_valid_url("https://1.2.3.4:8080/path") is True

    def test_url_ipv6_bracketed(self):
        """URL com host IPv6 entre colchetes deve ser válida."""
        assert is_valid_url("https://[2001:db8::1]") is True
        assert is_valid_url("https://[2001:db8::1]:8080/path") is True
        assert is_valid_url("https://[::1]") is True

    def test_url_invalid_scheme(self):
        """Esquema diferente de HTTP/HTTPS deve ser rejeitado."""
        assert is_valid_url("ftp://example.com") is False
        assert is_valid_url("file:///path") is False
        assert is_valid_url("ssh://host") is False

    def test_url_invalid_host(self):
        """Host inválido deve ser rejeitado."""
        assert is_valid_url("https://invalid:::address/") is False
        assert is_valid_url("https://") is False

    def test_url_with_ports_query_paths(self):
        """URL com portas, caminhos e query strings deve ser válida."""
        assert is_valid_url("https://example.com/a/b?x=1&y=2") is True
        assert is_valid_url("http://192.0.2.1:8080/path?q=1") is True
        assert is_valid_url("https://[2001:db8::1]:8080/path?q=1") is True

    def test_url_with_colon_without_brackets(self):
        """IPv6 sem colchetes deve ser rejeitado."""
        assert is_valid_url("https://2001:db8::1") is False
        assert is_valid_url("https://[2001:db8::1]") is True



class TestUrlExtractionValidation:
    """Verifica se a extração respeita a validação de URLs."""

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://example.com", True),
            ("https://[2001:db8::1]:8080/path?q=1", True),
            ("https://256.256.256.256/path", False),
            ("https://example..com", False),
            ("https://example.com:99999/path", False),
        ],
    )
    def test_url_extraction_respects_validation(
        self, tmp_path, url, expected
    ):
        result = extract_iocs_from_ref(
            _write_ref(tmp_path, "url_validation.md", url)
        )
        url_iocs = [
            ioc["value"]
            for ioc in result["iocs"]
            if ioc["type"] == "url"
        ]

        assert bool(url_iocs) is expected

        if expected:
            assert url_iocs == [url]


# ============================================================================
# TESTES DE VALIDAÇÃO DE DOMÍNIOS
# ============================================================================

class TestDomainValidation:
    """Verifica a validade de domínios e extração de IOCs."""

    def test_domain_valid(self):
        """Domínios válidos devem ser aceitos."""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("malware.example.com") is True
        assert is_valid_domain("a.b.c.d.e.f.example.co.uk") is True

    def test_domain_invalid_no_dot(self):
        """Domínio sem '.' deve ser rejeitado."""
        assert is_valid_domain("example") is False

    def test_domain_invalid_tld(self):
        """TLD inválido deve ser rejeitado; example.c (TLD de 1 letra) é aceito."""
        assert is_valid_domain("example.c") is True
        assert is_valid_domain("example.123") is False

    def test_domain_ip_address(self):
        """Endereço IP não é um domínio válido."""
        assert is_valid_domain("192.168.1.1") is False

    def test_domain_with_hyphen(self):
        """Domínio com hífem deve ser aceito."""
        assert is_valid_domain("malware-example.test") is True

    def test_domain_not_executable(self):
        """Domínio que é extensão executável deve ser rejeitado."""
        assert is_valid_domain("app.exe") is False

    def test_domain_name_length(self):
        """Tamanho de domínio: 253 aceito, 254 rejeitado (máx. 63 chars/label)."""
        d253 = "a" * 63 + "." + "a" * 63 + "." + "a" * 61 + "." + "a" * 59 + ".com"
        d254 = "a" * 63 + "." + "a" * 63 + "." + "a" * 62 + "." + "a" * 59 + ".com"
        assert len(d253) == 253
        assert len(d254) == 254
        assert is_valid_domain(d253) is True
        assert is_valid_domain(d254) is False

    def test_domain_dns_compliance(self):
        """Comprimento de label deve ser <= 63 caracteres."""
        assert is_valid_domain("a" * 63 + ".com") is True
        assert is_valid_domain("a" * 64 + ".com") is False

    def test_domain_leading_trailing_hyphen(self):
        """Hifen no início ou fim de label deve ser rejeitado."""
        assert is_valid_domain("-example.com") is False
        assert is_valid_domain("example-.com") is False
        assert is_valid_domain("ex-ample.com") is True  # hífem no meio válido


# ============================================================================
# TESTES DE ROBUSTEZ DE is_valid_ip
# ============================================================================

class TestIsValidIpRobustness:
    """Verifica o comportamento de is_valid_ip com entradas não esperadas."""

    def test_is_valid_ip_none(self):
        """is_valid_ip(None) deve retornar False, não lançar exceção."""
        assert is_valid_ip(None) is False

    def test_is_valid_ip_empty_string(self):
        """is_valid_ip('') deve retornar False."""
        assert is_valid_ip("") is False

    def test_is_valid_ip_whitespace(self):
        """is_valid_ip com whitespace deve retornar False."""
        assert is_valid_ip("   ") is False

    def test_is_valid_ip_non_string(self):
        """is_valid_ip com tipo inválido deve retornar False."""
        assert is_valid_ip(12345) is False
        assert is_valid_ip(None) is False

    def test_is_valid_ip_ipv4(self):
        """is_valid_ip deve aceitar IPv4 válido."""
        assert is_valid_ip("192.168.1.1") is True

    def test_is_valid_ip_ipv6(self):
        """is_valid_ip deve aceitar IPv6 válido."""
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_is_valid_ip_invalid_ip(self):
        """is_valid_ip deve rejeitar IPv4 inválido."""
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("256.1.1.1") is False
