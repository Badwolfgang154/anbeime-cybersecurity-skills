"""Pytest root fixture: gera os relatórios do extrator em um diretório temporário.

Os relatórios padrão do `ioc_extractor` (ioc_report.json / ioc_report_splunk)
são escritos na raiz do projeto e ignorados pelo .gitignore, então um clone
limpo não tem esses arquivos. Este fixture roda o extrator apontando
--output-dir para um tmp_path_factory e deixa os testes ler esses paths,
em vez de dependerem dos arquivos de raiz.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_DIR / "tools"


@pytest.fixture(scope="session")
def ioc_report(tmp_path_factory):
    """Roda o extrator e retorna os caminhos dos relatórios gerados no tmp.

    O extrator já contém --output-dir (opcional, padrão não muda). Rodamos
    --format all para exercitar a gravação dos dois arquivos (JSON + Splunk).
    """
    tmpdir = tmp_path_factory.mktemp("ioc-reports")
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "ioc_extractor.py"),
        "--output-dir",
        str(tmpdir),
        "--format",
        "all",
    ]
    subprocess.run(cmd, check=True, cwd=PROJECT_DIR, capture_output=True, text=True)

    report_path = tmpdir / "ioc_report.json"
    splunk_path = tmpdir / "ioc_report_splunk"
    if not report_path.is_file():
        raise RuntimeError(f"Extrator não gerou {report_path}: {tmpdir}")
    if not splunk_path.is_file():
        raise RuntimeError(f"Extrator não gerou {splunk_path}: {tmpdir}")

    yield {
        "project_dir": PROJECT_DIR,
        "report_path": report_path,
        "splunk_path": splunk_path,
        "tmpdir": tmpdir,
    }
