"""Auditoria de acessibilidade (WCAG 2.2 AA) do dashboard, num Chromium de verdade.

Roda dentro do container `a11y` do compose (`make a11y`). Falha com código 1 se achar qualquer
violação. Cobre o que o axe-core pega e alguns pontos que ele não pega (idioma, títulos, reflow).
O axe não decide tudo ("a revisar"); esses itens são listados, não contados como falha.
"""

import json
import os
import sys
from itertools import pairwise
from pathlib import Path
from urllib.request import Request, urlopen

import axe_playwright_python
from playwright.sync_api import Page, sync_playwright

URL = os.environ.get("DASHBOARD_URL", "http://dashboard:8501")
API = os.environ.get("SECOPS_API_URL", "http://api:8000")
AXE = next(Path(axe_playwright_python.__file__).parent.rglob("axe.min.js")).read_text()
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]
WIDTHS = [1280, 320]  # 320 px = tela de 1280 px com zoom de 400% (WCAG 1.4.10)
TABS = ["Visão geral", "Investigação"]

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)
    print(f"  FALHA: {message}")


def run_axe(page: Page, where: str) -> None:
    page.add_script_tag(content=AXE)
    result = page.evaluate(
        f"axe.run(document, {{runOnly: {{type: 'tag', values: {json.dumps(TAGS)}}}}})"
    )
    for violation in result["violations"]:
        for node in violation["nodes"][:3]:
            fail(f"[{where}] axe {violation['id']} ({violation['impact']}): {node['html'][:90]}")
    for item in result["incomplete"]:
        print(f"  a revisar [{where}]: {item['id']} ({len(item['nodes'])} elementos)")


def check_structure(page: Page, where: str, tab: str) -> None:
    lang = page.evaluate("document.documentElement.lang")
    if lang != "pt-BR":
        fail(f"[{where}] <html lang> é {lang!r}, o conteúdo é em pt-BR (WCAG 3.1.1)")
    levels = page.evaluate(
        "[...document.querySelectorAll('main h1, main h2, main h3, main h4')].map(h => +h.tagName[1])"
    )
    if levels.count(1) != 1:
        fail(f"[{where}] esperava um único h1, achou {levels.count(1)}")
    for before, after in pairwise(levels):
        if after > before + 1:
            fail(f"[{where}] título pula de h{before} para h{after} (WCAG 1.3.1)")
    if page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth"):
        fail(f"[{where}] a página rola na horizontal (WCAG 1.4.10)")
    broken = page.evaluate(
        "[...document.querySelectorAll('figure.grafico')]"
        ".filter(f => { const i = f.querySelector('img'); return !i || !i.naturalWidth || !i.alt; }).length"
    )
    if broken:
        fail(f"[{where}] {broken} gráfico(s) sem imagem carregada ou sem texto alternativo")
    if tab == "Visão geral" and not page.evaluate(
        "document.querySelectorAll('figure.grafico').length"
    ):
        fail(f"[{where}] a linha do tempo não foi renderizada")
    if page.evaluate("[...document.querySelectorAll('iframe')].some(f => f.offsetParent !== null)"):
        fail(f"[{where}] há um iframe visível/focável (parada de Tab sem conteúdo)")


def main() -> int:
    try:  # garante que existem alertas para auditar
        urlopen(Request(f"{API}/run", method="POST"), timeout=120).read()
    except OSError as exc:
        print(f"aviso: não consegui rodar a detecção ({exc}); auditando o que houver")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for width in WIDTHS:
            page = browser.new_page(viewport={"width": width, "height": 900}, locale="pt-BR")
            page.goto(URL)
            page.wait_for_selector("[data-testid=stMetric]", timeout=60000)
            page.wait_for_timeout(2000)
            for tab in TABS:
                where = f"{tab} @{width}px"
                print(f"== {where}")
                page.get_by_role("tab", name=tab).click()
                page.wait_for_timeout(2000)
                check_structure(page, where, tab)
                run_axe(page, where)
            page.close()
        browser.close()

    print(f"\n{'FALHOU' if failures else 'OK'}: {len(failures)} problema(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
