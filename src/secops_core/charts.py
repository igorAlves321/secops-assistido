"""Gráficos do painel como HTML/SVG acessível.

Os gráficos do Streamlit (Vega) trazem texto de eixo com pouco contraste, centenas de nós soltos
para o leitor de tela e uma barra de ferramentas sem foco visível. Aqui o markup é nosso: o dado
sempre está em texto (tabela) e o desenho é um complemento visual.

O `st.html` do Streamlit remove tags <svg>, por isso o gráfico de linha vai como <img>.
"""

import base64
from datetime import datetime
from html import escape

INK = "#111111"  # texto: 18,9:1 sobre branco
MUTED = "#4d4d4d"  # eixos: 8,5:1 sobre branco
BLUE = "#0b4f9e"  # barras e linha: 8,0:1 sobre branco
GRID = "#d0d0d0"

CSS = f"""
<style>
.barras {{ width: 100%; border-collapse: collapse; color: {INK}; }}
.barras caption {{ text-align: left; color: {MUTED}; padding-bottom: .25rem; }}
.barras th, .barras td {{ padding: .35rem .5rem; text-align: left; border-bottom: 1px solid {GRID}; }}
.barras td.valor {{ text-align: right; width: 3.5rem; }}
.barras td.desenho {{ width: 45%; }}
.barra {{ height: .9rem; background: {BLUE}; min-width: 2px; }}
.grafico {{ margin: 0; color: {INK}; }}
.grafico img {{ width: 100%; height: auto; display: block; }}
.grafico figcaption {{ color: {MUTED}; font-size: .875rem; }}
main:focus-visible {{ outline: 3px solid {BLUE}; outline-offset: -3px; }}
.rolagem {{ overflow-x: auto; }}
.rolagem:focus-visible {{ outline: 3px solid {BLUE}; outline-offset: 2px; }}
.dados {{ width: 100%; border-collapse: collapse; color: {INK}; }}
.dados caption {{ text-align: left; color: {MUTED}; padding-bottom: .25rem; }}
.dados th, .dados td {{ padding: .4rem .6rem; text-align: left; vertical-align: top; border-bottom: 1px solid {GRID}; }}
.dados thead th {{ border-bottom: 2px solid {INK}; white-space: nowrap; }}
@media (forced-colors: active) {{ .barra {{ background: CanvasText; }} }}
</style>
"""


def bars_html(caption: str, label: str, rows: dict[str, int], value_label: str = "Alertas") -> str:
    """Tabela com uma barra ao lado de cada valor. A barra é só reforço visual (aria-hidden)."""
    top = max(rows.values(), default=0) or 1
    body = "".join(
        f'<tr><th scope="row">{escape(str(name))}</th><td class="valor">{value}</td>'
        f'<td class="desenho" aria-hidden="true"><div class="barra" style="width:{100 * value / top:.0f}%"></div></td></tr>'
        for name, value in rows.items()
    )
    return (
        f'<table class="barras"><caption>{escape(caption)}</caption><thead><tr>'
        f'<th scope="col">{escape(label)}</th><th scope="col">{escape(value_label)}</th>'
        f'<td aria-hidden="true"></td></tr></thead><tbody>{body}</tbody></table>'
    )


def _nice_top(value: int) -> int:
    """Topo do eixo Y: próximo múltiplo de 5 (mínimo 5), para ticks redondos."""
    return max(5, -(-value // 5) * 5)


def timeseries_svg(points: list[tuple[datetime, int]]) -> str:
    """Linha do tempo como SVG autônomo (vira o conteúdo de um <img>)."""
    width, height, left, bottom, top_pad = 800, 260, 48, 28, 10
    plot_w, plot_h = width - left - 8, height - bottom - top_pad
    top = _nice_top(max((v for _, v in points), default=0))
    step = plot_w / max(len(points) - 1, 1)

    def y(value: float) -> float:
        return top_pad + plot_h * (1 - value / top)

    grid = "".join(
        f'<line x1="{left}" x2="{width - 8}" y1="{y(t):.1f}" y2="{y(t):.1f}" stroke="{GRID}"/>'
        f'<text x="{left - 6}" y="{y(t) + 4:.1f}" text-anchor="end" fill="{MUTED}" font-size="12">{t}</text>'
        for t in (0, top // 2, top)
    )
    days = "".join(
        f'<text x="{left + i * step:.1f}" y="{height - 8}" fill="{MUTED}" font-size="12">{when:%d/%m}</text>'
        for i, (when, _) in enumerate(points)
        if i == 0 or when.day != points[i - 1][0].day
    )
    line = " ".join(f"{left + i * step:.1f},{y(v):.1f}" for i, (_, v) in enumerate(points))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" font-family="sans-serif">'
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>{grid}{days}'
        f'<polyline points="{line}" fill="none" stroke="{BLUE}" stroke-width="2"/></svg>'
    )


def timeseries_html(points: list[tuple[datetime, int]], description: str, y_label: str) -> str:
    """Figura com a linha do tempo. O `st.html` do Streamlit remove tags <svg>, então o desenho
    vai como <img> (data URI) e o `alt` leva a descrição em texto: o leitor de tela lê uma frase
    em vez de percorrer centenas de pontos, e os valores exatos ficam na tabela por dia."""
    data = base64.b64encode(timeseries_svg(points).encode()).decode()
    return (
        f'<figure class="grafico"><img alt="{escape(description, quote=True)}" '
        f'src="data:image/svg+xml;base64,{data}">'
        f"<figcaption>{escape(y_label)} por hora, em UTC.</figcaption></figure>"
    )


def table_html(caption: str, headers: list[str], rows: list[list], uid: str) -> str:
    """Tabela de dados. A primeira coluna é o cabeçalho da linha. Em telas estreitas ela rola na
    horizontal (permitido para tabelas, WCAG 1.4.10), e a região é focável por teclado, com nome,
    para quem não usa mouse conseguir rolar (WCAG 2.1.1)."""
    head = "".join(f'<th scope="col">{escape(str(h))}</th>' for h in headers)
    body = "".join(
        f'<tr><th scope="row">{escape(str(row[0]))}</th>'
        + "".join(f"<td>{escape(str(cell))}</td>" for cell in row[1:])
        + "</tr>"
        for row in rows
    )
    return (
        f'<div class="rolagem" role="region" tabindex="0" aria-labelledby="{uid}-c">'
        f'<table class="dados"><caption id="{uid}-c">{escape(caption)}</caption>'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )
