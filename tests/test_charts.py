import base64
import re
from datetime import UTC, datetime, timedelta

import pytest

from secops_core import charts

T0 = datetime(2026, 1, 5, 22, 0, tzinfo=UTC)


def luminance(hex_color: str) -> float:
    def channel(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(int(hex_color[i : i + 2], 16)) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_on_white(hex_color: str) -> float:
    return 1.05 / (luminance(hex_color) + 0.05)


@pytest.mark.parametrize("color", [charts.INK, charts.MUTED, charts.BLUE])
def test_palette_meets_wcag_aa_on_white(color):
    assert contrast_on_white(color) >= 4.5  # texto: 1.4.3; gráficos e foco: 1.4.11 exige 3


def test_bars_are_a_real_table_with_headers():
    html = charts.bars_html("Alertas por gravidade", "Gravidade", {"alta": 4, "média": 10})

    assert "<caption>Alertas por gravidade</caption>" in html
    assert html.count('<th scope="col">') == 2
    assert html.count('<th scope="row">') == 2
    assert ">alta</th>" in html and 'class="valor">4<' in html


def test_bars_are_proportional_and_hidden_from_screen_readers():
    html = charts.bars_html("c", "x", {"a": 5, "b": 10})

    assert re.findall(r"width:(\d+)%", html) == ["50", "100"]
    assert html.count('aria-hidden="true"') == 3  # 2 barras + a célula vazia do cabeçalho


def test_bars_escape_html_and_accept_empty():
    assert "&lt;b&gt;" in charts.bars_html("c", "x", {"<b>": 1})
    assert "<tbody></tbody>" in charts.bars_html("c", "x", {})


def hours(values):
    return [(T0 + timedelta(hours=i), v) for i, v in enumerate(values)]


def test_timeseries_svg_has_one_line_and_no_per_point_nodes():
    svg = charts.timeseries_svg(hours([1, 5, 3, 9]))

    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"')  # autônomo, para virar <img>
    assert svg.count("<polyline") == 1
    assert len(re.search(r'points="([^"]+)"', svg).group(1).split()) == 4


def test_timeseries_labels_each_new_day_once():
    svg = charts.timeseries_svg(hours([1] * 6))  # 22h do dia 5 até 03h do dia 6

    assert svg.count(">05/01<") == 1 and svg.count(">06/01<") == 1


def test_timeseries_axis_top_rounds_up_to_multiple_of_five():
    svg = charts.timeseries_svg(hours([1, 7]))

    assert [int(v) for v in re.findall(r'text-anchor="end"[^>]*>(\d+)<', svg)] == [0, 5, 10]


def test_timeseries_handles_empty_input():
    assert "<polyline" in charts.timeseries_svg([])


def test_timeseries_figure_is_an_img_with_alt_text_not_an_svg_tag():
    html = charts.timeseries_html(hours([1, 9]), 'Pico de 9 "eventos" <b>', "Eventos")

    assert "<svg" not in html  # o st.html do Streamlit remove tags <svg>
    assert 'alt="Pico de 9 &quot;eventos&quot; &lt;b&gt;"' in html
    encoded = re.search(r'src="data:image/svg\+xml;base64,([^"]+)"', html).group(1)
    assert base64.b64decode(encoded).decode() == charts.timeseries_svg(hours([1, 9]))
    assert "<figcaption>Eventos por hora, em UTC.</figcaption>" in html


def test_table_is_a_labelled_focusable_region_with_headers():
    html = charts.table_html("Alertas", ["Nº", "Usuário"], [[1, "alice"], [2, "<b>"]], "t")

    assert 'role="region" tabindex="0" aria-labelledby="t-c"' in html  # rolável por teclado
    assert '<caption id="t-c">Alertas</caption>' in html
    assert html.count('<th scope="col">') == 2
    assert '<th scope="row">1</th><td>alice</td>' in html
    assert "&lt;b&gt;" in html and "<b>" not in html


def test_table_without_rows_is_still_valid():
    assert "<tbody></tbody>" in charts.table_html("c", ["A"], [], "t")
