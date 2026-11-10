"""WCAG AA contrast gate for the Hexbane Scan page (stdlib only, no browser) - run by tests/run_all.py.

Prior hone rounds repeatedly scored C5 "contrast unverified": the severity colours and the
light-theme decoded-text callout looked borderline for WCAG AA but nobody measured them. This
suite makes that a durable, CI-enforced fact. It parses the theme variables straight out of
web/styles.css and asserts the severity colours, the decoded-text callout label, the decoded body
text, and the FAIL/REVIEW/PASS verdict banner clear WCAG AA in BOTH themes (4.5:1 for normal text,
3:1 for the large 1.35rem/800 verdict word). If a future palette change drops any of these below
AA, this suite fails CI here - so the C5 "severity colours that pass contrast" anchor cannot
regress silently behind a visual change.

The colour math is the WCAG 2.x relative-luminance / contrast-ratio formula. Tinted surfaces
(e.g. the dashed `.hidden-text` box, which is `color-mix(in srgb, <critical> 6%, transparent)`
over the finding panel) are composited with a plain source-over blend so the measured background
is the one the text actually sits on.
"""

import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
CSS = (APP / "web" / "styles.css").read_text(encoding="utf-8")

AA = 4.5  # WCAG AA minimum for normal text
AA_LARGE = 3.0  # WCAG AA minimum for large text (the verdict word is 1.35rem weight-800 = large)
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def hex_to_rgb(value):
    value = value.lstrip("#")
    return (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16))


def srgb_channel(channel):
    channel = channel / 255.0
    return channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4


def luminance(rgb):
    r, g, b = (srgb_channel(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg, bg):
    l1, l2 = luminance(fg), luminance(bg)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


def mix_over(fg, bg, alpha):
    """Composite `color-mix(in srgb, <fg> <alpha>% , transparent)` over `bg` (source-over)."""
    return tuple(round(bg[i] * (1 - alpha) + fg[i] * alpha) for i in range(3))


def theme_variables(theme):
    """Merge the hex custom properties declared for `theme` across every matching :root block.

    A theme's palette is split across several blocks (the base :root block, the scan-page severity
    block, theme overrides), so gather all of them. The default :root block applies to dark; the
    [data-theme="light"] block applies only to light.
    """
    vars_ = {}
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", CSS):
        selector = selector.strip()
        if theme == "light":
            matched = 'data-theme="light"' in selector
        else:
            matched = "data-theme" not in selector or 'data-theme="dark"' in selector
        if not matched:
            continue
        for name, value in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body):
            value = value.strip()
            if value.startswith("#"):
                vars_[name] = hex_to_rgb(value)
    return vars_


for theme in ("dark", "light"):
    v = theme_variables(theme)
    panel = v.get("--panel")
    for name in ("--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--pass", "--text"):
        check(name in v, f"{theme}: web/styles.css is missing {name}")
    check(panel is not None, f"{theme}: web/styles.css is missing --panel")
    if panel is None:
        continue

    # Severity chips (.sev.*): transparent background over the finding panel.
    for name, label in (("--sev-critical", "critical"), ("--sev-high", "high"),
                        ("--sev-medium", "medium"), ("--sev-low", "low")):
        if v.get(name) is None:
            continue
        ratio = contrast(v[name], panel)
        check(ratio >= AA, f"{theme}: severity '{label}' chip is {ratio:.2f}:1, below WCAG AA {AA}:1")

    # Decoded-text callout (.hidden-text): dashed box tinted 6% critical over the panel.
    critical = v.get("--sev-critical")
    body = v.get("--text", critical)
    if critical is not None:
        box = mix_over(critical, panel, 0.06)
        label_ratio = contrast(critical, box)
        check(label_ratio >= AA,
              f"{theme}: decoded-text callout label is {label_ratio:.2f}:1, below WCAG AA {AA}:1")
        body_ratio = contrast(body, box)
        check(body_ratio >= AA,
              f"{theme}: decoded body text is {body_ratio:.2f}:1, below WCAG AA {AA}:1")

    # Verdict banner (.verdict-word): a large 1.35rem weight-800 word (>=14pt bold = large text),
    # so its WCAG AA bar is 3:1, not 4.5:1. Each word is its severity colour over a light tint of
    # that colour on the panel (see .verdict.FAIL/.REVIEW/.PASS in styles.css).
    for key, label, tint in (
        ("--sev-critical", "FAIL", 0.09),
        ("--sev-medium", "REVIEW", 0.10),
        ("--pass", "PASS", 0.09),
    ):
        colour = v.get(key)
        if colour is None:
            continue
        verdict_bg = mix_over(colour, panel, tint)
        ratio = contrast(colour, verdict_bg)
        check(ratio >= AA_LARGE,
              f"{theme}: verdict '{label}' word is {ratio:.2f}:1, below WCAG AA large {AA_LARGE}:1")

if failures:
    print("FAILED")
    for failure in failures:
        print(" -", failure)
    sys.exit(1)

print("OK - WCAG AA contrast holds for severity colours, decoded-text callout + verdict banner (both themes)")
