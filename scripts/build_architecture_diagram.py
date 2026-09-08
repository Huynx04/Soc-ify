#!/usr/bin/env python3
"""SOC-ify architecture diagram helper.

The source of truth is the committed, human-authored SVG at
assets/soc-architecture.svg — that is what README.md embeds (GitHub renders SVG).
This helper validates the SVG is well-formed and reports its dimensions so a
diagram edit can't silently land broken.

Optional: if `cairosvg` is installed it also bakes a PNG copy next to the SVG for
docs/PDF use (not embedded in README).

Usage:
    python scripts/build_architecture_diagram.py            # validate + (optional) PNG
"""
import os
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
SVG = os.path.join(os.path.dirname(HERE), "assets", "soc-architecture.svg")
PNG = SVG[:-4] + ".png"

# 1) well-formed + structural sanity
root = ET.parse(SVG).getroot()
ns = {"s": "http://www.w3.org/2000/svg"}
rects = len(root.findall(".//s:rect", ns))
texts = len(root.findall(".//s:text", ns))
vb = root.get("viewBox")
print(f"OK  {os.path.relpath(SVG, os.path.dirname(HERE))}  rects={rects} text_nodes={texts}  viewBox={vb}")
assert rects >= 8, "too few boxes - diagram likely broken"
assert root.get("viewBox"), "missing viewBox"

# 2) optional PNG bake
try:
    import cairosvg
    cairosvg.svg2png(url=SVG, write_to=PNG, output_width=1400)
    print(f"PNG baked: {os.path.relpath(PNG, os.path.dirname(HERE))}")
except ImportError:
    print("cairosvg not installed -> skipping PNG (SVG is the README source of truth).")
print("diagram check passed.")
