#!/usr/bin/env python3
"""Convert a `script` typescript log into an ASCII terminal MP4.

Uses drawtext with textfile= (one temp file per line) to completely avoid
quoting hell. Green-on-black terminal look, monospace font.
"""
import re
import subprocess
import sys
import tempfile
import os
import shutil

SRC = os.environ.get("KEYSMITH_DEMO_SCRIPT", "/tmp/keysmith-demo.script")
OUT = os.environ.get(
    "KEYSMITH_DEMO_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "demo.mp4"),
)
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
WIDTH = 95
FONT_SIZE = 22
LINE_H = 30
MARGIN = 40
VID_W, VID_H = 1280, 720

def parse_typescript(path):
    raw = open(path, "rb").read().decode("utf-8", errors="replace")
    ansi = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]')
    text = ansi.sub("", raw)
    lines = []
    for line in text.splitlines():
        line = line.rstrip()
        if line.startswith("Script started") or line.startswith("Script done"):
            continue
        lines.append(line)
    return lines

def screens_from_lines(lines, rows=24):
    screens = []
    page = []
    for line in lines:
        page.append(line)
        if len(page) >= rows:
            screens.append(page)
            page = []
    if page:
        screens.append(page)
    return screens

def main():
    lines = parse_typescript(SRC)
    screens = screens_from_lines(lines)
    print(f"parsed {len(lines)} lines, {len(screens)} screens")

    dur = 4.0
    total = len(screens) * dur

    workdir = tempfile.mkdtemp(prefix="smcp-drawtext-")
    filter_parts = []
    file_idx = 0
    for i, screen in enumerate(screens):
        for j, line in enumerate(screen[:24]):
            line = line[:WIDTH]
            if not line.strip():
                continue
            # Write line to temp file (textfile avoids all quoting issues)
            tf = os.path.join(workdir, f"t{file_idx:04d}.txt")
            with open(tf, "w", encoding="utf-8") as f:
                f.write(line)
            file_idx += 1
            y = MARGIN + j * LINE_H
            filter_parts.append(
                f"drawtext=fontfile={FONT}:textfile={tf}:"
                f"fontsize={FONT_SIZE}:fontcolor=0x00C864:x={MARGIN}:y={y}:"
                f"enable='between(t,{i*dur:.2f},{i*dur+dur:.2f})'"
            )
    vf = ",".join(filter_parts)

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(vf)
        script_path = f.name

    cmd = [
        "ffmpeg", "-y",
        "-f", "lavfi", "-i", f"color=c=0x0a0a0a:s={VID_W}x{VID_H}:d={total:.1f}:r=8",
        "-filter_complex_script", script_path,
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        OUT,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(script_path)
    shutil.rmtree(workdir, ignore_errors=True)
    if r.returncode != 0:
        print("ffmpeg failed:", r.stderr[-600:])
        sys.exit(1)
    print(f"✅ wrote {OUT} ({len(screens)} screens, total {total:.0f}s)")

if __name__ == "__main__":
    main()
