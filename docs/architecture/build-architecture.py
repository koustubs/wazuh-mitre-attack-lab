"""Render the eleven diagrams and put the same source in all three places that carry it.

A diagram in this folder exists three times over: the `.mmd` file, a fenced block in
README.md, and a `{code, svg}` entry inside Wazuh-Project-Architecture.html, which renders
offline and therefore has to carry its own picture. Three copies edited by hand is three
copies that drift, and a diagram that disagrees with the repository is worse than no diagram,
because a reader has no way to tell which one is lying.

So the `.mmd` files are the source and this writes the other two from them. Edit a `.mmd`,
run this, commit all three.

Rendering needs mermaid-cli, which is fetched on demand and wants a few hundred megabytes of
headless Chromium the first time:

    python build-architecture.py                 # render and rewrite both consumers
    python build-architecture.py --check         # exit 1 if any copy is out of date
    python build-architecture.py --no-render     # rewrite the code blocks, keep the pictures

--no-render is for a text-only change, a renamed node or a corrected label, where the picture
is already right. It is not a way to skip the render on a structural edit; --check is what
catches that before it reaches a commit.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
README = HERE / "README.md"
PAGE = HERE / "Wazuh-Project-Architecture.html"
CONFIG = HERE / "mermaid.config.json"
MERMAID = "@mermaid-js/mermaid-cli@11"

FENCE = re.compile(r"```mermaid\r?\n(.*?)\r?\n```", re.S)
VIEWS = re.compile(r"(const views=)(\[.*?\])(;)", re.S)
HEADING = re.compile(r"^##\s+(\d+)\.\s+(.+?)\s*$", re.M)


def diagrams():
    """The .mmd files, in the order their numbers put them."""
    found = sorted(HERE.glob("[0-9][0-9]-*.mmd"))
    if not found:
        raise SystemExit("No numbered .mmd files in %s" % HERE)
    return found


def titles(readme):
    """The human titles, read from the README headings rather than kept a fourth time."""
    return dict((int(n), t) for n, t in HEADING.findall(readme))


def render(paths):
    """One SVG per diagram, with the id and theme the page's stylesheet expects."""
    npx = shutil.which("npx")
    if not npx:
        raise SystemExit("npx is not on PATH, so mermaid-cli cannot run. Install Node, or "
                         "pass --no-render if the pictures are already correct.")
    out = {}
    with tempfile.TemporaryDirectory() as work:
        work = pathlib.Path(work)
        # Chromium refuses to start as root in a container without this, and it is harmless
        # everywhere else.
        puppeteer = work / "puppeteer.json"
        puppeteer.write_text(json.dumps({"args": ["--no-sandbox"]}), encoding="utf-8")
        for index, path in enumerate(paths):
            target = work / (path.stem + ".svg")
            print("  rendering %s" % path.name)
            result = subprocess.run(
                [npx, "--yes", MERMAID, "-i", str(path), "-o", str(target),
                 "-c", str(CONFIG), "-I", "arch%d" % index, "-b", "transparent",
                 "-p", str(puppeteer)],
                capture_output=True, text=True)
            if result.returncode != 0 or not target.exists():
                sys.stderr.write(result.stdout + result.stderr)
                raise SystemExit("mermaid-cli failed on %s" % path.name)
            out[path.stem] = target.read_text(encoding="utf-8").strip()
    return out


def rewrite_readme(readme, codes):
    """Replace the fenced blocks in order. The count has to match or something has moved."""
    blocks = FENCE.findall(readme)
    if len(blocks) != len(codes):
        raise SystemExit("README.md has %d mermaid blocks and there are %d diagrams. Add the "
                         "missing section, or remove the extra block, before running this."
                         % (len(blocks), len(codes)))
    pieces, last, index = [], 0, 0
    for match in FENCE.finditer(readme):
        pieces.append(readme[last:match.start()])
        pieces.append("```mermaid\n%s\n```" % codes[index])
        last, index = match.end(), index + 1
    pieces.append(readme[last:])
    return "".join(pieces)


def rewrite_page(page, paths, codes, svgs, names):
    found = VIEWS.search(page)
    if not found:
        raise SystemExit("No `const views=[...]` array in %s" % PAGE.name)
    current = dict((v["name"], v) for v in json.loads(found.group(2)))
    views = []
    for index, path in enumerate(paths):
        number = int(path.name[:2])
        previous = current.get(path.stem, {})
        svg = svgs.get(path.stem) or previous.get("svg")
        if not svg:
            raise SystemExit("No picture for %s, and none in the page to keep. Run without "
                             "--no-render." % path.stem)
        views.append({"title": names.get(number) or previous.get("title") or path.stem,
                      "name": path.stem, "code": codes[index], "svg": svg})
    return page[:found.start()] + found.group(1) + json.dumps(
        views, ensure_ascii=False, separators=(",", ":")) + found.group(3) + page[found.end():]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true",
                   help="report whether the copies are current and change nothing")
    p.add_argument("--no-render", action="store_true",
                   help="keep the pictures already in the page")
    a = p.parse_args()

    paths = diagrams()
    codes = [path.read_text(encoding="utf-8").replace("\r\n", "\n").strip() for path in paths]
    readme = README.read_text(encoding="utf-8")
    page = PAGE.read_text(encoding="utf-8")
    names = titles(readme)

    if a.check:
        blocks = [b.replace("\r\n", "\n").strip() for b in FENCE.findall(readme)]
        stale = [paths[i].name for i in range(min(len(blocks), len(codes)))
                 if blocks[i] != codes[i]]
        if len(blocks) != len(codes):
            stale.append("README block count is %d against %d diagrams"
                         % (len(blocks), len(codes)))
        found = VIEWS.search(page)
        embedded = dict((v["name"], v["code"]) for v in json.loads(found.group(2))) \
            if found else {}
        stale += [path.name for path, code in zip(paths, codes)
                  if embedded.get(path.stem, "").replace("\r\n", "\n").strip() != code]
        if stale:
            print("Out of date: %s" % ", ".join(sorted(set(stale))))
            print("Run build-architecture.py.")
            return 1
        print("README.md and %s carry the current %d diagrams." % (PAGE.name, len(paths)))
        return 0

    svgs = {} if a.no_render else render(paths)
    README.write_text(rewrite_readme(readme, codes), encoding="utf-8", newline="\n")
    PAGE.write_text(rewrite_page(page, paths, codes, svgs, names),
                    encoding="utf-8", newline="\n")
    print("wrote %s and %s from %d diagrams" % (README.name, PAGE.name, len(paths)))
    if a.no_render:
        print("Pictures were kept as they were. Re-run without --no-render after a "
              "structural change.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
