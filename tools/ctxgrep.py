#!/usr/bin/env python3
"""Print ±N chars of context around literal matches (works on minified JS).
Usage: python3 -I ctxgrep.py <needle> <N> <path>..."""
import os, sys


def iter_files(path):
    if os.path.isfile(path):
        yield path
        return
    for d, _, files in os.walk(path):
        for fn in files:
            yield os.path.join(d, fn)


def main(needle: str, n: str, paths) -> None:
    nb, width = needle.encode(), int(n)
    for root in paths:
        for p in iter_files(root):
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            i = data.find(nb)
            while i != -1:
                ctx = data[max(0, i - width): i + len(nb) + width].decode("utf-8", "replace")
                print(f"{p}@{i}: {ctx.replace(chr(10), ' ⏎ ')}")
                i = data.find(nb, i + 1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
