#!/usr/bin/env python3
"""Minimal read-only ASAR extractor.  Usage: python3 -I asar_extract.py <app.asar> <out_dir>"""
import json, os, struct, sys


def extract(asar_path: str, out_dir: str) -> None:
    out_root = os.path.realpath(out_dir)
    with open(asar_path, "rb") as f:
        _, header_size = struct.unpack("<II", f.read(8))      # pickle(uint32 header_size)
        header_pickle = f.read(header_size)                    # pickle(string json)
        json_len = struct.unpack("<I", header_pickle[4:8])[0]
        header = json.loads(header_pickle[8:8 + json_len])
        base = 8 + header_size

        def walk(node: dict, rel: str) -> None:
            for name, entry in node.get("files", {}).items():
                if name in ("", ".", "..") or "/" in name or "\x00" in name:
                    raise ValueError(f"unsafe entry name {name!r}")
                path = os.path.join(rel, name)
                if "files" in entry:
                    walk(entry, path)
                    continue
                if entry.get("unpacked") or "link" in entry:
                    continue                                   # lives in app.asar.unpacked/ or is a symlink
                dest = os.path.realpath(os.path.join(out_root, path))
                if not dest.startswith(out_root + os.sep):
                    raise ValueError(f"path escapes output dir: {path}")
                os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
                f.seek(base + int(entry["offset"]))
                with open(dest, "wb") as out:
                    out.write(f.read(int(entry["size"])))

        walk(header, "")


if __name__ == "__main__":
    extract(sys.argv[1], sys.argv[2])
