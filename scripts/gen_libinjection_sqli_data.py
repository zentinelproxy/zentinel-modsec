#!/usr/bin/env python3
"""Generate src/libinjection/sqli_data.rs from libinjection's sqli data header.

Usage:
    curl -fsSLO https://raw.githubusercontent.com/libinjection/libinjection/v4.0.2/src/libinjection_sqli_data.h
    python3 scripts/gen_libinjection_sqli_data.py libinjection_sqli_data.h > src/libinjection/sqli_data.rs

v4.0.2 is the libinjection that ModSecurity v3 vendors (others/libinjection).
The output must be byte-identical to the committed file; CI does not run this,
so regenerate and diff when moving to another libinjection version.
"""
import re
import sys

HEADER = """\
// @generated from libinjection v4.0.2 src/libinjection_sqli_data.h
// (github.com/libinjection/libinjection). Do not edit by hand.
// Copyright 2012-2016 Nick Galbreath, 2021 LibInjection. BSD 3-Clause license.
//
// `CHAR_PARSE_MAP` is `char_parse_map`; `SQL_KEYWORDS` is `sql_keywords`, in the
// same order, which the binary search in `sqli.rs` depends on. Entries of type
// `F` are the fingerprint blacklist (fingerprint prefixed with `0`, upper case).

use super::sqli::Parser::{self, *};
"""


def rust_byte(c: str) -> str:
    if c == "\\":
        return "b'\\\\'"
    if c == "'":
        return "b'\\''"
    return f"b'{c}'"


def rust_bytes(s: str) -> str:
    out = []
    for ch in s:
        if ch in '"\\':
            out.append("\\" + ch)
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}")
    return 'b"' + "".join(out) + '"'


def c_unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def main(path: str) -> None:
    src = open(path, encoding="latin-1").read()

    parse_map = src.split("char_parse_map[] = {", 1)[1].split("};", 1)[0]
    funcs = re.findall(r"&parse_(\w+)", parse_map)
    assert len(funcs) == 256, len(funcs)
    variants = [f[0].upper() + f[1:] for f in funcs]

    kw_block = src.split("sql_keywords[] = {", 1)[1].split("};", 1)[0]
    keywords = re.findall(r'\{"((?:[^"\\]|\\.)*)",\s*\'((?:[^\'\\]|\\.))\'\}', kw_block)
    assert keywords, "no keywords parsed"

    out = [HEADER, "#[rustfmt::skip]", "pub(super) static CHAR_PARSE_MAP: [Parser; 256] = ["]
    for row in range(0, 256, 8):
        out.append("    " + ", ".join(variants[row : row + 8]) + f", // {row}")
    out.append("];")
    out.append("")
    out.append("#[rustfmt::skip]")
    out.append(f"pub(super) static SQL_KEYWORDS: [(&[u8], u8); {len(keywords)}] = [")
    for word, kind in keywords:
        out.append(f"    ({rust_bytes(c_unescape(word))}, {rust_byte(c_unescape(kind))}),")
    out.append("];")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
