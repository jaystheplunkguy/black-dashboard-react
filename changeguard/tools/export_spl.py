#!/usr/bin/env python3
"""Export the ChangeGuard saved searches as plain SPL files.

    python3 tools/export_spl.py            # writes spl/changeguard_searches.spl and spl/changeguard_searches_expanded.spl

- changeguard_searches.spl           each search as in the app (uses the cg_* macros), with schedule/time range
- changeguard_searches_expanded.spl  the same searches with every macro expanded, so they run without the app's
                                     macros (they still need the KV stores/lookups and the Arango commands)
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(ROOT, "splunk_app", "changeguard", "default")
OUT = os.path.join(ROOT, "spl")


def read_conf(path):
    """Minimal .conf reader: stanzas, key = value, backslash line continuation (newline kept)."""
    stanzas, current, key = {}, None, None
    with open(path) as handle:
        lines = handle.read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("[") and line.rstrip().endswith("]"):
            current = line.strip()[1:-1]
            stanzas[current] = {}
            continue
        if "=" in line and current is not None:
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            while value.endswith("\\") and i < len(lines):
                value = value[:-1].rstrip() + "\n" + lines[i].rstrip()
                i += 1
            stanzas[current][key] = value
    return stanzas


def split_args(text):
    """Split macro arguments on top-level commas; Splunk strips one level of surrounding quotes."""
    args, depth, quote, buf = [], 0, False, ""
    for ch in text:
        if ch == '"':
            quote = not quote
        if not quote and ch == "(":
            depth += 1
        if not quote and ch == ")":
            depth -= 1
        if ch == "," and depth == 0 and not quote:
            args.append(buf)
            buf = ""
            continue
        buf += ch
    args.append(buf)
    out = []
    for arg in args:
        arg = arg.strip()
        if len(arg) >= 2 and arg[0] == '"' and arg[-1] == '"':
            arg = arg[1:-1]
        out.append(arg)
    return out


MACRO_CALL = re.compile(r"`([A-Za-z_][\w]*)(?:\(((?:[^`])*)\))?`")


def expand(text, macros, depth=0):
    if depth > 20:
        raise RuntimeError("macro recursion")

    def repl(match):
        name, raw_args = match.group(1), match.group(2)
        args = split_args(raw_args) if raw_args is not None else []
        stanza = "%s(%d)" % (name, len(args)) if args else name
        if stanza not in macros:
            return match.group(0)
        body = macros[stanza]["definition"]
        names = [a.strip() for a in macros[stanza].get("args", "").split(",") if a.strip()]
        for arg_name, value in zip(names, args):
            body = body.replace("$%s$" % arg_name, value)
        return expand(body, macros, depth + 1)

    previous = None
    while previous != text:
        previous = text
        text = MACRO_CALL.sub(repl, text)
    return text


def header(name, settings, comment):
    sched = settings.get("cron_schedule") if settings.get("enableSched") == "1" else "manual / not scheduled"
    earliest, latest = settings.get("dispatch.earliest_time"), settings.get("dispatch.latest_time")
    lines = ["Saved search : %s" % name, "Schedule     : %s" % sched]
    if earliest or latest:
        lines.append("Time range   : earliest=%s latest=%s" % (earliest or "-", latest or "-"))
    if settings.get("realtime_schedule") == "0":
        lines.append("               realtime_schedule = 0 (missed windows are replayed)")
    if settings.get("max_concurrent"):
        lines.append("               max_concurrent = %s" % settings["max_concurrent"])
    if settings.get("counttype"):
        lines.append("Alert        : one alert per result (alert.digest_mode = 0); enable email/webhook in local/")
    # No backticks inside SPL comments: Splunk would try to expand them as macros.
    lines += [""] + [c.lstrip("# ").rstrip().replace("`", "'") for c in comment]
    body = "\n".join("  " + line if line else "" for line in lines)
    return "```\n" + body + "\n```"


def comments_by_stanza(path):
    out, pending = {}, []
    with open(path) as handle:
        for line in handle:
            if line.startswith("#"):
                pending.append(line.rstrip("\n"))
            elif line.startswith("["):
                out[line.strip()[1:-1]] = pending
                pending = []
            elif not line.strip():
                pending = [] if not pending or not out else pending
    return out


def main():
    macros = read_conf(os.path.join(DEFAULT, "macros.conf"))
    searches = read_conf(os.path.join(DEFAULT, "savedsearches.conf"))
    comments = comments_by_stanza(os.path.join(DEFAULT, "savedsearches.conf"))
    os.makedirs(OUT, exist_ok=True)
    plain, expanded = [], []
    intro = ("```\n  ChangeGuard AI - scheduled searches in SPL (%s).\n"
             "  Generated from splunk_app/changeguard/default/savedsearches.conf by tools/export_spl.py.\n"
             "  Each block is one saved search; paste a block into the search bar (or savedsearches.conf).\n```\n")
    plain.append(intro % "macro form: needs the changeguard app's macros")
    expanded.append(intro % "macros expanded: needs only the KV stores, lookups and the Arango commands")
    for name, settings in searches.items():
        comment = [c for c in comments.get(name, []) if not c.startswith("# ChangeGuard AI scheduled")
                   and not c.startswith("# Feeds ->") and not c.startswith("# validation reports")
                   and not c.startswith("# Override schedules")]
        head = header(name, settings, comment)
        plain.append(head + "\n" + settings["search"].strip() + "\n")
        expanded.append(head + "\n" + expand(settings["search"], macros).strip() + "\n")
    with open(os.path.join(OUT, "changeguard_searches.spl"), "w") as handle:
        handle.write("\n\n".join(plain))
    with open(os.path.join(OUT, "changeguard_searches_expanded.spl"), "w") as handle:
        handle.write("\n\n".join(expanded))
    # Macros in readable form, for reference.
    lines = ["```\n  ChangeGuard AI - macros (default/macros.conf). Settings > Advanced search > Search macros.\n```\n"]
    for name, stanza in macros.items():
        args = stanza.get("args")
        lines.append("``` macro: %s%s ```\n%s\n" % (name, ("   args: " + args) if args else "", stanza["definition"]))
    with open(os.path.join(OUT, "changeguard_macros.spl"), "w") as handle:
        handle.write("\n".join(lines))
    print("wrote %d searches and %d macros to %s" % (len(searches), len(macros), OUT))


if __name__ == "__main__":
    main()
