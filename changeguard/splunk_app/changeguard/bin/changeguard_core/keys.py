"""Deterministic ArangoDB keys.

Every component (SPL loaders, commands, MCP tools) must turn a hostname,
CI id or change number into the same _key, otherwise edges dangle. Keep all
key logic here.
"""

import hashlib
import re

# Characters ArangoDB allows in a document _key.
_DISALLOWED = re.compile(r"[^A-Za-z0-9_\-:.@()+,=;$!*'%]")
_MAX_KEY_BYTES = 254
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def safe_key(value):
    """Return a valid ArangoDB _key for any string (stable for equal input)."""
    if value is None:
        raise ValueError("key value is empty")
    text = str(value).strip()
    if not text:
        raise ValueError("key value is empty")
    key = _DISALLOWED.sub("_", text)
    if len(key.encode("utf-8")) > _MAX_KEY_BYTES:
        digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
        key = key[:200] + "_" + digest
    return key


def safe_id(collection, value):
    """Return '<collection>/<safe_key>'. Accepts 'col/key' and re-sanitises the key part."""
    text = str(value).strip()
    if "/" in text and collection is None:
        col, _, key = text.partition("/")
        return col + "/" + safe_key(key)
    if "/" in text and text.split("/", 1)[0] == collection:
        text = text.split("/", 1)[1]
    return collection + "/" + safe_key(text)


def normalise_host(value):
    """Canonical device name: lower-case short hostname, IPs kept as-is.

    Must match the `cg_norm_host` SPL macro.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if _IPV4.match(text):
        return text
    return text.split(".", 1)[0]


def edge_key(from_id, to_id, label=None):
    """Stable edge key derived from its endpoints, so re-loads upsert instead of duplicating."""
    raw = "%s|%s|%s" % (from_id, to_id, label or "")
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]
