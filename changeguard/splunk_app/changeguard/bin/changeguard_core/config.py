"""Where ArangoDB connection settings come from.

Inside Splunk: [arango] stanza of changeguard.conf + password from Splunk's
encrypted storage (realm "changeguard", username = the Arango user).
Outside Splunk (MCP server, scripts, tests): CG_ARANGO_* environment variables.
"""

import os

from .arango import ArangoClient

PASSWORD_REALM = "changeguard"


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y")


def client_from_env():
    return ArangoClient(
        url=os.environ.get("CG_ARANGO_URL", "http://127.0.0.1:8529"),
        database=os.environ.get("CG_ARANGO_DB", "changeguard"),
        username=os.environ.get("CG_ARANGO_USER", "root"),
        password=os.environ.get("CG_ARANGO_PASSWORD", ""),
        verify_ssl=_truthy(os.environ.get("CG_ARANGO_VERIFY_SSL", "true")),
        timeout=int(os.environ.get("CG_ARANGO_TIMEOUT", "30")),
    )


def client_from_splunk(service):
    """Build a client from the Splunk app config. `service` is splunklib's Service."""
    stanza = service.confs["changeguard"]["arango"].content
    username = stanza.get("username", "root")
    password = None
    for credential in service.storage_passwords:
        if credential.realm == PASSWORD_REALM and credential.username == username:
            password = credential.clear_password
            break
    if password is None:
        password = os.environ.get("CG_ARANGO_PASSWORD")
    if password is None:
        raise RuntimeError(
            "No ArangoDB password stored. Add one with realm=%s username=%s "
            "(see README: storage/passwords)." % (PASSWORD_REALM, username)
        )
    return ArangoClient(
        url=stanza.get("url", "http://127.0.0.1:8529"),
        database=stanza.get("database", "changeguard"),
        username=username,
        password=password,
        verify_ssl=_truthy(stanza.get("verify_ssl", "true")),
        timeout=int(stanza.get("timeout", "30")),
    )
