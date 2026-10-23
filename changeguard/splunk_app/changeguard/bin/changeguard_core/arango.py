"""Minimal ArangoDB HTTP client (stdlib only, so it runs inside Splunk's Python).

Only what ChangeGuard needs: AQL cursors, bulk upserts, and a few admin calls
for bootstrap.
"""

import base64
import json
import ssl
import urllib.error
import urllib.request

UPSERT_DOCS_AQL = """
FOR d IN @docs
  UPSERT { _key: d._key }
  INSERT d
  UPDATE UNSET(d, "_key", "_from", "_to")
  IN @@col
  OPTIONS { keepNull: false, mergeObjects: true }
  COLLECT WITH COUNT INTO n
  RETURN n
"""


class ArangoError(Exception):
    def __init__(self, message, status=None, error_num=None):
        super().__init__(message)
        self.status = status
        self.error_num = error_num


class ArangoClient(object):
    def __init__(self, url, database, username, password, verify_ssl=True, timeout=30, opener=None):
        self.base = url.rstrip("/")
        self.database = database
        self.timeout = timeout
        token = base64.b64encode(("%s:%s" % (username, password)).encode("utf-8")).decode("ascii")
        self._auth = "Basic " + token
        self._context = None
        if not verify_ssl:
            self._context = ssl.create_default_context()
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE
        self._opener = opener or self._default_open

    # -- transport ---------------------------------------------------------

    def _default_open(self, request):
        handlers = [urllib.request.HTTPSHandler(context=self._context)] if self._context else []
        return urllib.request.build_opener(*handlers).open(request, timeout=self.timeout)

    def request(self, method, path, body=None, database=None, system=False):
        db = "_system" if system else (database or self.database)
        url = "%s/_db/%s%s" % (self.base, db, path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._auth)
        req.add_header("Content-Type", "application/json")
        try:
            resp = self._opener(req)
            raw = resp.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8"))
            except ValueError:
                payload = {"errorMessage": raw.decode("utf-8", "replace")}
            raise ArangoError(payload.get("errorMessage", str(exc)), exc.code, payload.get("errorNum")) from exc
        except urllib.error.URLError as exc:
            raise ArangoError("cannot reach ArangoDB at %s: %s" % (self.base, exc.reason)) from exc
        return json.loads(raw.decode("utf-8")) if raw else {}

    # -- AQL ---------------------------------------------------------------

    def aql(self, query, bind_vars=None, batch_size=1000):
        """Run AQL and return all results (follows the cursor)."""
        body = {"query": query, "bindVars": bind_vars or {}, "batchSize": batch_size}
        res = self.request("POST", "/_api/cursor", body)
        results = list(res.get("result", []))
        while res.get("hasMore"):
            res = self.request("POST", "/_api/cursor/%s" % res["id"])
            results.extend(res.get("result", []))
        return results

    def upsert(self, collection, docs, batch_size=1000):
        """Insert-or-merge documents (or edges) by _key. Returns the number written."""
        written = 0
        for i in range(0, len(docs), batch_size):
            chunk = docs[i:i + batch_size]
            res = self.aql(UPSERT_DOCS_AQL, {"docs": chunk, "@col": collection})
            written += res[0] if res else 0
        return written

    # -- admin (bootstrap only) ---------------------------------------------

    def ensure_database(self):
        existing = self.request("GET", "/_api/database", system=True).get("result", [])
        if self.database not in existing:
            self.request("POST", "/_api/database", {"name": self.database}, system=True)
            return True
        return False

    def ensure_collection(self, name, edge=False):
        try:
            self.request("POST", "/_api/collection", {"name": name, "type": 3 if edge else 2})
            return True
        except ArangoError as exc:
            if exc.error_num == 1207:  # duplicate name
                return False
            raise

    def ensure_index(self, collection, fields, unique=False, sparse=True):
        body = {"type": "persistent", "fields": fields, "unique": unique, "sparse": sparse}
        return self.request("POST", "/_api/index?collection=%s" % collection, body)

    def ensure_graph(self, name, edge_definitions):
        try:
            self.request("POST", "/_api/gharial", {"name": name, "edgeDefinitions": edge_definitions})
            return True
        except ArangoError as exc:
            if exc.error_num == 1925:  # graph already exists
                for definition in edge_definitions:
                    self.request(
                        "PUT", "/_api/gharial/%s/edge/%s" % (name, definition["collection"]), definition
                    )
                return False
            raise
