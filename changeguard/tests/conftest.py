import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "splunk_app", "changeguard", "bin"))
sys.path.insert(0, os.path.join(ROOT, "mcp_server"))
sys.path.insert(0, os.path.join(ROOT, "arango"))


class FakeClient(object):
    """Records calls; returns canned AQL results in order."""

    def __init__(self, results=None, fail=None):
        self.results = list(results or [])
        self.fail = fail
        self.upserts = []
        self.queries = []

    def upsert(self, collection, docs):
        if self.fail:
            raise self.fail
        self.upserts.append((collection, docs))
        return len(docs)

    def aql(self, query, bind_vars=None):
        if self.fail:
            raise self.fail
        self.queries.append((query, bind_vars))
        return self.results.pop(0) if self.results else []
