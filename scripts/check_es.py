#!/usr/bin/env python3
import sys, os, traceback
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import elasticsearch
print("lib version:", getattr(elasticsearch, "__version__", "?"))

from elasticsearch import Elasticsearch

ES_USER = os.environ.get("SOC_ES_USER", "CHANGE_ME")
ES_PASS = os.environ.get("SOC_ES_PASS", "CHANGE_ME")

try:
    es = Elasticsearch(["http://127.0.0.1:9200"],
                       basic_auth=(ES_USER, ES_PASS),
                       request_timeout=10, verify_certs=False)
    print("ping:", es.ping())
    try:
        info = es.info()
        print("info:", info.get("version", {}).get("number"))
    except Exception as e:
        print("info-error:", type(e).__name__, str(e)[:300])
except Exception as e:
    print("client-err:", type(e).__name__)
    traceback.print_exc()
