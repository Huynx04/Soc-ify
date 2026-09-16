"""SOC-ify offline test suite.

Runs with NO Elasticsearch / Kibana / network — pure static validation of the
artifacts that must stay coherent. This is what CI runs on every push.

    python -m pytest tests/ -q          (if pytest is available)
    python tests/test_artifacts.py      (stdlib-only fallback)
"""
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules", "detection-rules.yaml")
PIPELINE = os.path.join(ROOT, "ingest-pipelines", "nginx-soc-enrich.json")
TRANSFORM = os.path.join(ROOT, "transforms", "freq-detection-by-ip.json")
TEMPLATE_HINT = os.path.join(ROOT, "scripts", "deploy.sh")
README = os.path.join(ROOT, "README.md")

REQUIRED_RULES = [f"R-{i:03d}" for i in range(1, 20)]
VALID_SEVERITY = {1, 2, 3, 4}


def _load_rules():
    if yaml is None:
        raise RuntimeError("PyYAML required to validate detection-rules.yaml")
    with open(RULES, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# --------------------------------------------------------------------- rules
def test_rules_file_parses():
    doc = _load_rules()
    assert "rules" in doc, "detection-rules.yaml must have a top-level 'rules' key"
    assert isinstance(doc["rules"], list)
    assert len(doc["rules"]) > 0


def test_all_19_rules_present():
    ids = [r["id"] for r in _load_rules()["rules"]]
    missing = [r for r in REQUIRED_RULES if r not in ids]
    assert not missing, f"missing rules: {missing}"
    assert len(ids) == len(set(ids)), "duplicate rule IDs"


def test_rule_ids_are_well_formed():
    for r in _load_rules()["rules"]:
        assert re.fullmatch(r"R-\d{3}", r["id"]), f"bad rule id {r['id']!r}"
        assert r.get("title"), f"{r['id']} has no title"


def test_rules_map_to_mitre():
    """Every rule must carry MITRE context -- a headline claim in the README."""
    for r in _load_rules()["rules"]:
        mitre = r.get("mitre") or {}
        has = (mitre.get("id") or r.get("mitre_id") or
               mitre.get("technique") or r.get("mitre_technique"))
        assert has, f"{r['id']} has no MITRE mapping"


def test_readme_rule_count_matches_yaml():
    """Guards the exact bug we already shipped once: README saying 18 when it's 19."""
    n = len(_load_rules()["rules"])
    text = open(README, encoding="utf-8").read()
    assert f"**{n} detection rules**" in text, \
        f"README feature bullet must say {n} detection rules"
    assert f"R-001…{n:03d}" in text or f"R-001..R-{n:03d}" in text, \
        f"README rule-table heading must span up to R-{n:03d}"


def test_no_stale_rule_counts_in_scripts():
    """Any hardcoded '18 rule' style string in scripts/ is a latent doc bug."""
    bad = []
    for name in os.listdir(os.path.join(ROOT, "scripts")):
        if not name.endswith(".py"):
            continue
        path = os.path.join(ROOT, "scripts", name)
        for i, line in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
            if re.search(r"\b18 rule|\bR-001\.\.R-018", line):
                bad.append(f"{name}:{i}")
    assert not bad, f"stale rule-count references: {bad}"


# ------------------------------------------------------------------ pipeline
def test_ingest_pipeline_is_valid_json_and_structural():
    doc = json.load(open(PIPELINE, encoding="utf-8"))
    procs = doc.get("processors")
    assert isinstance(procs, list) and procs, "pipeline needs processors"


def test_pipeline_classifies_attacks():
    """The pipeline's whole job: emit soc.attack_class / severity / confidence."""
    raw = open(PIPELINE, encoding="utf-8").read()
    for field in ("soc.attack_class", "soc.severity", "soc.confidence"):
        assert field in raw, f"pipeline does not set {field}"


def test_transform_is_valid_json():
    doc = json.load(open(TRANSFORM, encoding="utf-8"))
    assert doc.get("source", {}).get("index"), "transform needs a source index"
    assert doc.get("dest", {}).get("index"), "transform needs a dest index"


def test_every_pipeline_script_exists():
    """deploy.sh registers the pipeline; the file it points at must exist."""
    text = open(TEMPLATE_HINT, encoding="utf-8").read()
    refs = re.findall(r"ingest-pipelines/([\w\-.]+\.json)", text)
    assert refs, "deploy.sh should reference an ingest pipeline file"
    for ref in refs:
        assert os.path.exists(os.path.join(ROOT, "ingest-pipelines", ref)), \
            f"deploy.sh references missing ingest-pipelines/{ref}"


# ---------------------------------------------------------------------- repo
def test_no_secrets_committed():
    """Cheap secret scan -- must never regress on a public portfolio repo."""
    pats = re.compile(
        r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|"
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    )
    hits = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", ".venv"}]
        for name in files:
            if name.endswith((".png", ".zip", ".exe", ".docx", ".xlsx")):
                continue
            path = os.path.join(base, name)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if pats.search(text):
                hits.append(os.path.relpath(path, ROOT))
    assert not hits, f"possible secrets committed: {hits}"


def test_env_local_not_tracked():
    ignore = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
    assert ".env.local" in ignore, ".env.local must stay gitignored"


def test_scripts_compile():
    import py_compile
    import tempfile
    bad = []
    sdir = os.path.join(ROOT, "scripts")
    with tempfile.TemporaryDirectory() as tmp:
        for name in os.listdir(sdir):
            if not name.endswith(".py"):
                continue
            try:
                py_compile.compile(os.path.join(sdir, name),
                                   cfile=os.path.join(tmp, name + "c"),
                                   doraise=True)
            except py_compile.PyCompileError as e:
                bad.append(f"{name}: {e}")
    assert not bad, f"syntax errors: {bad}"


# --------------------------------------------------- stdlib-only fallback run
def _main():
    if yaml is None:
        print("[!] PyYAML missing -- pip install pyyaml (rules tests need it)")
        return 1
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS {name}")
        except Exception as e:
            failed.append(name)
            print(f"  FAIL {name}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed"
          + (f" -- FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
