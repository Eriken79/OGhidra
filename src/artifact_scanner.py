import os
import yara
from typing import Dict, List

base_dir = os.path.dirname(os.path.abspath(__file__))
text_rules_dir = os.path.abspath(os.path.join(base_dir, "..", "yara-rules-text"))

filepaths = {}
for root, _, files in os.walk(text_rules_dir):
    for name in files:
        if name.endswith((".yar", ".yara")):
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, text_rules_dir)
            namespace = os.path.splitext(rel_path)[0].replace("\\", "_").replace("/", "_")
            filepaths[namespace] = full_path

good_filepaths = {}
for ns, path in filepaths.items():
    try:
        yara.compile(filepath=path)
        good_filepaths[ns] = path
    except yara.Error as e:
        print(f"Skipping bad rule: {path} -> {e}")

try:
    rules = yara.compile(filepaths=good_filepaths) if good_filepaths else None
    print("Text YARA compile succeeded.")
except yara.Error as e:
    print(f"Text YARA compile failed: {e}")
    rules = None


def scan_for_artifacts(text: str) -> List[Dict[str, str]]:
    if not text or rules is None:
        return []
    print("Text")
    print(text)
    raw_matches = rules.match(data=text.encode("utf-8", errors="ignore"))
    artifacts = []

    for match in raw_matches:
        artifacts.append({
            "pattern": match.meta.get("description", match.rule),
            "match": match.rule,
        })
    print("Artifacts:")
    print(artifacts)
    return artifacts
