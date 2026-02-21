import json
from pathlib import Path
from typing import Iterable

def read_jsonl(path: str) -> Iterable[dict]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def read_lines(path: str) -> Iterable[str]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")
