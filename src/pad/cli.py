import argparse
import json

from pad.io.loaders import read_jsonl, read_lines
from pad.parsers.windows import parse_windows
from pad.parsers.linux import parse_linux_auth
from pad.parsers.cloud import parse_cloud
from pad.detection.engine import detect

def main():
    ap = argparse.ArgumentParser(prog="pad", description="Privilege Abuse Detection (reference implementation)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run detection on input log files")
    run.add_argument("--windows", required=False)
    run.add_argument("--linux", required=False)
    run.add_argument("--cloud", required=False)

    args = ap.parse_args()

    events = []

    if args.windows:
        for evt in read_jsonl(args.windows):
            ne = parse_windows(evt)
            if ne:
                events.append(ne)

    if args.linux:
        for line in read_lines(args.linux):
            ne = parse_linux_auth(line)
            if ne:
                events.append(ne)

    if args.cloud:
        for evt in read_jsonl(args.cloud):
            ne = parse_cloud(evt)
            if ne:
                events.append(ne)

    alerts = detect(events)
    for a in alerts:
        print(json.dumps(a, ensure_ascii=False))

if __name__ == "__main__":
    main()
