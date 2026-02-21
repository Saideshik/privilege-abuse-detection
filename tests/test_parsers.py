from pad.parsers.linux import parse_linux_auth
from pad.parsers.windows import parse_windows

def test_linux_parser():
    line = "Feb 20 09:12:01 web01 sudo: admin01 : TTY=pts/0 ; PWD=/home/admin01 ; USER=root ; COMMAND=/usr/bin/apt update"
    e = parse_linux_auth(line)
    assert e is not None
    assert e.user == "admin01"
    assert e.host == "web01"
    assert e.action == "sudo"

def test_windows_parser():
    evt = {"timestamp":"2026-02-20T09:18:44","source":"windows","event_id":4688,"user":"admin01","host":"dc01","process":"powershell.exe","command_line":"powershell -enc AAA"}
    e = parse_windows(evt)
    assert e is not None
    assert e.action == "process"
    assert e.process == "powershell.exe"
