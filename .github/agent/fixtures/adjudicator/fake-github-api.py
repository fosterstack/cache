#!/usr/bin/env python3
"""SYNTHETIC TEST DOUBLE — not the auditor.

A fake of the GitHub issues API surface the auditor's notifier uses. It only
RECORDS calls to a JSON state file so a test can assert the auditor opened
exactly one owner-decision issue and that a second run UPDATED it rather than
opening a second. No network, no judgment.

  create <state.json> <title> <label> <assignee>   -> prints issue number, records it
  find   <state.json> <title>                       -> prints matching issue number or ""
  comment <state.json> <number> <text>              -> records a comment
  dump   <state.json>                               -> prints the state
"""
import json, os, sys

def load(p):
    return json.load(open(p)) if os.path.exists(p) else {"issues": [], "next": 1}

def save(p, s):
    json.dump(s, open(p, "w"))

def main():
    op = sys.argv[1]; state = sys.argv[2]; s = load(state)
    if op == "create":
        title, label, assignee = sys.argv[3], sys.argv[4], sys.argv[5]
        num = s["next"]; s["next"] += 1
        s["issues"].append({"number": num, "title": title, "label": label,
                             "assignee": assignee, "state": "open", "comments": []})
        save(state, s); print(num)
    elif op == "find":
        title = sys.argv[3]
        m = [i for i in s["issues"] if i["title"] == title and i["state"] == "open"]
        print(m[0]["number"] if m else "")
    elif op == "comment":
        num = int(sys.argv[3]); text = sys.argv[4]
        for i in s["issues"]:
            if i["number"] == num:
                i["comments"].append(text)
        save(state, s)
    elif op == "dump":
        json.dump(s, sys.stdout)

if __name__ == "__main__":
    main()
