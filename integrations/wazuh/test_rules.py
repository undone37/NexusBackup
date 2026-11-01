#!/usr/bin/python3 -I
"""Offline check of the Wazuh decoder and rules (integrations/wazuh/README.md): both files parse, rule ids are
unique and in 110100..110199, and every line of samples.log ends in the rule its `# rule <id>` comment names.

The matcher is a small model of Wazuh's: a line whose program name the decoder accepts is decoded as JSON; from
the rules with <decoded_as>, the first child (file order) whose conditions all hold is taken, repeatedly. It
covers what these rules use (<decoded_as>, <if_sid>, pcre2 <field> and <action>); the real check is
`wazuh-logtest` on a manager (lab)."""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d (\S+) ([^:\s]+): (.*)$")


def load(name):
    # Wazuh files hold several top-level elements: parse them inside one root
    with open(os.path.join(HERE, name)) as f:
        return ET.fromstring("<root>" + f.read() + "</root>")


def decoder():
    d = load("nexusbackup_decoders.xml").find("decoder")
    assert d.get("name") == "nexusbackup" and d.findtext("plugin_decoder") == "JSON_Decoder"
    return d.get("name"), re.compile(d.findtext("program_name"))


def rules():
    out = [r for g in load("nexusbackup_rules.xml") for r in g.findall("rule")]
    ids = [r.get("id") for r in out]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    assert all(110100 <= int(i) <= 110199 for i in ids), ids
    for r in out:
        for c in r:
            assert c.tag in ("decoded_as", "if_sid", "field", "action", "description", "group"), c.tag
            if c.tag in ("field", "action"):
                assert c.get("type") == "pcre2", f"rule {r.get('id')}: pcre2 expected"
    return out


def holds(rule, fields):
    for c in rule:
        if c.tag in ("field", "action"):
            v = fields.get(c.get("name") if c.tag == "field" else "action")
            if not isinstance(v, str) or not re.search(c.text, v):
                return False
    return True


def match(line, dec, rs):
    name, prog = dec
    m = HEADER.match(line)
    if not m or not prog.search(m.group(2)):
        return None
    fields = json.loads(m.group(3))
    cur = next((r for r in rs if r.findtext("decoded_as") == name and holds(r, fields)), None)
    while cur is not None:
        nxt = next(
            (r for r in rs if r.findtext("if_sid") == cur.get("id") and holds(r, fields)),
            None,
        )
        if nxt is None:
            return cur.get("id")
        cur = nxt
    return None


def main():
    dec, rs = decoder(), rules()
    want, n = None, 0
    with open(os.path.join(HERE, "samples.log")) as f:
        for line in f.read().splitlines():
            if line.startswith("# rule "):
                want = line.split()[2]
            elif line and not line.startswith("#"):
                got = match(line, dec, rs)
                assert got == want, f"{got} != {want}: {line[:100]}"
                n += 1
    assert match("Nov  1 12:00:00 nb1 sshd: {}", dec, rs) is None, "other programs are not ours"
    assert n >= 10
    print(f"wazuh: {len(rs)} rules, {n} samples ok")


if __name__ == "__main__":
    sys.exit(main())
