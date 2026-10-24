#!/usr/bin/env python3
# Minimal SMTP sink for lab tests (lockdown.sh: the new-device notice): accepts every message and appends it to
# the log file (no relay, no auth). Usage: smtp-sink.py PORT LOG; run it on a lab VM, point Settings -> Alert delivery
# at it for the test and back afterwards.
import socketserver, sys, time

LOG = sys.argv[2] if len(sys.argv) > 2 else "mail.log"

class H(socketserver.StreamRequestHandler):
    def w(self, s):
        self.wfile.write((s + "\r\n").encode())

    def handle(self):
        self.w("220 lab-sink ESMTP")
        data, mail = False, []
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data:
                if line == ".":
                    with open(LOG, "a") as f:
                        f.write(f"--- {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n" + "\n".join(mail) + "\n")
                    data, mail = False, []
                    self.w("250 queued")
                else:
                    mail.append(line)
                continue
            cmd = line[:4].upper()
            if cmd in ("EHLO", "HELO"):
                self.w("250 lab-sink")
            elif cmd == "DATA":
                data = True
                self.w("354 go on")
            elif cmd == "QUIT":
                self.w("221 bye")
                return
            else:
                self.w("250 ok")

socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
