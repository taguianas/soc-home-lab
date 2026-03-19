from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.request

THEHIVE_URL = "http://thehive:9000/api/v1/alert"
THEHIVE_API_KEY = "pOMxZSAmLaVwhDeQ1uesvn/0r2YC7xoA"

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        rule = body.get("rule", {})
        agent = body.get("agent", {})
        srcip = body.get("srcip", "unknown")

        alert = {
            "title": f"Wazuh Alert: {rule.get('description', 'Unknown')}",
            "description": f"Agent: {agent.get('name','unknown')}\nSource IP: {srcip}\nRule ID: {rule.get('id','N/A')}\nLevel: {rule.get('level','N/A')}",
            "type": "external",
            "source": "wazuh",
            "sourceRef": f"wazuh-{rule.get('id','0')}-{srcip}",
            "severity": 2 if rule.get("level", 0) < 12 else 3,
            "tags": ["wazuh", "automated"]
        }

        req = urllib.request.Request(
            THEHIVE_URL,
            data=json.dumps(alert).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {THEHIVE_API_KEY}"
            }
        )
        try:
            resp = urllib.request.urlopen(req)
            print(f"[OK] Alert created: {alert['title']}")
        except Exception as e:
            print(f"[ERR] Failed: {e}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": True}).encode())

print("SOC Bridge listening on port 5555...")
HTTPServer(("0.0.0.0", 5555), WebhookHandler).serve_forever()
