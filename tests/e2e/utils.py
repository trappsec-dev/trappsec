import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class AlertHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data)
            self.server.alerts.append(data)
        except:
            pass
        
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        pass

class AlertServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.alerts = []

    def clear(self):
        self.alerts = []
    
    def get_alerts_for_agent(self, user_agent):
        return [a for a in self.alerts if a.get("user_agent") == user_agent]
