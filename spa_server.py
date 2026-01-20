#!/usr/bin/env python3
import http.server
import socketserver
import os
import urllib.request
import urllib.error

PORT = 8888
DIRECTORY = "/home/ubuntu/sentinela-ti/frontend/dist"
BACKEND_URL = "http://localhost:3001"

class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def do_GET(self):
        # Proxy para API
        if self.path.startswith('/api'):
            return self.proxy_request('GET')
        
        # Se o arquivo existe, serve normalmente
        path = self.translate_path(self.path)
        if os.path.exists(path) and os.path.isfile(path):
            return super().do_GET()
        
        # Se é um diretório com index.html, serve normalmente
        if os.path.isdir(path):
            index_path = os.path.join(path, 'index.html')
            if os.path.exists(index_path):
                return super().do_GET()
        
        # Caso contrário, serve index.html (SPA fallback)
        self.path = '/index.html'
        return super().do_GET()
    
    def do_POST(self):
        if self.path.startswith('/api'):
            return self.proxy_request('POST')
        self.send_error(404)
    
    def do_PUT(self):
        if self.path.startswith('/api'):
            return self.proxy_request('PUT')
        self.send_error(404)
    
    def do_DELETE(self):
        if self.path.startswith('/api'):
            return self.proxy_request('DELETE')
        self.send_error(404)
    
    def do_PATCH(self):
        if self.path.startswith('/api'):
            return self.proxy_request('PATCH')
        self.send_error(404)
    
    def proxy_request(self, method):
        try:
            url = f"{BACKEND_URL}{self.path}"
            
            # Ler corpo da requisição se houver
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Criar requisição
            req = urllib.request.Request(url, data=body, method=method)
            
            # Copiar headers relevantes
            for header in ['Content-Type', 'Authorization', 'Accept']:
                if header in self.headers:
                    req.add_header(header, self.headers[header])
            
            # Fazer requisição
            with urllib.request.urlopen(req, timeout=30) as response:
                self.send_response(response.status)
                
                # Copiar headers da resposta
                for header, value in response.getheaders():
                    if header.lower() not in ['transfer-encoding', 'connection']:
                        self.send_header(header, value)
                self.end_headers()
                
                # Enviar corpo
                self.wfile.write(response.read())
                
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"error": "{str(e)}"}}'.encode())

# Permitir reutilização da porta
class ReuseAddrTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReuseAddrTCPServer(("0.0.0.0", PORT), SPAHandler) as httpd:
    print(f"Servidor SPA com proxy rodando na porta {PORT}")
    httpd.serve_forever()
