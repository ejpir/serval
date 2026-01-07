#!/usr/bin/env python3
# Chunked encoding test backend
# Responds with Transfer-Encoding: chunked

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class ChunkedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Send chunked response
        self.send_response(200)
        self.send_header('Transfer-Encoding', 'chunked')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        # Send multiple chunks
        chunks = [b'Hello ', b'from ', b'chunked ', b'backend!']
        for chunk in chunks:
            self.wfile.write(f'{len(chunk):x}\r\n'.encode())
            self.wfile.write(chunk)
            self.wfile.write(b'\r\n')
        # Last chunk
        self.wfile.write(b'0\r\n\r\n')
        self.wfile.flush()

    def do_POST(self):
        # Read request body and echo it back chunked
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        print(f'Received POST body: {body}', file=sys.stderr)

        self.send_response(200)
        self.send_header('Transfer-Encoding', 'chunked')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        # Echo body in chunks
        response = b'Received: ' + body
        chunk_size = 10
        for i in range(0, len(response), chunk_size):
            chunk = response[i:i+chunk_size]
            self.wfile.write(f'{len(chunk):x}\r\n'.encode())
            self.wfile.write(chunk)
            self.wfile.write(b'\r\n')
        self.wfile.write(b'0\r\n\r\n')
        self.wfile.flush()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
    server = HTTPServer(('127.0.0.1', port), ChunkedHandler)
    print(f'Chunked backend listening on :{port}')
    server.serve_forever()
