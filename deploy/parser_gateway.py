"""Private, single-job OCR accounting endpoint and Tika process supervisor.

Only the isolated parser container runs this module. It accepts bounded bytes,
never filenames or commands, and never logs request paths, document text or errors.
"""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
WORKER = Path('/opt/parser/page_ocr.py')
ACTIVE: set[subprocess.Popen] = set()


def worker_limits():
    # The worker also writes bounded raster files; stdout is checked separately.
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def stop_process(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def run_worker(input_path, kind, maximum, directory):
    output = directory / 'result.json'
    with output.open('wb') as stream:
        process = subprocess.Popen(
            [sys.executable, str(WORKER), '--input', str(input_path), '--kind', kind,
             '--max-text-chars', str(maximum)],
            stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.DEVNULL,
            start_new_session=True,
            preexec_fn=worker_limits,
            env={**os.environ, 'OMP_THREAD_LIMIT': '1', 'LC_ALL': 'C', 'LANG': 'C'},
        )
        ACTIVE.add(process)
        try:
            process.wait(timeout=58)
        finally:
            stop_process(process)
            ACTIVE.discard(process)
    if process.returncode != 0 or output.stat().st_size > MAX_OUTPUT_BYTES:
        raise ValueError('worker_failed')
    data = json.loads(output.read_bytes())
    if not isinstance(data, dict):
        raise ValueError('worker_failed')
    return data


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.respond(code, {'error': 'invalid_request'})

    def respond(self, status, value):
        encoded = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        self.close_connection = True

    def do_GET(self):
        self.respond(200, {'status': 'ok'}) if self.path == '/health' else self.respond(404, {'error': 'not_found'})

    def do_PUT(self):
        if self.path not in {'/v1/pdf', '/v1/image'}:
            self.respond(404, {'error': 'not_found'})
            return
        lengths = self.headers.get_all('Content-Length', [])
        if self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not lengths[0].isdigit():
            self.respond(400, {'error': 'invalid_length'})
            return
        size = int(lengths[0])
        if not 0 < size <= MAX_INPUT_BYTES:
            self.respond(413, {'error': 'input_size_limit'})
            return
        try:
            limit_text = self.headers.get('X-Max-Text-Chars', '1000000')
            maximum = int(limit_text)
            if not 1 <= maximum <= 1_000_000:
                raise ValueError('limit')
        except (TypeError, ValueError):
            self.respond(400, {'error': 'invalid_limit'})
            return
        try:
            # All request bytes and child output live in a private tmpfs directory.
            with tempfile.TemporaryDirectory(prefix='ocr-', dir='/tmp') as name:
                directory = Path(name)
                input_path = directory / 'input.bin'
                remaining = size
                with input_path.open('wb') as stream:
                    while remaining:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            raise ValueError('truncated_input')
                        stream.write(chunk)
                        remaining -= len(chunk)
                result = run_worker(input_path, self.path.rsplit('/', 1)[1], maximum, directory)
            self.respond(200, result)
        except Exception:
            # Do not include subprocess output, patient text or client filenames.
            self.respond(502, {'error': 'accounting_worker_failed'})


class Server(http.server.HTTPServer):
    # Single active request bounds jobs, threads, memory and temporary storage.
    request_queue_size = 4
    timeout = 1

    def handle_error(self, request, client_address):
        pass


def main():
    os.umask(0o077)
    tika = subprocess.Popen(
        ['java', '-Dlog4j.configurationFile=/opt/tika/log4j2.xml', '-jar', '/opt/tika/server.jar',
         '--host', '0.0.0.0', '--config', '/opt/tika/tika-config.xml'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    ACTIVE.add(tika)

    def terminate(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        with Server(('0.0.0.0', 9997), Handler) as server:
            while tika.poll() is None:
                server.handle_request()
        return 1
    finally:
        for process in list(ACTIVE):
            stop_process(process)
        ACTIVE.clear()


if __name__ == '__main__':
    sys.exit(main())
