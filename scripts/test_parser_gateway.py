"""The isolated endpoint must bound uploads/jobs and keep parse failures private."""
import importlib.util
import json
from pathlib import Path
import socket
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

SPEC = importlib.util.spec_from_file_location('parser_gateway', Path(__file__).parents[1] / 'deploy/parser_gateway.py')
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)


@pytest.fixture
def server(monkeypatch):
    server = gateway.Server(('127.0.0.1', 0), gateway.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def call(url, data=b'PDF SYNTHETIC SENSITIVE', headers=None):
    try:
        response = urlopen(Request(url, data=data, method='PUT', headers=headers or {}), timeout=3)
    except HTTPError as response:
        return response.code, json.loads(response.read()), response.headers
    with response:
        return response.status, json.loads(response.read()), response.headers


def test_endpoint_passes_only_local_bytes_and_cleans_directory(server, monkeypatch):
    paths = []
    def worker(path, kind, limit, directory):
        assert path.read_bytes() == b'PDF SYNTHETIC SENSITIVE'
        assert kind == 'pdf' and limit == 19
        paths.extend([path, directory])
        return {'protocol': 'parser-accounting/v1', 'units': []}
    monkeypatch.setattr(gateway, 'run_worker', worker)
    status, data, headers = call(server+'/v1/pdf', headers={'X-Max-Text-Chars': '19'})
    assert status == 200 and data['protocol'] == 'parser-accounting/v1'
    assert headers['Cache-Control'] == 'no-store'
    assert all(not path.exists() for path in paths)


def test_worker_failure_returns_fixed_message_and_cleans_files(server, monkeypatch, capsys):
    paths = []
    def worker(path, kind, limit, directory):
        paths.append(directory)
        raise ValueError('PRIVATE MRN VALUE IN PARSER ERROR')
    monkeypatch.setattr(gateway, 'run_worker', worker)
    status, data, headers = call(server+'/v1/image')
    assert status == 502 and data == {'error': 'accounting_worker_failed'}
    assert all(not path.exists() for path in paths)
    assert 'PRIVATE' not in capsys.readouterr().err


@pytest.mark.parametrize('path,limit,expected', [
    ('/v1/pdf?url=http://outside.test', '12', 404),
    ('/v1/pdf', '0', 400), ('/v1/pdf', '1000001', 400),
    ('/v1/pdf', '-1', 400), ('/v1/pdf', 'not-int', 400),
])
def test_unapproved_targets_and_limits_rejected_before_worker(server, monkeypatch, path, limit, expected):
    monkeypatch.setattr(gateway, 'run_worker', lambda *args: pytest.fail('Worker must not start'))
    assert call(server+path, headers={'X-Max-Text-Chars': limit})[0] == expected


def test_oversized_length_rejected_without_reading_body(server, monkeypatch):
    monkeypatch.setattr(gateway, 'run_worker', lambda *args: pytest.fail('Worker must not start'))
    port = int(server.rsplit(':', 1)[1])
    with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
        connection.sendall(b'PUT /v1/pdf HTTP/1.0\r\nContent-Length: 999999999\r\n\r\n')
        assert b'413' in connection.recv(4096)


def test_chunked_and_duplicate_lengths_are_rejected(server, monkeypatch):
    monkeypatch.setattr(gateway, 'run_worker', lambda *args: pytest.fail('Worker must not start'))
    port = int(server.rsplit(':', 1)[1])
    for headers in [b'Content-Length: 3\r\nContent-Length: 3', b'Transfer-Encoding: chunked']:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
            connection.sendall(b'PUT /v1/pdf HTTP/1.0\r\n'+headers+b'\r\n\r\n')
            assert b'400' in connection.recv(4096)
