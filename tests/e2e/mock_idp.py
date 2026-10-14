#!/usr/bin/env python3
"""A small OIDC provider for the end-to-end test, shaped like Authentik.

    mock_idp.py --port 19000 --client-id jellyfin --client-secret S --redirect-uri URL

Issuer http://127.0.0.1:<port>/application/o/jellyfin/ (per-app issuer, shared authorize
and token endpoints, as Authentik). Authorization code flow with PKCE S256 only; the
redirect URI must match exactly; client_secret_post or basic. The "logged-in" person is set
by the test: POST /_test/user {"sub": …, "username": …, "groups": […]}. RS256 ID tokens with
nonce, sub, preferred_username and groups. Only for tests: one key, everything in memory.
"""

import argparse
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Idp:
    def __init__(self, port, client_id, client_secret, redirect_uri):
        self.base = "http://127.0.0.1:%d" % port
        self.issuer = self.base + "/application/o/%s/" % client_id
        self.client_id, self.client_secret, self.redirect_uri = client_id, client_secret, redirect_uri
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "test-key"
        self.user = {"sub": "sub-alice", "username": "alice", "groups": ["residents"]}
        self.codes = {}

    def jwks(self):
        numbers = self.key.public_key().public_numbers()
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": b64url(n), "e": b64url(e)}]}

    def id_token(self, user, nonce):
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        body = {"iss": self.issuer, "aud": self.client_id, "sub": user["sub"], "iat": now, "nbf": now,
                "exp": now + 300, "nonce": nonce, "preferred_username": user["username"], "groups": user["groups"]}
        signing_input = b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(body).encode())
        signature = self.key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + b64url(signature)


def make_handler(idp):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002
            pass

        def reply(self, code, data, headers=None):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(url.query))
            if url.path == "/application/o/%s/.well-known/openid-configuration" % idp.client_id:
                self.reply(200, {
                    "issuer": idp.issuer,
                    "authorization_endpoint": idp.base + "/application/o/authorize/",
                    "token_endpoint": idp.base + "/application/o/token/",
                    "userinfo_endpoint": idp.base + "/application/o/userinfo/",
                    "jwks_uri": idp.base + "/application/o/%s/jwks/" % idp.client_id,
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                })
            elif url.path == "/application/o/%s/jwks/" % idp.client_id:
                self.reply(200, idp.jwks())
            elif url.path == "/application/o/authorize/":
                problems = []
                if q.get("client_id") != idp.client_id:
                    problems.append("client_id")
                if q.get("redirect_uri") != idp.redirect_uri:
                    problems.append("redirect_uri %r" % q.get("redirect_uri"))
                if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
                    problems.append("response_type/pkce")
                if not q.get("nonce") or not q.get("state"):
                    problems.append("nonce/state")
                if problems:
                    self.reply(400, {"error": "invalid_request", "problems": problems})
                    return
                code = secrets.token_urlsafe(24)
                idp.codes[code] = {"challenge": q["code_challenge"], "nonce": q["nonce"], "user": dict(idp.user),
                                   "redirect_uri": q["redirect_uri"]}
                target = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]})
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif url.path == "/_test/state":
                self.reply(200, {"user": idp.user, "codes": len(idp.codes)})
            else:
                self.reply(404, {"error": "not found"})

        def do_POST(self):
            url = urllib.parse.urlsplit(self.path)
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if url.path == "/_test/user":
                idp.user = json.loads(raw)
                self.reply(200, {"ok": True})
                return
            if url.path != "/application/o/token/":
                self.reply(404, {"error": "not found"})
                return
            form = dict(urllib.parse.parse_qsl(raw.decode()))
            client_id, client_secret = form.get("client_id"), form.get("client_secret")
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                client_id, _, client_secret = base64.b64decode(auth[6:]).decode().partition(":")
                client_id, client_secret = urllib.parse.unquote(client_id), urllib.parse.unquote(client_secret)
            if client_id != idp.client_id or client_secret != idp.client_secret:
                self.reply(401, {"error": "invalid_client"})
                return
            entry = idp.codes.pop(form.get("code", ""), None)
            if form.get("grant_type") != "authorization_code" or entry is None:
                self.reply(400, {"error": "invalid_grant"})
                return
            verifier = form.get("code_verifier", "")
            if b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
                self.reply(400, {"error": "invalid_grant", "error_description": "PKCE"})
                return
            if form.get("redirect_uri") != entry["redirect_uri"]:
                self.reply(400, {"error": "invalid_grant", "error_description": "redirect_uri"})
                return
            self.reply(200, {"access_token": secrets.token_urlsafe(24), "token_type": "Bearer", "expires_in": 300,
                             "id_token": idp.id_token(entry["user"], entry["nonce"])})

    return Handler


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-secret", required=True)
    p.add_argument("--redirect-uri", required=True)
    a = p.parse_args()
    idp = Idp(a.port, a.client_id, a.client_secret, a.redirect_uri)
    ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(idp)).serve_forever()


if __name__ == "__main__":
    main()
