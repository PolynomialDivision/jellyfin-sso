#!/usr/bin/env python3
"""End-to-end test of the plugin in a real Jellyfin against tests/e2e/mock_idp.py (run.sh).

Plays the browser with plain HTTP (redirects followed by hand) and checks the login paths
and the refusals: web login, single-use secret, Quick Connect by typed code only, no access
without a mapped group, no takeover of a local account, a disabled user stays disabled,
forged forwarding headers do not change the callback, the login button, the managed file.
"""

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

JF = "http://127.0.0.1:8096"
IDP = "http://127.0.0.1:19000"
CLIENT = 'MediaBrowser Client="e2e", Device="e2e", DeviceId="e2e-device", Version="1.0"'
ADMIN = ("jellyfin-admin", "admin-password-for-the-test")
failures = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def http(method, url, body=None, headers=None, form=None):
    data, hdrs = None, dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def check(name, ok, detail: object = ""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  -> " + str(detail)[:400]))
    if not ok:
        failures.append(name)


def token_header(token):
    return {"Authorization": CLIENT + ', Token="%s"' % token}


def set_user(sub, username, groups):
    http("POST", IDP + "/_test/user", {"sub": sub, "username": username, "groups": groups})


def sso_login(start="/sso/oidc/start", extra_headers=None):
    """Browser path up to the page the callback returns: (status, body, authorize URL)."""
    status, headers, body = http("GET", JF + start, headers=extra_headers)
    if status != 302:
        return status, body, None
    authorize = headers["Location"]
    status, headers, body = http("GET", authorize)
    if status != 302:
        return status, body, authorize
    callback = headers["Location"]
    status, headers, body = http("GET", callback)
    return status, body, authorize


def credentials_from_page(body):
    m = re.search(r'Username: ("(?:[^"\\]|\\.)*"), Pw: ("(?:[^"\\]|\\.)*")', body)
    return (json.loads(m.group(1)), json.loads(m.group(2))) if m else (None, None)


def authenticate(username, password):
    return http("POST", JF + "/Users/AuthenticateByName", {"Username": username, "Pw": password},
                headers={"Authorization": CLIENT})


def main():
    # --- Jellyfin's first-run wizard, through its API
    http("POST", JF + "/Startup/Configuration", {"UICulture": "en-US", "MetadataCountryCode": "DE",
                                                 "PreferredMetadataLanguage": "de"})
    http("GET", JF + "/Startup/User")
    http("POST", JF + "/Startup/User", {"Name": ADMIN[0], "Password": ADMIN[1]})
    http("POST", JF + "/Startup/Complete")
    status, _, body = authenticate(*ADMIN)
    check("local admin can log in with its password", status == 200, body)
    admin = token_header(json.loads(body)["AccessToken"]) if status == 200 else {}

    def users():
        return {u["Name"]: u for u in json.loads(http("GET", JF + "/Users", headers=admin)[2])}

    # --- the login button and the managed settings
    branding = json.loads(http("GET", JF + "/Branding/Configuration")[2])
    check("login button points at the provider", 'href="/sso/oidc/start/authentik"' in branding.get("LoginDisclaimer", ""),
          branding)
    status, _, _ = http("POST", JF + "/sso/admin/config", {"Providers": []}, headers=admin)
    check("dashboard cannot change managed settings", status == 409, status)
    status, _, _ = http("GET", JF + "/sso/admin/config")
    check("admin API needs a login", status in (401, 403), status)

    # --- web login of a resident: a new user, no admin, all libraries
    set_user("sub-alice", "alice", ["residents"])
    status, body, authorize = sso_login(extra_headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"})
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(authorize or "").query))
    check("callback URL ignores forged forwarding headers",
          q.get("redirect_uri") == JF + "/sso/oidc/callback/authentik", q.get("redirect_uri"))
    check("authorize request uses PKCE S256 and a nonce",
          q.get("code_challenge_method") == "S256" and len(q.get("nonce", "")) >= 40, q)
    username, secret = credentials_from_page(body)
    check("callback page carries a one-time login", username == "alice" and secret, body[:300])
    status, _, auth_body = authenticate(username, secret)
    check("one-time login gives a Jellyfin token", status == 200, auth_body)
    status, _, _ = authenticate(username, secret)
    check("one-time login works only once", status == 401, status)
    status, _, _ = authenticate("alice", "a guessed password")
    check("SSO user has no password login", status == 401, status)
    alice = users().get("alice", {})
    policy = alice.get("Policy", {})
    check("resident is no admin and sees all libraries",
          policy.get("IsAdministrator") is False and policy.get("EnableAllFolders") is True, policy)

    # --- the same person again: the link, not a second user
    set_user("sub-alice", "alice", ["residents", "it-admins"])
    status, body, _ = sso_login()
    username, secret = credentials_from_page(body)
    check("second login uses the link", username == "alice" and len([u for u in users() if u.startswith("alice")]) == 1)
    check("admin flag follows the groups", users()["alice"]["Policy"]["IsAdministrator"] is True)

    # --- an admin's change in Jellyfin survives the next login (Jellyfin refuses to disable
    # an administrator, so alice is a plain resident again first)
    set_user("sub-alice", "alice", ["residents"])
    sso_login()
    check("admin flag is taken away with the group", users()["alice"]["Policy"]["IsAdministrator"] is False)
    pol = users()["alice"]["Policy"]
    pol["IsDisabled"] = True
    status, _, _ = http("POST", JF + "/Users/%s/Policy" % alice["Id"], pol, headers=admin)
    check("admin can disable alice", status in (200, 204), status)
    status, body, _ = sso_login()
    username, secret = credentials_from_page(body)
    status, _, _ = authenticate(username or "alice", secret or "x")
    check("disabled user stays disabled after an SSO login",
          status != 200 and users()["alice"]["Policy"]["IsDisabled"] is True, status)
    pol = users()["alice"]["Policy"]
    pol["IsDisabled"] = False
    http("POST", JF + "/Users/%s/Policy" % alice["Id"], pol, headers=admin)

    # --- no mapped group: refused, nobody created
    set_user("sub-mallory", "mallory", ["vpn-users"])
    status, body, _ = sso_login()
    check("login without a mapped group is refused", status == 400 and "no access" in body, (status, body[:200]))
    check("refused login creates no user", "mallory" not in users())

    # --- an IdP account named like a local account does not take it over
    set_user("sub-evil", ADMIN[0], ["residents", "it-admins"])
    status, body, _ = sso_login()
    check("IdP user named like the local admin is refused", status == 400 and credentials_from_page(body)[0] is None,
          (status, body[:200]))
    status, _, _ = authenticate(*ADMIN)
    check("local admin still logs in with its password", status == 200, status)

    # --- state: replayed and unknown callbacks
    set_user("sub-alice", "alice", ["residents"])
    status, headers, _ = http("GET", JF + "/sso/oidc/start")
    status, headers, _ = http("GET", headers["Location"])
    callback = headers["Location"]
    first = http("GET", callback)[0]
    second = http("GET", callback)[0]
    check("a callback works once", first == 200 and second == 400, (first, second))
    status, _, _ = http("GET", JF + "/sso/oidc/callback/authentik?code=x&state=guessed")
    check("unknown state is refused", status == 400, status)

    # --- Quick Connect: never from a link, only by typing the code
    status, _, body = http("POST", JF + "/QuickConnect/Initiate", headers={"Authorization": CLIENT})
    check("Quick Connect can be started", status == 200, body)
    qc = json.loads(body) if status == 200 else {"Code": "000000", "Secret": "x"}
    status, _, body = http("GET", JF + "/sso/oidc/start/qc?code=" + qc["Code"])
    check("a Quick Connect code in a link is refused", status == 400 and "never accepted" in body, (status, body[:200]))
    status, body, _ = sso_login("/sso/oidc/start/qc")
    m = re.search(r'name="token" value="([0-9A-F]+)"', body)
    check("Quick Connect login shows the code form", status == 200 and m, body[:300])
    token = m.group(1) if m else ""
    status, _, body = http("POST", JF + "/sso/oidc/quickconnect", form={"token": token, "code": "999999"})
    check("a wrong code is refused", status == 400, (status, body[:200]))
    status, _, body = http("POST", JF + "/sso/oidc/quickconnect", form={"token": token, "code": qc["Code"]})
    check("the token is single use (also after a wrong code)", status == 400, (status, body[:200]))
    status, body, _ = sso_login("/sso/oidc/start/qc")
    token = re.search(r'name="token" value="([0-9A-F]+)"', body).group(1)
    status, _, body = http("POST", JF + "/sso/oidc/quickconnect", form={"token": token, "code": qc["Code"]})
    check("the typed code approves the device", status == 200 and "approved" in body, (status, body[:200]))
    status, _, body = http("GET", JF + "/QuickConnect/Connect?secret=" + qc["Secret"])
    check("the device sees the approval", status == 200 and json.loads(body).get("Authenticated") is True, body)
    status, _, body = http("POST", JF + "/Users/AuthenticateWithQuickConnect", {"Secret": qc["Secret"]},
                           headers={"Authorization": CLIENT})
    check("the device gets a token for alice", status == 200 and json.loads(body)["User"]["Name"] == "alice", body[:200])

    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
