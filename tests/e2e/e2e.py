#!/usr/bin/env python3
"""End-to-end test of the plugin in a real Jellyfin against tests/e2e/mock_idp.py (run.sh).

Plays the browser with plain HTTP (redirects followed by hand) and checks the login paths
and the refusals: web login, single-use secret, Quick Connect by typed code only, no access
without a mapped group, no takeover of a local account, a disabled user stays disabled,
forged forwarding headers do not change the callback, the login button, the managed file.
Then the enforcement (managed "Enforcement" section, rounds every 3 s): the directory feed
disables, enables and (de)promotes linked users, a stale feed changes nothing, a disable by
hand stays, unmanaged accounts and stray API keys go, the break-glass account follows the
managed file, the network settings are set with one restart.
"""

import datetime
import json
import os
import re
import subprocess
import sys
import time
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
    css = http("GET", JF + "/Branding/Css")[2]
    check("login style is served once", css.count("/* jellyfin-sso:start") == 1 and "#loginPage" in css, css[:200])
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

    # A new password login replaces the token of the same user and device (Jellyfin), so the
    # admin token from the start was logged out by "local admin still logs in" above.
    status, _, body = authenticate(*ADMIN)
    enforcement(token_header(json.loads(body)["AccessToken"]) if status == 200 else {})

    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


# --- enforcement --------------------------------------------------------------------------

MANAGED = os.environ.get("E2E_MANAGED", "")
FEED = os.environ.get("E2E_FEED", "")
CONTAINER = os.environ.get("E2E_CONTAINER", "jellyfin-sso-e2e")
ROUND = 3  # IntervalSeconds in run.sh


def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def write_feed(allowed, admins, age=0):
    generated = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=age)
    write_atomic(FEED, json.dumps({"version": 1, "generated_at": generated.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                   "allowed": allowed, "admins": admins}))


def set_break_glass(enabled):
    with open(MANAGED) as f:
        cfg = json.load(f)
    cfg["Enforcement"]["BreakGlass"]["Enabled"] = enabled
    write_atomic(MANAGED, json.dumps(cfg, indent=2))


def wait_for(predicate, timeout=8 * ROUND):
    """True as soon as predicate() is; False after the timeout."""
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.5)
    return predicate()


def me(token):
    status, _, body = http("GET", JF + "/Users/Me", headers=token_header(token))
    return status, (json.loads(body) if status == 200 else {})


def web_login(sub, username, groups):
    """SSO web login through the mock IdP: (status of the token request, access token)."""
    set_user(sub, username, groups)
    _, body, _ = sso_login()
    user, secret = credentials_from_page(body)
    status, _, auth_body = authenticate(user or username, secret or "x")
    return status, (json.loads(auth_body)["AccessToken"] if status == 200 else None)


def startups():
    out = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True, check=False)
    return (out.stdout + out.stderr).count("Startup complete")


def enforcement(admin):
    def users(hdr=None):
        return {u["Name"]: u for u in json.loads(http("GET", JF + "/Users", headers=hdr or admin)[2])}

    def policy(name, hdr=None):
        return users(hdr).get(name, {}).get("Policy", {})

    resident = ["residents"]

    # --- no feed yet: the local rules only
    status, _, body = http("POST", JF + "/Users/New", {"Name": "local-extra", "Password": "pw"}, headers=admin)
    check("admin can create a local account", status == 200, (status, body[:200]))
    check("an unmanaged local account is disabled",
          wait_for(lambda: policy("local-extra").get("IsDisabled") is True), policy("local-extra"))
    check("without a feed a linked user is left alone", policy("alice").get("IsDisabled") is False, policy("alice"))
    check("break-glass account may log in only from the local networks",
          policy(ADMIN[0]).get("EnableRemoteAccess") is False and policy(ADMIN[0]).get("IsAdministrator") is True,
          policy(ADMIN[0]))

    # --- network settings: as configured, after exactly one restart
    status, _, body = http("GET", JF + "/System/Configuration/network", headers=admin)
    net = json.loads(body) if status == 200 else {}
    check("network settings are the configured ones",
          net.get("KnownProxies") == ["10.251.8.2"]
          and sorted(net.get("LocalNetworkSubnets", [])) == ["10.0.0.0/24", "10.0.10.0/24"]
          and net.get("EnableRemoteAccess") is True, net)
    check("Jellyfin restarted once for the KnownProxies", startups() == 2, startups())

    # --- carol (admin by group) and alice log in; then a feed with both
    status, carol = web_login("sub-carol", "carol", ["residents", "it-admins"])
    check("carol logs in via SSO as administrator", status == 200 and me(carol)[1].get("Policy", {}).get("IsAdministrator"),
          status)
    carol_hdr = token_header(carol or "")
    status, alice = web_login("sub-alice", "alice", resident)
    check("alice logs in via SSO", status == 200, status)
    time.sleep(1.1)  # the feed must be newer than these logins
    write_feed(["sub-alice", "sub-carol"], ["sub-carol"])
    time.sleep(2 * ROUND)
    check("a feed with everyone changes nobody",
          me(alice)[0] == 200 and policy("alice").get("IsDisabled") is False and policy("carol").get("IsAdministrator"),
          (me(alice)[0], policy("alice"), policy("carol")))

    # --- (a) alice removed from the feed: her token stops working, she is disabled
    write_feed(["sub-carol"], ["sub-carol"])
    check("removed from the feed: the existing token gets 401", wait_for(lambda: me(alice)[0] == 401), me(alice)[0])
    check("removed from the feed: the user is disabled", policy("alice").get("IsDisabled") is True, policy("alice"))

    # --- (c) a stale or future feed that lists alice again changes nothing
    write_feed(["sub-alice", "sub-carol"], ["sub-carol"], age=3600)
    time.sleep(3 * ROUND)
    check("a stale feed changes nothing", policy("alice").get("IsDisabled") is True, policy("alice"))
    write_feed(["sub-alice", "sub-carol"], ["sub-carol"], age=-3600)
    time.sleep(3 * ROUND)
    check("a feed from the future changes nothing", policy("alice").get("IsDisabled") is True, policy("alice"))

    # --- (b) back in the feed: enabled again, a new SSO login works
    write_feed(["sub-alice", "sub-carol"], ["sub-carol"])
    check("back in the feed: the user is enabled", wait_for(lambda: policy("alice").get("IsDisabled") is False),
          policy("alice"))
    status, alice = web_login("sub-alice", "alice", resident)
    check("back in the feed: a new SSO login works", status == 200 and me(alice)[0] == 200, status)

    # --- a fresh SSO login enables a user the enforcement disabled, and outweighs the older feed
    time.sleep(1.1)
    write_feed(["sub-carol"], ["sub-carol"])
    check("removed again: disabled", wait_for(lambda: policy("alice").get("IsDisabled") is True), policy("alice"))
    status, alice = web_login("sub-alice", "alice", resident)
    check("a fresh SSO login enables a user the enforcement disabled", status == 200, status)
    time.sleep(3 * ROUND)
    check("a login newer than the feed outweighs it", me(alice)[0] == 200 and policy("alice").get("IsDisabled") is False,
          (me(alice)[0], policy("alice")))
    time.sleep(1.1)
    write_feed(["sub-alice", "sub-carol"], ["sub-carol"])

    # --- (i) a user disabled by hand stays disabled although the feed lists it
    pol = policy("alice")
    pol["IsDisabled"] = True
    status, _, _ = http("POST", JF + "/Users/%s/Policy" % users()["alice"]["Id"], pol, headers=admin)
    check("admin can disable alice by hand", status in (200, 204), status)
    time.sleep(3 * ROUND)
    check("a user disabled by hand stays disabled while in the feed", policy("alice").get("IsDisabled") is True,
          policy("alice"))
    status, _ = web_login("sub-alice", "alice", resident)
    time.sleep(2 * ROUND)
    check("an SSO login does not enable a user disabled by hand",
          status != 200 and policy("alice").get("IsDisabled") is True, (status, policy("alice")))
    pol = policy("alice")
    pol["IsDisabled"] = False
    http("POST", JF + "/Users/%s/Policy" % users()["alice"]["Id"], pol, headers=admin)

    # --- (e) API keys: only allowed names survive
    for app in ("rogue-key", "house-monitoring"):
        status, _, _ = http("POST", JF + "/Auth/Keys?app=" + app, headers=admin)
        check("admin can create API key " + app, status in (200, 204), status)

    def key_names():
        return sorted(k["AppName"] for k in json.loads(http("GET", JF + "/Auth/Keys", headers=admin)[2])["Items"])
    check("an API key with a name not allowed is deleted", wait_for(lambda: key_names() == ["house-monitoring"]),
          key_names())

    # --- (f) break-glass off: no password login, its token is gone; on again: it works locally
    set_break_glass(False)
    check("break-glass off: its token gets 401", wait_for(lambda: http("GET", JF + "/Users/Me", headers=admin)[0] == 401))
    status, _, _ = authenticate(*ADMIN)
    bg = policy(ADMIN[0], carol_hdr)
    check("break-glass off: password login fails, the account stays administrator",
          status != 200 and bg.get("IsDisabled") is True and bg.get("IsAdministrator") is True, (status, bg))
    set_break_glass(True)
    check("break-glass on: password login from loopback works", wait_for(lambda: authenticate(*ADMIN)[0] == 200))

    # --- (d) admin flag removed via the feed: the token stays valid, the flag goes
    time.sleep(1.1)
    write_feed(["sub-alice", "sub-carol"], [])
    check("admin removed in the feed: token valid, no administrator",
          wait_for(lambda: me(carol or "")[0] == 200 and me(carol or "")[1].get("Policy", {}).get("IsAdministrator") is False),
          me(carol or ""))
    check("no further restart", startups() == 2, startups())


if __name__ == "__main__":
    sys.exit(main())
