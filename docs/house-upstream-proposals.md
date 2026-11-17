# Proposals for upstream (drafts)

What the house fork carries on top of be-nj/jellyfin-sso and would rather not carry. Each
has its own branch from `upstream/main` (HOUSE.md). Not sent yet: the owner submits them.
SECURITY.md asks for anything about reaching an account through a private advisory, so the
public-address fix goes that way; the others are ordinary issues, a pull request once the
maintainer wants the change.

---

## Advisory: the redirect URI follows the request's forwarded headers

*Private advisory (Security → Advisories → New), branch `fix/public-address`.*

**Summary.** The redirect URI the plugin sends to the provider is built from the request's
`Host`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-Prefix` (`Web/SsoAddress.cs`,
`Web/ForwardedPaths.cs`). Their shape is checked, but they are read from whoever sent the
request, as `ForwardedPaths` says itself.

**Impact.** `GET /sso/oidc/start/<id>` with `X-Forwarded-Host: attacker.example` yields an
authorize URL with `redirect_uri=https://attacker.example/sso/oidc/callback/<id>`. Where the
provider accepts that redirect URI (a wildcard or regex redirect URI, which Authentik and
Keycloak both allow), the attacker sends that authorize URL to a victim with a provider
session and receives the victim's code. The plugin redeems a code at its own callback with
the attacker's state and browser binding, so the attacker is signed in as the victim. With
an exact redirect URI registered, the provider refuses and what is left is the `Secure`
flag of the cookies and the links in the plugin's pages following the forged values.

**Versions.** 1.12.22 and earlier.

**Fix (proposed, branch `fix/public-address`).** A `PublicAddress` setting: when set, the
redirect URI, the cookies' `Secure` flag and the links come from it alone and the headers
are not read; empty, nothing changes. The documentation then advises setting it.

**Workaround.** Register the exact redirect URI at the provider, and have the reverse proxy
overwrite `X-Forwarded-*` rather than pass them through.

Written with the help of Claude Code (Claude Opus 5.5).

---

## Issue: settings from a file, for servers set up by configuration management

*Branch `feat/settings-file`.*

A server deployed with Ansible, NixOS or a compose file has its providers and group mappings
in version control, but the plugin only takes them through the configuration page or a
hand-made `POST /sso/admin/config`, which has to be repeated after every reinstall and
drifts from what the repository says.

Proposal: `JELLYFIN_SSO_SETTINGS_FILE` names a JSON file with the names of
`GET /sso/admin/config`. It is applied at startup, before the login buttons are written.
What it names wins over the page, which shows those settings disabled with a note; what it
leaves out stays editable. A file with any mistake (invalid JSON, a name that is not a
setting, a value the page would refuse) is not applied at all and the page says why; the
server keeps the configuration it had. Links and the remembered groups cannot be set this
way, and every provider in the file needs a fixed `Id`, since links refer to it.

The checks of the page's save move into one place so the file goes through the same ones.
About 300 lines with tests; we run it in production. Would you take a pull request?

Written with the help of Claude Code (Claude Opus 5.5).

---

## Issue: a group mapping for every library, without admin

*Branch `feat/all-libraries`.*

A mapping names its libraries by id. A group that should see everything has to be ticked
library by library, and misses every library created later; only administrators get all of
them. A mapping written outside the page (see the settings file above) cannot know the ids
at all.

Proposal: `AllLibraries` on a mapping, *All libraries, including ones added later* on the
card, granting through Jellyfin's own `EnableAllFolders`. Small change, one test. Would you
take a pull request?

Written with the help of Claude Code (Claude Opus 5.5).

---

## Issue: let the Quick Connect approval ask for the code

*Branch `feat/quick-connect-typed-code`.*

The approval takes the code from `/sso/oidc/start/qc?code=…` and asks the person to compare
it with their device. That comparison is the only check: a link somebody else sent, opened
by a person who is signed in at the provider, shows their code next to an *Approve* button,
and a click signs the sender's device in as the person. Jellyfin's own Quick Connect page
asks for the code instead.

Proposal: `TypeQuickConnectCode`, off by default so existing links keep working. On, the
approval page asks for the code the device shows and a code in the link is ignored. Would
you take a pull request?

Written with the help of Claude Code (Claude Opus 5.5).
