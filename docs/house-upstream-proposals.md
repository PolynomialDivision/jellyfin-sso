# Proposals for upstream

What the house fork proposed to be-nj/jellyfin-sso (pull request #295, 2026-11-17), and what
came of it.

| Proposal | Upstream |
|---|---|
| `AllLibraries` per group mapping | taken: #299 (2026-11-18) |
| `PublicAddress`: redirect URI, cookies and links from it, not from request headers | taken: #303, plus a login opened at another address is sent to the public address first |
| Quick Connect code no device waits with: an answer, not a 404 | taken: #301, also a code approved already |
| `TypeQuickConnectCode`: the approval asks for the code | taken: #305, plus three tries per sign-in |
| Settings from a file (`JELLYFIN_SSO_SETTINGS_FILE`) | **declined** (2026-11-18): "a second configuration path to keep in step with every new setting, and so far one person has asked for it". The maintainer would look again given an issue that describes the setup and others with the same need. |

So the settings file is house-only now (HOUSE.md). Should others ask for it, the issue below
is the text to start from; it describes the house's commit, which follows upstream's
`ConfigurationRules` since the rebase of 2026-11-18.

---

## Issue: settings from a file, for servers set up by configuration management

*Commit "Read the settings from a file" on `house`.*

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
