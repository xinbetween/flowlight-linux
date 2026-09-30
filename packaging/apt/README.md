# The apt repository

Three files build it and one secret publishes it.

| | |
| --- | --- |
| `build.sh` | A directory of `.deb` files in, a servable archive out: pool, `Packages` per architecture, `Release`. Needs coreutils, `ar` and `gzip`, and nothing else — which is why CI can run it on every change. |
| `sign.sh` | Clearsigns `Release` into `InRelease`, writes `Release.gpg` beside it, and exports the public key to the archive root. Signs with whatever keyring `gpg` is pointed at and never reads a key out of a file itself. |
| `index.html` | The page at the root of the site, because the address people paste first should not be a 404. `@VERSION@` and `@FINGERPRINT@` are filled in by the two scripts. |

`.github/workflows/apt.yml` runs them: it collects the `.deb` assets from the newest release, builds the
archive, **proves it works with a throwaway key it generates and discards**, and then — only if the repository
has a `GPG_SIGNING_KEY` — signs the real one and deploys it to GitHub Pages.

It runs **after the `Release` workflow finishes**, not when the release is published. A release exists for
several minutes before it has any packages attached, because attaching them is the last thing `Release` does —
so triggering on the release itself meant this ran, found nothing to serve, and stopped. Dispatching it by hand
with a tag works at any time, which is what to do when a release needed a second attempt.

The proof is the part worth keeping. It generates a key, signs a copy of the archive, adds it to `apt` over
`file://` with `signed-by`, runs `apt-get update` and installs `flowlight` from it. That runs on every dispatch
whether or not a real key exists, so the machinery is known to work before it is ever asked to publish, and a
malformed `Release` is a red check rather than a broken `apt-get update` on somebody's machine.

## The key is yours to make

Nobody else should make it, including whoever is writing this code: the signing key *is* the trust people are
being asked to extend, and a key that arrived from somewhere else is not that.

```sh
# A signing-only key with no expiry date to forget about. Give it a passphrase you keep, then export it
# unprotected only for the moment it takes to paste it into a secret — or better, make a second key for CI.
gpg --quick-generate-key "Flowlight Archive <you@example.com>" ed25519 sign never

gpg --list-secret-keys --keyid-format=long     # note the fingerprint
gpg --armor --export-secret-keys <fingerprint> # this is what the secret holds
```

Then, in the repository's settings: **Secrets and variables → Actions → New repository secret**, named
`GPG_SIGNING_KEY`, holding the armoured private key. If the key has a passphrase, add `GPG_SIGNING_PASSPHRASE`
as well.

Two more things are yours rather than this file's:

- **Pages has to be on**, set to deploy from GitHub Actions (Settings → Pages → Source: GitHub Actions).
  Without it the deploy step fails and says so.
- **Keep the private key somewhere that is not only CI.** Losing it means every machine that added this
  repository has to be told about a new key by hand, which is the one failure mode of an archive that cannot be
  fixed by publishing something.

Until the secret exists, the workflow builds and verifies the archive and then stops, saying what is missing.
Nothing is published unsigned: `apt` refuses an unsigned archive by default, and the way around that —
`[trusted=yes]` — teaches somebody to turn off the check that makes the repository worth having.
