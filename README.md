# Sign in with Google for Nolviko

Official [Nolviko](https://github.com/Nolviko/nolviko) extension: members sign up and sign in with their Google account.

## Features

- "Sign in with Google" on the login and registration pages
- Set up entirely from the admin panel — no file editing: the settings page shows the steps and the exact
  redirect address to register at Google
- New accounts only with a Google-verified address; an address that already has an account is linked once
  after that account's password (never a silent takeover)
- Members link and unlink Google on their account page
- Bans, account status and two-step verification apply as with the password form
- OpenID Connect with state, nonce and PKCE; no OAuth library

## Setup

1. Install and enable the extension (below).
2. Open **Admin → Extensions → Sign in with Google → Settings** and follow the steps: create an OAuth client
   (Web application) in the Google Cloud Console with the redirect address shown on the page.
3. Paste the client ID and client secret and save. The secret is stored encrypted and never shown again.

Hosts that prefer files can set `oauth.google.client_id` / `client_secret` in `config/local.php` (or
`FORUM_GOOGLE_CLIENT_ID` / `FORUM_GOOGLE_CLIENT_SECRET`); these win over the settings page.

## Installation

1. Download the latest `nolviko-ext-nolviko-google-<version>.zip` from this repository's **Releases** page, and copy
   the SHA-256 checksum shown next to it.
2. In your forum: **Admin → Extensions → Upload**, choose the ZIP, paste the SHA-256 and confirm that you trust
   the package.
3. Install and enable it. Updates work the same way: upload the newer ZIP; the forum turns the extension off,
   replaces its files and turns it on again. Your settings and data are kept.

Requires [Nolviko](https://github.com/Nolviko/nolviko) 0.1.0-beta.2 or newer. Disabling the extension keeps its data.

## Development

The package contains `extension.json`, `LICENSE`, `src/`, `translations/`; `tests/` and this README
stay in the repository. The extension uses only Nolviko core classes and PHP's standard library — no Composer
packages of its own.

Tests run against a Nolviko core checkout with its development dependencies:

```bash
php <nolviko-dev-vendor>/bin/phpunit --bootstrap <nolviko-dev-vendor>/autoload.php tests
```

Code style follows the core project (PSR-12, 120 columns). All text goes through `translations/en.json` and
`translations/tr.json`.

## License

[Apache License 2.0](LICENSE), like Nolviko itself.
