# Update server

The update server is a plain static mirror. GitHub Actions builds and signs everything and
pushes it to the `updates` branch; `sync.php` copies that branch to the web server every hour.

```
updates/app.json(.sig)    newest TGuard version + installer hash   (release key)
updates/feeds.json(.sig)  hashes of the lists below                (feeds key)
updates/signatures.txt    sha256;name
updates/urls.txt          malicious URLs / host:domain entries
updates/allow.txt         sha256 of files confirmed as false positives
updates/rules.json        extra detection rules (optional)
```

The lists are built from `lists/` in this repo, MalwareBazaar and URLhaus, and the lists managed
in the luis-tavares.pt backoffice (`/tguard/listas/urls.txt`, `hashes.txt` and `allow.txt`),
which the feeds workflow downloads every hour before signing.

TGuard only accepts these files when the signature matches the public keys built into it,
so the web server holds no secrets and can't push anything on its own.

## Setup (cPanel)

1. Create a subdomain, e.g. `tguard.luis-tavares.pt`, and upload `public/` to its document root.
2. Put `sync.php` somewhere outside the web root and set `TGUARD_UPDATES_DIR` (or edit `$target`).
3. Add a cron job: `php /home/USER/tguard-sync/sync.php` every hour.

## GitHub secrets

- `TGUARD_RELEASE_KEY`: signs new versions (used when a release is published)
- `TGUARD_FEEDS_KEY`: signs the hourly lists
- `ABUSECH_AUTH_KEY`: optional, pulls MalwareBazaar and URLhaus into the lists
