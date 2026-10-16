# LAN HTTP Administration Recovery

## Affected versions

Dark Threat Radar Community versions **v1.17.3 through v1.17.7** incorrectly
required HTTPS for administrative requests made from another machine on the
same private network. The application continues collecting and retaining data,
but Settings, Watchlist administration, and one-click updates can be blocked
with `Administrative access requires HTTPS or a local connection`.

Version **v1.17.8** restores the intended Community behavior: HTTP
administration works on RFC 1918 private networks, while HTTPS remains an
optional operator choice.

## Native Linux recovery

1. Open the installation's `.env` file (normally
   `/opt/dark-threat-radar/.env` or `/root/threat-radar/.env`).
2. Set `ALLOW_INSECURE_SENSITIVE_TRANSPORT=true`. Add the line if it is absent.
3. Restart the application service: `sudo systemctl restart threat-radar.service`.
4. Reload the browser and install the signed v1.17.8 update.
5. After v1.17.8 is running, set
   `ALLOW_INSECURE_SENSITIVE_TRANSPORT=false` and restart the service again.

The temporary compatibility switch is only needed to let an affected older
version submit its authenticated update request. Version v1.17.8 recognizes
private-network clients without it.

## Docker Compose recovery

1. Set `ALLOW_INSECURE_SENSITIVE_TRANSPORT=true` in the project's `.env` file.
2. Recreate the service with `docker compose up -d`.
3. Upgrade the checkout or image to v1.17.8 using the installation's normal
   Docker upgrade procedure.
4. Set the variable back to `false` and run `docker compose up -d` again.

## Deployment boundary

Community installations are intended for private networks. The separately
operated public demo has its own Cloudflare and read-only gateway controls;
these recovery steps do not apply to the demo.
