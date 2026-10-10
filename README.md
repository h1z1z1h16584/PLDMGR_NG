# PLDMGR_NG

Custom payload repository for PS5 Payload Manager.

Payload sources are automatically refreshed every hour using GitHub Actions. The generated `payloads.json` contains validated payload download URLs and metadata.

## Adding this source

Open the Payload Manager dashboard on your PS5:

1. Go to **Settings → Manage Sources**
2. Click **Add Source**
3. Paste the following URL:


```text
https://raw.githubusercontent.com/h1z1z1h16584/PLDMGR_NG/main/payloads.json
```

---

## For maintainers

### Adding a payload

Edit [`links.txt`](links.txt).
