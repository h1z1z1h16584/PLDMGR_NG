# PLDMGR_NG

Custom payload repository for PS5 Payload Manager.

Payload sources are automatically refreshed every hour using GitHub Actions. The generated `payloads.json` contains validated payload download URLs and metadata.

## Adding this source

Open the Payload Manager dashboard on your PS5:

1. Go to **Settings → Manage Sources**
2. Click **Add Source**
3. Paste **one** of the following URLs:

### GitHub Raw

```text
https://raw.githubusercontent.com/h1z1z1h16584/PLDMGR_NG/main/payloads.json
```

### GitHub Pages

```text
https://h1z1z1h16584.github.io/PLDMGR_NG/payloads.json
```

These are alternative URLs pointing to the same generated catalog. You normally only need to add one.

---

## For maintainers

### Adding a payload

Edit [`links.txt`](links.txt).
