# Secure IT UP Collector

The collector is local-first and safe by default. Running it with no network flags collects local host inventory only and writes a backend-compatible JSON file.

```bash
python secure_it_up_collector.py --output collector-output.json
```

Network discovery requires all of the following:

- `--authorized`
- one or more `--scope` CIDRs
- an explicit discovery flag such as `--ping-sweep` or `--tcp-scan`

Use dry run mode before sending any probes:

```bash
python secure_it_up_collector.py --authorized --scope 192.168.10.0/24 --tcp-scan --dry-run
```

Public IP ranges are rejected unless `--allow-public-scope` is provided with written authorization. The collector refuses default routes and broad CIDRs by default.
