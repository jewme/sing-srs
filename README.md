# Rule-Set Builder for sing-box

Generate sing-box rule-set JSON and SRS files from multiple rule sources.

## Features

- Parse Surge lists, YAML, JSON, SRS, and AdGuard DNS filter lists
- Merge and deduplicate rules
- Generate domain-only (`DOMN/`) and CIDR-only (`CIDR/`) subsets
- Convert AdGuard DNS filter lists directly to SRS in `DNSF/`
- Compile JSON rule-sets to SRS
- Automatic GitHub Actions build and publish

GitHub Actions builds daily and publishes the generated rule-sets to the `rule-set` branch.

## License

MIT