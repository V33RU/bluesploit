# Signature file schema

`bluetooth_cves.json` is a JSON document with this top-level shape:

```json
{
  "schema_version": 1,
  "generated_note": "free-text",
  "entries": [ { ...entry... } ]
}
```

## Entry fields

All fields are required unless marked optional.

| Field            | Type           | Notes                                                                 |
|------------------|----------------|-----------------------------------------------------------------------|
| `id`             | string         | `CVE-YYYY-NNNN[NNN]` (4 to 7 digit suffix per CVE Numbering Authority spec) |
| `name`           | string         | Short human label, e.g. "KNOB, Key Negotiation Of Bluetooth"          |
| `severity`       | enum           | `info` \| `low` \| `medium` \| `high` \| `critical`                   |
| `confidence`     | enum           | `low` \| `medium` \| `high` (see SOURCE.md)                           |
| `applies_to`     | object         | `protocol`: `classic` \| `ble` \| `dual`                              |
| `match`          | object         | See "Match block"                                                     |
| `description`    | string         | One-line operational summary                                          |
| `related_modules`| list[string]   | Module paths under `modules/` to suggest, e.g. `exploits/knob`        |
| `references`     | list[string]   | URLs. Must include the NVD record. Should include one primary source. |
| `disclosed`      | string         | `YYYY-MM-DD` disclosure date                                          |

## Match block

```json
{
  "fingerprint": "lmp_features" | "ll_features" | "smp_pairing" | "service",
  "rules": [ { ...rule... } ],
  "rationale": "free-text explaining why this rule is defensible"
}
```

A signature matches a host fingerprint when **at least one rule in
`rules`** is fully satisfied (logical OR over rules, logical AND
over fields within a rule).

### Rule fields by fingerprint type

For `fingerprint: lmp_features`:

- `lmp_version_max_inclusive` , string, BR/EDR LMP version (e.g. `"5.3"`)
- `lmp_version_min_inclusive` , string, optional lower bound
- `encryption_supported` , bool, optional
- `secure_connections_controller` , bool, optional
- `secure_connections_host` , bool, optional

For `fingerprint: ll_features`:

- `le_supported` , bool, optional
- `le_2m_phy` , bool, optional
- `le_coded_phy` , bool, optional

For `fingerprint: smp_pairing`:

- `legacy_pairing_accepted` , bool, optional
- `mitm_required` , bool, optional
- `max_key_size_max` , int, optional

For `fingerprint: service`:

- `uuid` , string, optional
- `vendor_oui_in` , list[string], optional

Empty `rules: []` means "informational only, no fingerprint-based
detection wired in yet"; the scanner reports the entry but never
flags a host as matching.

## Compatibility

The `schema_version` field exists so future migrations can be
non-breaking. Readers should ignore unknown top-level fields and
unknown entry-level fields. Writers should bump `schema_version`
when fields are renamed or removed.
