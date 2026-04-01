# Config format (simple JSON -> DeviceRequest)

`mdoc_reader` app builds `DeviceRequest` from a JSON file that follows `DeviceRequest` / `ItemRequest` naming.

## JSON shape

- `version: String` (optional, default is builder default)
- `docRequests: [ ... ]` (required)
  - `itemsRequest` (required)
    - `docType: String` (required)
    - `nameSpaces: BTreeMap<String, BTreeMap<String, bool>>` (required)

Example:

```json
{
  "docRequests": [
    {
      "itemsRequest": {
        "docType": "org.iso.18013.5.1.mDL",
        "nameSpaces": {
          "org.iso.18013.5.1": {
            "age_over_18": false,
            "portrait": false
          }
        }
      }
    }
  ]
}
```

`nameSpaces` is parsed by `serde_json::from_value` into `NameSpaces`, so app module (`crates/app`) is the only place that depends on `serde_json`.
