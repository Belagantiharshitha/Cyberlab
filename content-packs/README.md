# content-packs

Catalog/flags pack files used for import-export operations.

## Files

- `lightweight-localhost-labs.json`: Default curated pack with lab catalog entries and optional flag mappings

## Related routes

- Export: `/content_pack/export`
- Import: `/content_pack/import`

## Notes

Imported labs are written into `lab_catalog` in SQLite and shown via `/catalog` and `/dashboard` launch cards (subject to role/path filters and unlock rules).
