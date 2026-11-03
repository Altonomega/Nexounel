# Shared zstd dictionaries (v1)

Two trained dictionaries, embedded by `../dicts.go` so both tunnel ends
always ship identical bytes:

| File | ID | Trained on (synthetic samples only) |
|---|---|---|
| `upload-v1.dict` | 1 | HTTP/1.1 requests, JSON request bodies |
| `download-v1.dict` | 2 | HTTP/1.1 responses, JSON responses, HTML pages |

## Provenance

Training samples are generated deterministically by `gen/main.go`
(fixed seed) from generic templates and word lists. No user traffic,
no scraped data, no deployment-specific content. All hostnames use
reserved `*.example.com` / `*.example.org` / `*.example.net` domains;
all tokens/keys are obviously fake placeholders.

## Regeneration

From the `core/` module root:

```sh
go run internal/compression/dicts/gen/main.go
```

The generator trains with `zstd.BuildDict` (klauspost/compress),
enforces the 64 KiB per-dictionary cap (shrinking the dictionary
history until the trained dictionary fits), verifies a round-trip
plus fail-closed decoding without the dictionary, and prints sizes
and SHA-256 hashes. Output is byte-identical across runs.

## Versioning rules

- A retrained dictionary pair is a NEW version: new file names, new
  `DictionaryVersion`, and NEW dictionary IDs. Never reuse an ID with
  different content: decoders select dictionaries by the ID stored
  in each frame.
- `ZSTD_DICT_ENABLED` must be set symmetrically on both ends running
  the same binary version. A peer without dictionary support rejects
  dictionary frames (unknown dictionary ID) instead of decoding
  them; a peer on a different dictionary version does the same.
  There is no dictionary negotiation beyond the existing
  compression-type nibble.
- Dictionary content is not secret. It must never be trained on user
  traffic.
