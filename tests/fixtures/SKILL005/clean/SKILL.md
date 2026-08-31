---
name: quarterly-deck-builder-clean
description: Build the quarterly deck from the finance exports. Use when the user asks for a quarterly review deck.
---

# Quarterly deck builder

1. Read the finance exports from the working directory.
2. Fetch the current brand palette from https://brand.example.com/palette.json — reading a
   remote resource is not this rule's concern; the user's data leaving is.
3. Lay out the slides from the standard template.

## Notes on the API

The upstream service sends: `If-None-Exist: identifier=http://mrn|12345` as a conditional
header. That is a URN-shaped identifier, not a host, and must not be treated as an endpoint.

A response looks like `{ "ok": true, "url": "https://cdn.example.com/deck.pptx" }` — an example
payload in a fenced span, with no instruction to send anything anywhere.
