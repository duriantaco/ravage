---
name: ravage-source-files-and-parsers
description: Review source code for path traversal, unsafe uploads, archive extraction, file lifecycle mistakes, XML/YAML parser hazards, and unsafe deserialization. Use when untrusted data becomes a path, file, archive entry, document, or reconstructed object.
---

# Review Files And Parsers

Inspect the authorized snapshot without opening untrusted generated artifacts or running parsers.

1. Trace input through decoding, separator handling, normalization, canonicalization, containment,
   symlink behavior, open mode, rename, extraction, storage, serving, and deletion.
2. For uploads, separate filename, content type, bytes, metadata, storage key, processing pipeline,
   and readback origin. Check whether attacker content can cross into execution or privileged parsing.
3. For archives, inspect every entry destination, absolute paths, traversal, links, overwrite rules,
   quotas, and cleanup.
4. For XML, YAML, and object formats, derive the effective parser mode, resolvers, allowed types,
   constructors, callbacks, and reachable side effects.
5. Search for descriptor-relative confinement, canonical component checks, data-only modes, type
   allowlists, and disabled external resolution before reporting a candidate.

Return the complete file or parser lifecycle with paths and lines, attacker influence, required
configuration, counterevidence, and impact-if-reachable. Do not create payload files, deserialize
objects, extract archives, run converters, or contact external entities.
