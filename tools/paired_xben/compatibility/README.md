# Frozen XBEN compatibility catalog

This directory is the complete pre-draw compatibility policy for the pinned
XBEN source revision in `catalog.json`. Unlisted cases receive no patch.

The eight listed patches only redirect obsolete Debian package repositories to
`archive.debian.org` and disable package-index expiry checks. They do not alter
challenge application code, services, credentials, vulnerabilities, or flags.
The archive mirror is still a network dependency, so a successful build is not
bit-for-bit reproducible unless its fetched base image and packages are also
recorded by digest in the campaign evidence.

Every patch is bound by SHA-256 and must apply cleanly to its one declared case
at the pinned XBEN commit. The evaluator must bind the SHA-256 of the complete
catalog before the random case draw, resolve patches only through this catalog,
and refuse any compatibility edit after the draw.
