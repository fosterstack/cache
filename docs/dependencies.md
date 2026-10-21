<!-- DRAFT for the owner's discussion: customer-visible copy, not published. -->
# Dependencies

The release source includes a `vendor/` directory with every Go dependency the binary is built from, and the build uses only that code.

`dependency-provenance.json` at the repository root lists, for each module: its path, version, go.sum hash, the entry in the public Go checksum log, the upstream address, the upstream commit (for a pseudo-version) or tag (for a tagged version), and its licence.

What this claim is: each dependency is verified to be the same source the public checksum log records, from the stated upstream commit or tag.

What it is not: a review of the dependencies' code. The project makes no claim that anyone has reviewed that code.
