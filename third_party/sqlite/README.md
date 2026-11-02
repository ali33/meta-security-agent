# Vendored SQLite

- Version: 3.54.1 (amalgamation `sqlite-amalgamation-3540100.zip`, released 2026)
- Source: https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip (downloaded once by a developer; the build never touches the network)
- Published SHA3-256 of the zip (sqlite.org download page): `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30` (verified)
- Files kept: `sqlite3.c`, `sqlite3.h` (unmodified). `shell.c` and `sqlite3ext.h` are not vendored; extension loading is compiled out.
- License: public domain (https://www.sqlite.org/copyright.html). No attribution required.

## Updating
1. Read the release notes and https://www.sqlite.org/download.html for the new version and its SHA3-256.
2. Download the zip on a developer machine, verify the SHA3-256 against the download page, replace the two files.
3. Update this file (version, hash), run the full ctest, and review the diff of compile options in `CMakeLists.txt`.
