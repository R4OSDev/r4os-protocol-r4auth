# R4AUTH.R4P

`R4AUTH.R4P` is an independent R4OS protocol module implemented in Zig.

## Package

- Version: `0.1.2`
- Image target: `/R4OS/PROTOCOLS/R4AUTH.R4P`
- Image scope: `slim`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

## Build

On Windows:

    Build.bat

On Linux or macOS:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.


Sitzungs-Challenge ab 0.78.61
---------------------------
Op21 erzeugt acht frische Challengebytes aus SDK secure_random.fill. Der
Aufrufer besitzt sie genau fuer eine Verbindung, uebernimmt sie nie vom Peer
und verwendet sie nicht erneut fuer einen neuen Anmeldeversuch. Fehlende
Entropie liefert -27 mit Ausgabelaenge 0. Op12 verlangt exakt diese acht Bytes
als Eingabe und baut daraus den Type2-TSRequest. Op12 ist keine feste Fixture.

Die privaten Zustandshuellen enthalten dieselbe Challenge: R4S2 (16-Byte-
Header; Challenge ab8), R4W2 (48-Byte-Header; Challenge ab40) und R4C2
(20-Byte-Header; Challenge ab12, danach R4LK und TSRequest). Alte Kennungen
werden abgewiesen. Type3 wird in allen drei Pfaden gegen die Challenge im
zugehoerigen Zustand geprueft. Festwerte gehoeren nur zu ausdruecklichen
Diagnose-Fixtures. SPNEGO-Huellen bleiben als solche klassifiziert; nur am
Byte0 beginnendes NTLMSSP gilt als roher Token.
Die vollstaendige CredSSP-Nachweis-/Phasenpruefung und konfigurierbare
Anmeldegrundlage sind gesonderte Folgearbeit 0.78.62.
