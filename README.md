# R4AUTH.R4P

`R4AUTH.R4P` is an independent R4OS protocol module implemented in Zig.

## Package

- Version: `0.1.3`
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


R4AUTH: verbindungseigene Anmeldung ab 0.78.62
-------------------------------------------
R4AUTH 0.1.3 besitzt den NTLMv2-/CredSSP-Ablauf. RDPSVC uebergibt seine
beim Dienststart geladene Registrykonfiguration. Das Modul kennt fuer den
Produktpfad kein festes Kennwort. Unterstuetzt: Benutzername 1..31 druckbare
ASCII-Bytes ohne Pfadtrenner, Kennwort 1..31 UTF-8-Bytes ohne NUL, leere oder
lokale Domain R4OS, NTLMv2 mit Unicode, SIGN, SEAL, ESS und 128-Bit-Profil.
Kerberos und externe Domains sind nicht implementiert.

Op8 (R4AC) prueft nur die Konfigurationsform und meldet auth=pending.
Op21 initialisiert eine private Sitzung aus R4AI; Benutzer, NT-Hash,
Hardware-Challenge, TLS-Fingerabdruck und SubjectPublicKey bleiben an diese
Verbindung gebunden. Op19 verarbeitet R4C3 und liefert R4AO. Op18 beschreibt
diesen Vertrag. Alle Zahlen der privaten Huellen sind Little Endian:

- R4AC: Magic4, Benutzerlaenge u16, Kennwortlaenge u16, beide Texte.
- R4AI: Magic4, vier u16-Laengen (Benutzer, Kennwort, R4LK, Public-Key),
  danach genau diese vier Nutzdatenbereiche.
- R4C3: Magic4, drei u32-Laengen (Zustand, R4LK, TSRequest), danach die
  drei Bereiche. Zustand ist opak, R4LK genau140 Bytes, TSRequest max.4096.
- R4AO: Magic4, Zustandlaenge u32, Antwortlaenge u32, Phase u8, drei
  Nullbytes, privater Zustand, getrennte Netzwerkantwort. Nur letztere
  darf an den Client gesendet werden; niemals der Zustand oder R4LK.

Phasen: 1 Negotiate, 2 Authenticate, 3 Credentials, 4 Complete.
Type1 liefert Type2 mit neuer Challenge und passenden Flags/Payloadoffsets.
Type3 und pubKeyAuth sind gemeinsam erforderlich; authInfo ist dort noch
unzulassig. NTProof, NTLMv2-Blob, optionaler bzw. angeforderter MIC und
verschluesselter Sitzungsschluessel werden geprueft. Der MIC umfasst die
exakten NTLM-Nachrichten ohne umgebende SPNEGO-Felder.

PubKeyAuth ist eine echte NTLM-ESS-signierte und versiegelte Nachricht.
Version5/6 bindet den SHA256-Wert aus Richtungskennung inklusive NUL,
ClientNonce32 und ASN.1 SubjectPublicKey; Version2..4 bindet den Public-Key
mit der vorgesehenen inkrementierten Serverantwort. Die pro Richtung
fortgefuehrten RC4-/Signaturzustaende pruefen die Nachrichtensequenz.
Erst ein anschliessendes versiegeltes authInfo mit TSPasswordCreds fuer
Benutzer, Domain und Kennwort dieser Sitzung erreicht Complete. Verfruehte,
fehlende, doppelte oder fremden Sitzungen zugeordnete Teile schlagen fehl.
R4LK-Recordzaehler duerfen fortschreiten; Schluessel und Zertifikatbindung
muessen gleich bleiben. Abschluss/Fehler loeschen den lokalen Zustand.

Alte Annahme-Ops11/16 sind nicht mehr verfuegbar (-26). Ops3/7/13/14/17/20
und die alten R4S2/R4W2/R4C2-Harnessfunktionen sind Diagnose-Fixtures mit
bekannten Testdaten. Ihr Ergebnis ist kein Nachweis einer echten Anmeldung.
Op12 bleibt ein Diagnosebuilder mit acht vom Aufrufer gelieferten
Challengebytes. Der produktive Type2 entsteht ausschliesslich in Op19.
Fehler: -6 Token, -20 Kennwort/Nachweis, -24 Bindung, -25 Zustand,
-26 nicht unterstuetztes Profil, -27 fehlende Entropie, -28 Konfiguration;
Ausgabelaenge ist bei Dispatchfehlern null.

Nachweis: begrenzte ReleaseSafe-Hostfaelle fuer einen unabhaengig erzeugten
CredSSP-v6-Ablauf, falsches Kennwort, fehlende/falsche Bindung, falsche
Sitzung/Reihenfolge und Wiederholung; veroeffentlichter NTLM-Sealing-Vektor.
Ein kurzer SMP4-QEMU-Lauf prueft echte TLS1.2/CredSSP-Pakete mit geaenderten
lokalen Zugangsdaten und die Ablehnung des bisherigen Standardkennworts.
Dies ist keine neue Windows-mstsc- oder vollstaendige RDP-Desktopabnahme.
