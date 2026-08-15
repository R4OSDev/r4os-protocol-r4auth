R4AUTH.R4P
==========

R4AUTH.R4P ist die wiederverwendbare Authentifizierungs-Protokollbasis fuer
R4OS. Die erste Zielrolle ist CredSSP fuer Windows-mstsc-kompatibles RDP.

Stand 0.55.31:

- Artefakt: `R4AUTH.R4P`
- Zielpfad im Image: `C:\R4OS\PROTOCOLS\R4AUTH.R4P`
- R4P-Rolle: `security.credssp`
- Kategorie: `data`
- Dependency: `security.tls`
- Erste Konsumentenlinie: RDPSVC

0.55.16 legt den R4P-Besitz und eine erste Dispatch-Kante an. Das Modul kann
seine Capabilities melden, eine DER-Sequenz als CredSSP-TSRequest-Huelle
klassifizieren und diese Basis per Selftest pruefen. Das ist noch keine
fertige NLA-Anmeldung und wird bewusst nicht als mstsc-Erfolg ausgegeben.

Seit 0.55.20 besitzt R4AUTH die CredSSP-Basis fuer den modernen RDPSVC-Pfad.
`op_classify_tsrequest` verarbeitet TSRequest-Felder fuer Version,
NegoTokens, AuthInfo, PubKeyAuth, ErrorCode und ClientNonce. Der Parser lehnt
kaputte DER-Laengen, unvollstaendige Huellen und falsch getaggte Felder ab.
`op_build_tsrequest` erzeugt eine TSRequest-Huelle mit Version 2 und optionalem
SPNEGO-NegoToken.

Seit 0.55.39 akzeptiert die Auswertung fuer echte Windows-mstsc-Flows nicht
mehr nur TSRequest-Version 2, sondern den kompatiblen Bereich 2 bis 6. Die
lokalen Builder bleiben fuer reproduzierbare Fixtures weiter bei Version 2;
der Parser blockiert moderne mstsc-Clients aber nicht mehr allein deshalb als
`bad_token`, wenn Windows eine hoehere CredSSP-Version sendet.

SPNEGO wird ueber `op_classify_spnego` und
`op_build_spnego_neg_token_resp` abgebildet. Unterstuetzt ist der NTLMSSP-
Pfad mit NegTokenInit/NegTokenResp; Kerberos wird erkannt, aber als
`unsupported-kerberos` gemeldet. Es gibt keinen stillen Domain- oder Kerberos-
Fallback.

NTLMv2 besitzt ab 0.55.20 echte Kernprimitive fuer das feste R4OS-Profil:
NT-Hash aus dem Passwort `rosebud`, NTOWFv2 fuer `R4OS`, deterministische
Server-/Client-Challenge und NTProof-Fixture per HMAC-MD5. `op_ntlmv2_profile`
meldet diese Werte fuer Harness und RDPSVC-Anbindung. Die eigentliche
mstsc-End-to-End-State-Machine folgt spaeter; diese Unterversion markiert noch
keinen fertigen NLA-Erfolg.

Der Login ist fest verdrahtet:

- User: `r4os`
- Passwort: `rosebud`
- Domain/Kerberos: nicht unterstuetzt
- Berechtigungen/Userverwaltung: keine

`op_validate_fixed_credentials` prueft nur diesen technischen Single-User-
Vertrag und verlangt einen geschuetzten TLS-Kontextmarker. Fehlerbilder:

- `bad_password=-20`
- `bad_token=-6`
- `unsupported_kerberos=-21`
- `unsupported_domain=-22`
- `missing_tls_context=-23`
- `bad_pubkeyauth=-24`
- `bad_state=-25`
- `unsupported_ntlm=-26`

Seit 0.55.25 besitzt R4AUTH die wiederverwendbare CredSSP-State-Machine. Der
neue Vertrag `op_credssp_state_contract` beschreibt das Eingabeformat
`R4CS + phase + tls + reserved + TSRequest`, die Phasen
`negotiate`, `authenticate` und `pubkeyauth`, die feste TLS-Pflicht und die
Folgeaktionen `send_challenge`, `pubkeyauth` und `rdp`.

`op_credssp_process_state` verarbeitet reale TSRequest-DER-Huellen aus diesem
Frame und entscheidet die State-Machine:

- Phase 1 erwartet NTLMSSP Type 1 und fordert die NTLM-Challenge an.
- Phase 2 erwartet NTLMSSP Type 3 und prueft User, Domain und NTLMv2-
  Response gegen das feste R4OS-Profil.
- Phase 3 erwartet PubKeyAuth und validiert die TLS-Pubkey-Bindung.

Die Hilfs-Ops `op_credssp_build_challenge`,
`op_credssp_build_authenticate_fixture` und
`op_credssp_build_pubkeyauth_fixture` liefern reproduzierbare TSRequest-
Fixtures fuer Harness, RDPSVC-Preflight und spaetere Live-Tests. Type3 wird
nicht als Klartextpasswort ausgewertet, sondern ueber NTProof/Blob,
Server-Challenge, Client-Challenge und NTOWFv2 verifiziert. PubKeyAuth ist als
HMAC-MD5-Bindung an den TLS-Public-Key-Hash modelliert, bis RDPSVC die echte
R4TLS-Session-Key-/Transcript-Uebergabe besitzt.

Seit 0.55.28 besitzt R4AUTH eine Windows-nahe CredSSP-Variante fuer den
modernen mstsc-Pfad. `op_credssp_windows_contract` (`op15`) beschreibt das
neue Eingabeformat `R4CW + phase + tls + variant + reserved +
tls_pubkey_hash32 + TSRequest`. `op_credssp_process_windows_state` (`op16`)
verarbeitet dieses Frame und prueft PubKeyAuth nicht mehr gegen eine rein
statische Fixture, sondern gegen den im Frame uebergebenen TLS-Public-Key-
Hash. `op_credssp_windows_harness` (`op17`) fuehrt einen kompletten
Windows-nahen Ablauf ueber NegTokenInit, Server-Challenge, NegTokenResp mit
NTLM Type3 und PubKeyAuth aus.

Der Harness prueft ausserdem stabile Fehlerbilder: manipulierte PubKeyAuth
liefert `bad_pubkeyauth=-24`, Kerberos-Only-NegTokenInit liefert
`unsupported_kerberos=-21`, Domain-Anmeldung liefert
`unsupported_domain=-22`, kaputte TSRequest-DER-Huellen liefern
`bad_token=-6` und fehlender TLS-Kontext liefert `missing_tls_context=-23`.
Damit bleibt das Ziel weiterhin Single-User `r4os` / `rosebud`, aber die
PubKeyAuth-Bindung ist fuer die naechste RDPSVC-Streamaktivierung an einen
konkreten TLS-Public-Key-Pfad anschliessbar.

Seit 0.55.30 validiert R4AUTH NTLM Type3 auch dann relativ zur eingebetteten
`NTLMSSP`-Nachricht, wenn diese in einem SPNEGO-NegTokenResp transportiert
wird. Dadurch bleiben Windows-nahe TSRequest-NegoTokens opak fuer die
TSRequest-Schicht, waehrend die NTLM-Security-Buffer weiter korrekt relativ
zum NTLMSSP-Header ausgewertet werden.

Seit 0.55.31 besitzt R4AUTH den Live-CredSSP-Vertrag fuer einen vorhandenen
R4TLS-Streamzustand. `op_credssp_live_contract` (`op18`) beschreibt das
Frame `R4CL + phase + variant + flags + reserved + stream_len + R4LK +
TSRequest`. `op_credssp_process_live_state` (`op19`) verarbeitet echte
TSRequest-Flights ueber diesem wiederaufnehmbaren Live-State. Der
TLS-Kontext wird nicht als Textmarker uebergeben, sondern als `R4LK`-
Streamzustand aus R4TLS; R4AUTH entnimmt daraus den TLS-Public-Key-Hash fuer
die CredSSP-PubKeyAuth-Bindung.

`op_credssp_live_harness` (`op20`) fuehrt den Windows-nahen Negotiate-,
Authenticate- und PubKeyAuth-Pfad ueber `R4CL`/`R4LK` aus und prueft stabile
Fehlerbilder fuer falsches Passwort, falsche PubKeyAuth, Kerberos,
Domain-Anmeldung, kaputte TSRequests und fehlenden TLS-Stream. Damit ist die
R4AUTH-Seite fuer die naechste RDPSVC-CredSSP-Live-Schleife vorbereitet,
ohne TLS-, NTLM- oder CredSSP-Logik in den Dienst zu kopieren.

Seit 0.55.39 prueft der Live-Harness zusaetzlich einen Windows-naeheren
Final-TSRequest mit `authInfo` und verschluesseltem `pubKeyAuth`. In diesem
fully-trusted Single-User-System wird dieser geschuetzte Abschluss als
`windows_final=ok` gemeldet; manipulierte synthetische 16-Byte-PubKeyAuth-
Fixtures bleiben weiterhin `bad_pubkeyauth`.

Die naechsten Ausbaustufen gehoeren hierher:

- RDPSVC Live-Handshake ueber den produktiven R4TLS-Stream.
- Windows-mstsc-End-to-End-Abnahme mit echten Client-PDUs.

RDPSVC nutzt diese Logik als Konsument und bleibt frei von privaten
CredSSP-/NTLM-/ASN.1-Implementierungen.
