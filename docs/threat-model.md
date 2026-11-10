# Model zagrożeń i protokół

Chronione: poufność i integralność telemetrii między klientem a bramą, uwierzytelnienie negocjacji,
odrzucanie powtórzeń i podmiany parametrów KEM. Home Assistant otrzymuje świadomie jawne odczyty
po weryfikacji w bramie. Broker widzi metadane i te zweryfikowane odczyty.

Przeciwnik może przechwytywać, opóźniać, zmieniać i ponownie publikować komunikaty aplikacyjne.
Nie zna 32-bajtowego, losowego PSK, nie przejął hosta, plików sekretów ani konta bramy.
Testowe konto atakującego ma celowo szersze prawa do szyfrowanego transportu niż zwykły użytkownik.
W wdrożeniu usuń to konto i odpowiadający mu fragment ACL.

## Przebieg

1. Klient wysyła `hello`: wersja, ID, algorytm, losowy nonce 256 bitów, czas i HMAC-SHA256.
2. Brama weryfikuje HMAC, czas i nonce; generuje świeżą efemeryczną parę KEM i losowy identyfikator sesji.
   `offer` wiąże klucz publiczny, algorytm, ID, nonce klienta i sesję przez HMAC.
3. Klient weryfikuje ofertę i powiązanie z własnym żądaniem, enkapsuluje sekret i przesyła `exchange`
   z szyfrogramem KEM, identyfikatorem sesji i HMAC. X25519 używa klucza efemerycznego jako odpowiednika
   szyfrogramu i oblicza wspólny sekret ECDH.
4. Brama weryfikuje HMAC przed dekapsulacją. SHA256 kanonicznego transkryptu offer+exchange jest solą HKDF.
   HKDF-SHA256 wyprowadza dwa różne klucze AES-256: do klient→brama i brama→klient.
5. Brama wysyła zaszyfrowane `ready` z sekwencją 0; klient potwierdza w ten sposób posiadanie klucza przez bramę.
6. Telemetria zaczyna od sekwencji 1. Nonce GCM to 4 bajty zera + 64-bitowa sekwencja big endian.
   Każdy kierunek ma osobny klucz. Nagłówek (wersja, rodzaj, ID, algorytm, sesja, sekwencja i kierunek) jest AAD.
   Sesja nie może ponownie użyć sekwencji do szyfrowania innej treści. Kod klienta zwiększa ją przed wysłaniem;
   odpowiedź bramy powstaje raz dla zaakceptowanej sekwencji.
7. Brama najpierw sprawdza sesję/sekwencję, weryfikuje tag, dekoduje i sprawdza schemat/czas telemetrii,
   publikuje odczyt i zaszyfrowany `ack`. Duplikaty QoS 1 odrzuca bez ponownej publikacji.

Sesje żyją najwyżej 240 sekund, oczekujące handshake 30 sekund; klient odnawia po 180 sekundach.
Tolerancja zegara to 60 sekund. Nowa sesja ma nową parę KEM, sekret i nonce; restart bramy usuwa
sesje i wymaga nowego handshake. Lista nonce hello jest ograniczona czasem 120 sekund, a poprawne
hello przyjmowane najwyżej raz na sekundę. Wszystkie wiadomości mają limit rozmiaru.

## Ograniczenia

- Uwierzytelnienie używa **klucza współdzielonego**, a nie podpisów PQC lub infrastruktury certyfikatów PQC.
  HMAC-SHA256 z losowym 256-bitowym PSK uwierzytelnia pełny handshake. Sam KEM nie uwierzytelnia stron.
- TLS używa klasycznych certyfikatów RSA. Warstwa aplikacyjna ML-KEM/HQC chroni sesję klient↔brama;
  **nie jest to TLS postkwantowy**. Wariant X25519 jest klasycznym punktem odniesienia.
- Broker i HA są zaufane w zakresie jawnych stanów po weryfikacji; administrator brokera może fałszować
  takie stany. Przejęcie PSK, klienta lub bramy wykracza poza model. Sekrety są plikami, bez TPM/HSM.
- PSK jest przypisany jednemu demonstracyjnemu urządzeniu `sensor-01`. Kolejne urządzenia wymagają
  oddzielnych PSK, loginów, ACL, sesji i rejestru tożsamości; skalowanie przez współdzielenie PSK jest błędne.
- DoS, pełna ochrona side-channel, bezpieczne kasowanie pamięci Pythona, formalny dowód protokołu
  i niezależny audyt nie są zrealizowane. Atakujący może zagłuszyć ruch lub zerwać dostępność.
- Brak ACK powoduje nowy handshake; odczyt mógł już dotrzeć do HA. Protokół zapewnia odrzucenie replay
  w ramach sesji, nie transakcyjne exactly-once dostarczenie całego systemu.
- Konto atakującego nie ma prawa do stanów HA, ale może zatruwać retained transport lub blokować
  wymianę; są to scenariusze dostępności, nie obejście AEAD.
- Python, HQC i biblioteki natywne to prototyp badawczy, bez deklaracji zgodności FIPS lub audytu.

## Macierz weryfikacji

| Scenariusz | Oczekiwany wynik | Dowód |
|---|---|---|
| Trzy prawdziwe KEM | Identyczne sekrety i poprawne dane | Testy + smoke MQTT |
| Podmiana klucza/algorytmu oferty | Błąd HMAC przed enkapsulacją | Testy MITM |
| Oferta z poprzedniego hello | Niezgodność nonce | Test automatyczny |
| Manipulacja exchange | Błąd HMAC przed dekapsulacją | Test + kem-tamper |
| Zmiana szyfrogramu lub AAD | Błąd GCM / nagłówka, sekwencja nieprzyjęta | Test + tamper |
| Powtórzenie telemetrii | Odrzucenie, brak drugiego stanu | Test + replay |
| Restart/wygaśnięcie sesji | Stary pakiet odrzucony | Test automatyczny |
| Atakujący publikuje stan HA | MQTT PUBACK Not authorized | Smoke integracyjny |
