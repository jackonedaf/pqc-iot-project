# Weryfikacja implementacji

Sprawdzone lokalnie przy wdrożeniu projektu:

- 28 testów pytest na Windows/Python 3.10 i w kontenerze Linux/Python 3.12: zaliczone.
- `ruff check .` oraz `docker compose config --quiet`: zaliczone.
- Kontenery Mosquitto, bramy i symulatora: stan `healthy`.
- Dla ML-KEM-768, HQC-128 i X25519: po 3 poprawne odczyty i zaszyfrowane ACK przez prawdziwy MQTT/TLS.
- Konto atakującego nie może publikować do tematu stanów HA: PUBACK MQTT v5 `0x87 Not authorized`.
- Powtórzony pakiet: brama zarejestrowała `ProtocolError`; brak ponownego ACK.
- Zmieniony szyfrogram/nagłówek: brama zarejestrowała `InvalidTag`; poprawne odczyty nadal docierały.
- Benchmark w kontenerze: po 20 iteracji dla każdego algorytmu, rozmiary 64 i 1024 bajty; CSV i wykresy utworzone.
- Walidacja konfiguracji Home Assistanta: zaliczona; HTTP port 8123: odpowiedź 200.

To testy poprawności i uruchomienia. Krótkie serie nie są pełnym eksperymentem statystycznym.
Nie wykonano pomiarów na fizycznym Raspberry Pi/ESP32. Interfejs HA wymaga pierwszego utworzenia konta
i dodania MQTT zgodnie z README; nie tworzono użytkownikowi konta administratora ani nie modyfikowano `.storage`.
Testy MITM deterministycznie manipulują uwierzytelnioną ofertą KEM w testach protokołu;
narzędzia sieciowe wstrzykują ograniczoną liczbę pakietów w lokalnym laboratorium.
