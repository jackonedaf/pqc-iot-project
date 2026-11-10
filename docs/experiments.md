# Metodyka i szablon raportu

PDF przewiduje pomiary fizyczne. Repozytorium dostarcza oprogramowanie pomiarowe; nie zawiera
zmyślonych wyników sprzętowych ani deklaracji, że HQC mieści się w RAM ESP32.

## Plan badań

1. Zapisz model urządzenia, CPU/taktowanie, RAM, system, architekturę, wersje bibliotek, commit,
   ograniczenia kontenera, temperaturę/tryb zasilania i sposób połączenia sieciowego.
2. Na jednym hoście wykonaj rozgrzewkę (oddzielny, odłożony plik), a następnie co najmniej 100–1000
   iteracji każdego algorytmu dla tych samych rozmiarów danych. Powtórz serię kilka razy.
3. Porównaj generację, enkapsulację, dekapsulację, HKDF, AES-GCM, czas CPU i rozmiary kluczy/szyfrogramów.
   RSS w CSV jest pomiarem procesu przed/po. Szczyt zmierz osobnym profilerem natywnym lub
   `/usr/bin/time -v` na osobnych procesach dla algorytmu; nie używaj wyłącznie tracemalloc dla kodu C.
4. Dla sieci utrzymuj stałe QoS 1, TLS, lokalizację brokera, interwał i konfigurację. Mierz różne
   rozmiary dopełnienia, algorytmy i warianty Ethernet/Wi-Fi. Dłuższe eksperymenty archiwizuj oddzielnie.
5. Raportuj liczbę prób, medianę, średnią, p95 RTT, rozkład i udział braku ACK; odróżnij timeout aplikacji
   od utraty ramek/pakietów. Rozróżnij czas handshake od czasu telemetrii już po ustanowieniu sesji.
6. Uruchom scenariusze MITM/replay i zachowaj logi bramy oraz kontrolne poprawne odczyty po ataku.
7. Uruchom oprogramowanie na fizycznym Raspberry Pi. Dla ESP32 przygotuj firmware i zmierz wolny/minimalny
   heap oraz stack high-water mark; przy braku zasobów udokumentuj błąd/OOM i wariant bramy Pi.

## Co wymaga dalszej pracy sprzętowej

- Sterownik prawdziwego czujnika i firmware ESP32.
- Osobno zabezpieczony kanał ESP32 → Pi przy wariancie bramy.
- Zmierzona, a nie szacowana zgodność HQC/ML-KEM z dostępnym RAM i czasem obliczeń ESP32.
- Fizyczne pomiary energii, szczytu RAM oraz utraty pakietów, jeśli są częścią końcowych badań.

## Układ raportu końcowego

1. Cel i hipotezy (kompromis ML-KEM/HQC względem X25519).
2. Architektura i granice zaufania.
3. Protokół, tożsamości, zarządzanie kluczami i model zagrożeń.
4. Stanowisko, metodologia i wersje.
5. Surowe CSV, statystyki, wykresy czasu/rozmiarów/pamięci.
6. Scenariusze ataków: wejście, oczekiwanie, obserwacja, log i ograniczenia dowodu.
7. Wyniki na urządzeniach, ewentualny brak RAM HQC i uzasadnienie bramy.
8. Ograniczenia, wnioski i dalsze prace.

Przy publikacji usuń sekrety i identyfikatory środowiska. W wynikach podaj, czy były uzyskane
w kontenerze na komputerze, bezpośrednio na Raspberry Pi czy na mikrokontrolerze.
