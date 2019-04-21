# IPK Projekt č. 2

## Úvod
Autor: xgregu02 (Sabína Gregušová)</br>
Mojou úlohou bolo vytvoriť jednoduchý TCP/UDP skener s použitím raw socketov a raw paketov pre zadanú doménu v jazyku C/C++.

## Riešenie
Projekt som riešila v jazyku C++ podľa mojich znalostí nadobudnutých z predmetu IPK a internetových zdrojov. Všetky kódy, ktoré nepatria mne majú pri sebe uvedený odkaz a ak sú dostupné aj ďaľšie informácie, tak sú uvedené aj tie.</br>
Môj projekt zisťuje stav zadaných portov pre UDP alebo TCP a funguje pre IPv6 aj IPv4,no defaultne sa používa IPv4. IPv6 sa použije, ak je zadaná IP adresa s formátom IPv6.

## Spustenie
K projektu je priložený makefile, preto je potrebné začať so zostavením projektu pomocou príkazu

```
make
```

Projekt sa spúšťa pomocou príkazu

```
sudo ./ipk-scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]
```

a musí sa spúšťať so správcovskými právami. Prepínač -pt označuje použitie protokolu TCP, prepínač -pu označuje použitie protokolu UDP. Port ranges môže mať formát:
* -22 (jeden port)
* 1-65535 (rozmedzie portov)
* 22,23,24 (zoznam portov)

Ak nemá užívateľ záujem o použitie niektorého z protokolov, tak len stačí neuviesť daný prepínač.

Rozhranie (interface) je nepovinný argument, a ak nie je zadané, defaultne sa použije prvé neloopbackové rozhranie.

Povinným argumentom je zadanie doménového mena alebo IP adresy. Nezáleží na tom, ktorý údaj bude zadaný, ale nemôžu byť zadané oba naraz. 
