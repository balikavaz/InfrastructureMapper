## Infrastructure Mapper

Infrastructure Mapper je rješenje koje služi za automatiziranu analizu internetskih domena i spremanje informacija za izradu kataloga. Kroz nekoliko klikova sistemski administratori, sigurnosni stručnjaci ili drugi IT stručnjaci mogu izraditi katalog infrastrukture koju održavaju, pregledati otvorene portove, provjeriti sigurnosnu reputaciju i slično. Automatizirani skener mijenja sate ručnog rada i korelacije informacija za izradu cjelovitog pregleda javne mrežne infrastrukture za pojedinu domenu.

Dovoljno je upisati željenu domenu, naprimjer **unipu.hr** i sustav će automatski:   
1. putem besplatnog API poziva povući iz javnog dostupnog servisa Security Trails sve poddomene (engl. *subdomains*) za zadanu domenu;
2. prevesti sve internetske adrese u odgovarajuće javne IP adrese koje su konfigurirane za zadanu domenu koristeći javni DNS servis;
3. obogatiti svaku IP adresu dodatnim informacijama iz besplatnog servisa Abuse IP Database i to na način da će za svaku IP adresu dobaviti njenu sigurnosnu reputaciju (0 je OK, sve više od toga je sumnjivo), zemlju u kojoj se nalazi IP adresa, kojem pružatelju usluga pripada i pripada li IP adresa TOR proxy sustavu;
4. skenirat će svaku IP adresu (neinvazivno - mali set portova) po osnovnom setu TCP portova i detektirat će otvorene portove.

Nakon konsolidacije svih informacija o domeni za koju smo zatražili analizu (naprimjer **unipu.hr**), Infrastructure Mapper će spremiti sve u bazu podataka.   
Podatke dodatno obrađuje u rubrici **Pregled** gdje se vide svi zapisi kao i grafički prikaz najvažnijih zapažanja. Sve podatke moguće je izmijeniti, obrisati ili dopuniti u rubrici **Promjene**.

#### **VAŽNO**: Infrastructure Mapper dolazi sa već popunjenom bazom za **unipu.hr** domenu, koja ima preko 200 mapiranja u upotrebi. Nije nužno koristiti skener za inicijalno prikupljanje podataka.

### Sken
Funkcionalnost u kojoj možemo zatražiti analizu neke domene. Skeniranje može potrajati, ovisno o veličini infrastrukture za koju je zatražena analiza.
Nakon pokretanja skeniranja potrebno je pratiti pješčanik u tabu internetskog pretraživača ili još detaljnije, CLI poruke u Docker-u. Nakon što se pješčanik ukloni, pojavit će se zeleni okvir koji obavještava korisnika da je skeniranje gotovo, tada je informacije o infrastrukturi domene moguće pregledati u rubrici **Pregled**.

Svakim novim pokretanjem skenera Infrastructure Mapper će obrisati postojeće zapise u bazi (prvenstveno zbog preglednosti). 

#### **VAŽNO**: Iako TCP skeniranje nije invazivno, podešeno je za ispitivanje 10-ak portova - imajte na umu da nije preporučljivo skenirati bilo koji sustav bez dodatne dozvole.

### Pregled
Funkcionalnost u kojoj možemo pregledati sve informacije koje su prikupljene automatskom analizom. Dva grafa prikazuju udio pružatelja usluga (ISP) za javne IP adrese i servise na njima, te drugi graf prikazuje najčešće mapirane IP adrese u zatraženoj domeni.

### Promjene
Funkcionalnost u kojoj možemo pojedinačnim odabirom mijenjati, brisati ili dodavati zapise u bazi podataka.

## Use case diagram

![Infrastructure Mapper use case](https://github.com/balikavaz/InfrastructureMapper/blob/main/use_case_diagram.png)

## Instalacija i pokretanje
Za instaliranje i pokretanje nužno je slijediti opisane korake.

#### 1. korak - preuzimanje datoteka sa Git repozitorija

```
git clone https://github.com/balikavaz/InfrastructureMapper.git
cd InfrastructureMapper
```

#### 2. korak - Upisivanje odgovarajućih API ključeva za vanjske servise koji obogaćuju podatke.

U Python skriptu naziva **infrastructure_scanner.py** potrebno je upisati dva API ključa koji služe za prikupljanje informacija o IP adresama i domenama koje analizira Infrastructure Mapper.

APIKey = '*<kljuc_za_abuse_ip_database_servis>*'  
APIKey1 = '*<kljuc_za_security_trails_servis>*'

Sačuvati nove ključeve u datoteci.

#### 3. korak - Izraditi Docker image i pokrenuti ga.

```
docker build --tag infosustavi:projekt .
docker run -p 8080:8080 infosustavi:projekt
```

#### 4. korak - Pristupanje Infrastructure Mapper-u.

Otvoriti internetski pretraživač i upisati:
```
http://127.0.0.1:8080/
```
