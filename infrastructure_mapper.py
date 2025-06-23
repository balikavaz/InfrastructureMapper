#!/usr/bin/env python3

# Import Flash modula.
from flask import Flask, render_template, request, redirect, url_for
# Import ponyORM modula za rad sa bazom podataka.
from pony.orm import Database, Required, db_session, select, commit
# Import collections modula za efikasniji rad sa listama.
from collections import Counter
# Import custom modula koji služi za prikupljanje podataka o internetskim domenama.
import infrastructure_scanner

app = Flask(__name__)
DBName = 'infrastructure_database.sqlite'
db = Database()

db.bind(provider = 'sqlite', filename = DBName, create_db = True)

# Definiranje klase za rad sa bazom podataka i tablicom u koju upisujem sve rezultate "KompletnaInfrastruktura".
class KompletnaInfrastruktura(db.Entity):
	ip_address = Required(str)
	reputation = Required(int)
	internet_address = Required(str)
	isp = Required(str)
	country = Required(str)
	tor = Required(str)
	tcp_ports = Required(str)

db.generate_mapping(create_tables = True)

# Funkcija za brisanje svih zapisa u bazi podataka.
@db_session
def BrisanjeBaze():
	KompletnaInfrastruktura.select().delete(bulk = True)
	db.execute("DELETE FROM sqlite_sequence WHERE name='KompletnaInfrastruktura'")
	commit()
	print(f' [>] Svi zapisi iz baze su obrisani.')

# Ruta za otvaranje startne stranice.
@app.route("/")
def index():
	return render_template("index.html")

# Ruta za otvaranje stranice za pokretanje skeniranja domene.
# Opcija skeniranja služi za automatsko popunjavanje baze podataka.
@app.route("/sken", methods=["GET", "POST"])
@db_session
def sken():
	if request.method == "POST":
		BrisanjeBaze()
		domena = request.form.get("domena")
		print(f' [>] Prikupljam podatke za domenu {domena}.')

		rezultati = infrastructure_scanner.PassiveDNS(domena)
		broj_upisanih = 0

		# Obrađivanje podataka koje je vratio vanjski modul infrastructure_scanner i upisivanje u bazu podataka.
		for zapis in rezultati:
			try:
				ip_address, internet_address, reputation, isp, country, tor, tcp_ports = zapis.split('|')
				ip_address = ip_address.strip()
				internet_address = internet_address.strip()
				reputation = int(reputation)
				isp = isp.strip()
				country = country.strip()
				tor = tor.strip()
				tcp_ports = tcp_ports.strip().strip('[]') or 'None'

				# Provjeri da li zapis već postoji
				postoji = select(z for z in KompletnaInfrastruktura
					if z.ip_address == ip_address and z.internet_address == internet_address).exists()

				if not postoji:
					KompletnaInfrastruktura(
						ip_address = ip_address,
						internet_address = internet_address,
						reputation = reputation,
						isp = isp,
						country = country,
						tor = tor,
						tcp_ports = tcp_ports
					)
					broj_upisanih += 1

			except Exception as e:
				print(f"[!] Greška pri parsiranju zapisa: {zapis}")
				print(f"    Detalji: {e}")

		return render_template("sken.html", domena = domena, pokrenuto = True, broj = broj_upisanih)

	return render_template("sken.html", pokrenuto = False)

# Ruta za otvaranje stranice koja služi za učitavanje podataka iz baze - HTML u kojem se nalaze i grafovi.
@app.route("/pregled")
@db_session
def pregled():
	zapisi = select(z for z in KompletnaInfrastruktura)[:]
	isp_counter = Counter(z.isp for z in zapisi)
	ip_counter = Counter(z.ip_address for z in zapisi)

	top_isp = dict(isp_counter.most_common(5))
	top_ip = dict(ip_counter.most_common(10))

	return render_template("pregled.html", zapisi = zapisi, top_isp = top_isp, top_ip = top_ip)

# Ruta za učitavanje stranice koja služi za odrađivanje promjena u bazi podataka.
@app.route("/promjene")
@db_session
def promjene():
	zapisi = select(z for z in KompletnaInfrastruktura)[:]
	return render_template("promjene.html", zapisi = zapisi)

# Ruta za učitavanje stranice na kojoj upisujemo i dodajemo nove podatke u bazu podataka.
@app.route("/dodaj", methods = ["GET", "POST"])
@db_session
def dodaj():
	if request.method == "POST":
		KompletnaInfrastruktura(
			ip_address = request.form["ip_address"],
			reputation = int(request.form["reputation"]),
			internet_address = request.form["internet_address"],
			isp = request.form["isp"],
			country = request.form["country"],
			tor = request.form["tor"],
			tcp_ports = request.form["tcp_ports"]
		)

		return redirect(url_for("promjene"))
	return render_template("dodaj.html")

# Ruta za učitavanje stranice na kojoj možemo mijenjati postojeće zapise u bazi podataka.
@app.route("/uredi/<int:id>", methods = ["GET", "POST"])
@db_session
def uredi(id):
	zapis = KompletnaInfrastruktura.get(id = id)
	if request.method == "POST":
		zapis.ip_address = request.form["ip_address"]
		zapis.reputation = int(request.form["reputation"])
		zapis.internet_address = request.form["internet_address"]
		zapis.isp = request.form["isp"]
		zapis.country = request.form["country"]
		zapis.tor = request.form["tor"]
		zapis.tcp_ports = request.form["tcp_ports"]
		return redirect(url_for("promjene"))
	return render_template("uredi.html", zapis = zapis)

# Ruta za brisanje kompletnog sloga u bazi podataka sa odabranim id-em.
@app.route("/obrisi/<int:id>")
@db_session
def obrisi(id):
	zapis = KompletnaInfrastruktura.get(id = id)
	if zapis:
		zapis.delete()
	return redirect(url_for("promjene"))

if __name__ == "__main__":
	app.run(host = '0.0.0.0', port = 8080)
