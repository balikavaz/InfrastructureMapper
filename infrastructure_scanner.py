#!/usr/bin/python3

import httpx
from datetime import datetime, timezone
import socket
import time
import re
import nmap
import json

# API ključ za SecurityTrails servis - dohvat sudbdomena.
APIKey = ''

# API ključ za AbuseIPDB servis - obogaćivanje informacija o IP adresama.
APIKey1 = ''
SleepInterval = 0.5

# Funkcija za prevođenje internetskih adresa (subdomain + domain) koje prikupi putem običnog DNS-a.
def DNSTranslation(DNS):
	try:
		IPAddress = socket.gethostbyname(DNS)
		time.sleep(1) # Da izbjegnemo invazivno prevođenje putem DNS-a, tu je kratka pauza.
		return IPAddress
	except socket.gaierror as e:
		IPAddress = 'None'
		return IPAddress
		pass

# Funkcija za dohvat svih poddomena (engl. subdomains) preko API-a.
def GetSubdomains(Domain):
	try:
		URL = f'https://api.securitytrails.com/v1/domain/{Domain}/subdomains'
		Headers = {
			'Host': 'api.securitytrails.com',
			'User-agent': 'curl/7.68.0',
			'accept': '*/*',
			'apikey': f'{APIKey}'
		}

		# Kreiranje HTTP2 klijenta.
		with httpx.Client(http2 = True) as Client:
			Response = Client.get(URL, headers = Headers)

		if Response.status_code == 200:
			return Response.json()
		else:
			return f' [!] Pogreska 1 u fukciji GetSubdomains: {Response.status_code} - {Response.text}'

	except Exception as e:
		return f' [!] Pogreska 2 u funkciji GetSubdomains: {e}'

# Funkcija za provjeru reputacije svake IP adrese preko API-a.
def AbuseIPDB(IPAddress):
	# HTTP Header for API
	try:
		print(f' [>] Obogaćivanje podataka za IP adresu {IPAddress} sa servisa Abuse IP Database.')
		URL = f'https://api.abuseipdb.com/api/v2/check?ipAddress={IPAddress}&maxAgeInDays=90&verbose'
		Headers = {
			'Host': 'api.abuseipdb.com',
			'User-agent': 'curl/7.68.0',
			'key': f'{APIKey1}',
			'accept': 'application/json'
		}

		# HTTP/2 format
		with httpx.Client(http2 = True) as Client:
			Response = Client.get(URL, headers = Headers)

		if Response.status_code == 200:
			return Response.json()
		else:
			print(f' [!] Pogreska 1 u funkciji AbuseIPDB: {Response.status_code} - {Response.text}')

	except Exception as e:
		print(f' [!] Pogreska 2 u funkciji AbuseIPDB: {e}')

# Funkcija za ciscenje i normalizaciju podataka iz AbuseIPDB izvoda. Parisranje JSON odgovora.
def PrintOutput(Results):
	IPA = Results['data']['ipAddress']
	AbuseConfidenceScore = Results['data']['abuseConfidenceScore']
	ISP = Results['data']['isp']
	Country = Results['data']['countryName']
	TORProxy = Results['data']['isTor']

	if TORProxy == True:
		TORProxy = 'TOR'
	else:
		TORProxy = 'NotTOR'

	Output = f'{AbuseConfidenceScore}|{ISP}|{Country}|{TORProxy}'
	return Output

# Funkcija za skeniranje otvorenih TCP portova na IP adresi.
def TCPScan(IPAddress):
	Scanner = nmap.PortScanner()
	try:
		print(f' [>] Skeniranje IP adrese {IPAddress}.')
		Scanner.scan(hosts = IPAddress, arguments = '-n -Pn -T4 -p21,22,23,25,53,80,110,139,143,443,445,1433,1521,3306,3389,8080,8443')  # Postavio sam opciju da skenira 1000 najčešće korištenih TCP portova.

		OpenPorts = []
		for Port in Scanner[IPAddress]['tcp']:
			if Scanner[IPAddress]['tcp'][Port]['state'] == 'open':
				OpenPorts.append(Port)
		return OpenPorts

	except Exception as e:
		return []

# Funkcija za spajanje dviju lista u jednu jedinstvenu koja sadrzi sva polja.
def KonsolidacijaPodataka(IPAddress_Enrichment, IPAddress_InternetAddress):
	IPInfo = {}
	for Entry in IPAddress_Enrichment:
		Parts = Entry.split("|")
		IP = Parts[0]

		# Uklanjamo drugi element (SUBDOMAIN)
		IPInfo[IP] = "|".join([Parts[0]] + Parts[2:])

	# Spajanje u novu listu
	NewList = []
	for Entry in IPAddress_InternetAddress:
		IP, Domain = Entry.split("|")
		if IP in IPInfo:
			Combined = f"{IP}|{Domain}|{IPInfo[IP].split('|', 1)[1]}"
			NewList.append(Combined)

	return NewList

# "Glavna" funkcija koja prihvaca domenu iz Front-End modula "Sken".
def PassiveDNS(Domain):
	IPAddress_Enrichment = []
	Subdomains = GetSubdomains(Domain)
	Sub1 = Subdomains.get('subdomains', [])
	print(f' [>] Za domenu {Domain} ukupni broj različitih internetskih adresa je {len(Sub1)}.')
	Sub2 = set(Sub1)

	AllIPAddresses = []
	IPAddress_InternetAddress = []

	# Pokusaj prevesti sve dohvacene internetske adrese i spremi ih privremeno u listu.
	for i in Sub1:
		Output = DNSTranslation(f'{i}.{Domain}')

		if Output == 'None':
			print(f' [!] Za internetsku adresu {i}.{Domain} nema prijevoda. Moguće je da više nije u upotrebi.')
		else:
			AllIPAddresses.append(Output)
			IPAddress_InternetAddress.append(f'{Output}|{i}.{Domain}')

	AllIPAddresses2 = set(AllIPAddresses)
	AllIPAddresses3 = list(AllIPAddresses2)
	print(f' [>] Internetska domena {Domain} je mapirana na ukupno {len(AllIPAddresses3)} različitih javnih IP adresa.')

	# Obogati sve prevedene internetske adrese
	for IP in AllIPAddresses3:
		Results = AbuseIPDB(IP)	# Dohvati podatke o reputaciji, ISP-u, zemlji.
		Reputation = PrintOutput(Results) # Dodatno pročisti AbuseIPDB dohvaćene podatke.
		TCPPorts = TCPScan(IP) # Skeniraj IP adresu po TCP portovima.
		PartialData = f'{IP}|SUBDOMAIN|{Reputation}|{TCPPorts}'
		IPAddress_Enrichment.append(PartialData)

	IPAddress_Enrichment.sort()
	IPAddress_InternetAddress.sort()

	Data = KonsolidacijaPodataka(IPAddress_Enrichment, IPAddress_InternetAddress) # Konsolidiraj podatke iz AbuseIPDB i TCP skena u jedinstvenu listu.

	print(f' [>] Prikupljanje podataka je gotovo. Dodano je ukupno {len(Data)} zapisa.')
	return Data # Završni rezultat prije spremanja u bazu podataka.

if __name__ == '__main__':
	PassiveDNS('bug.hr') # Domena samo za test ispravnosti.
