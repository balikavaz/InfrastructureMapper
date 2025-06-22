FROM python:3.12.3

# Instalacija nmap skenera kao sistemskog alata
RUN apt-get update && \
	apt-get install -y nmap && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR InfrastructureMapper/
COPY requirements.txt req.txt
RUN pip3 install -r req.txt
COPY . .
EXPOSE 8080
CMD ["python3", "-u", "infrastructure_mapper.py"]
