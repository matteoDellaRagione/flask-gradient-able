# Usa l'immagine di Kali Linux come base
FROM kalilinux/kali-rolling

# Aggiorna il sistema e correggi eventuali pacchetti rotti
RUN apt-get update && apt-get upgrade -y && apt-get install -f

# Installa le dipendenze necessarie per compilare Python dai sorgenti
RUN apt-get install -y wget build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev

# Scarica e compila Python 3.9 dai sorgenti
RUN wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tgz
RUN tar xzf Python-3.9.0.tgz
RUN cd Python-3.9.0 && ./configure --enable-optimizations && make altinstall

# Assicurati che Python 3.9 sia disponibile nel PATH
ENV PATH="/usr/local/bin:$PATH"

# Installa i tool specifici
RUN apt-get install -y theharvester dnsrecon host dnsutils gowitness texlive python3.13-venv texlive-full amass

# Imposta le variabili d'ambiente
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Copia il file requirements.txt
COPY requirements.txt .

# Installa le dipendenze Python
RUN /usr/local/bin/pip3.9 install --upgrade pip
RUN /usr/local/bin/pip3.9 install --no-cache-dir -r requirements.txt

# Copia il resto del codice
COPY . .

# Crea la directory ApiKeys e i file .txt
RUN mkdir -p ApiKeys && \
    touch ApiKeys/shodan.txt && \
    touch ApiKeys/hunterio.txt && \
    touch ApiKeys/linkedin.txt

# Comando di default per avviare Gunicorn e Flask
CMD ["/usr/local/bin/gunicorn", "--config", "gunicorn-cfg.py", "run:app"]
