# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
import hashlib
import binascii
import subprocess
import re
import json
import shodan
import concurrent.futures
import csv
import io
import sys
import requests
# Inspiration -> https://www.vitoshacademy.com/hashing-passwords-in-python/


def hash_pass(password):
    """Hash a password for storing."""

    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash)  # return bytes


def verify_pass(provided_password, stored_password):
    """Verify a stored password against one provided by user"""

    stored_password = stored_password.decode('ascii')
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password


def parse_host_output(output):
    addresses = []
    mail_servers = []

    # Espressioni regolari per trovare gli indirizzi IP e i server mail
    address_pattern = re.compile(r'has address ([\d\.]+)')
    mail_pattern = re.compile(r'mail is handled by \d+ ([\w\.\-]+)')

    # Parso l'output per trovare le corrispondenze
    for line in output.splitlines():
        address_match = address_pattern.search(line)
        mail_match = mail_pattern.search(line)
        if address_match:
            addresses.append(address_match.group(1))
        if mail_match:
            mail_servers.append(mail_match.group(1))

    # Creare un dizionario con i risultati
    host_data = {
        "IP": addresses,
        "mail server": mail_servers
    }
    
    return host_data

def host(domain):
     # Esegui il comando host
    result = subprocess.run(['host', domain], capture_output=True, text=True)
    return parse_host_output(result.stdout)  

def whois_to_json(domain):
    # Esegui il comando whois
    result = subprocess.run(['whois', domain], capture_output=True, text=True)
    whois_output = result.stdout
    
    # Parso l'output di whois
    whois_data = {}
    for line in whois_output.splitlines():
        match = re.match(r"^(.*?):\s*(.*)$", line)
        if match:
            key, value = match.groups()
            whois_data[key.strip()] = value.strip()
    
    # Converti in JSON
    return json.dumps(whois_data, indent=4)

def dnsrecon(domain):
    # Esegui il comando dnsrecon per il dominio specificato
    result = subprocess.run(['dnsrecon', '-d', domain], capture_output=True, text=True)
    output = result.stdout
    
    # Analizza l'output
    mail_servers = []
    addresses = []
    conf = []
    
    for line in output.splitlines():
        if 'MX' in line:
            parts = line.split()
            mail_servers.append(parts[-1])
        elif f'A {domain}' in line:
            parts = line.split()
            addresses.append(parts[-1])
        elif f'TXT {domain}' in line:
            conf.append(line.split(f'{domain} ')[-1])
    
    # Crea il dizionario JSON
    data = {
        'mail server': mail_servers,
        'IP': addresses,
        'conf': conf
    }
    
    return data

def resolve_host(host):
    try:
        # Esegui nslookup per l'host
        result = subprocess.run(['nslookup', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        # Trova tutte le linee che contengono l'indirizzo IP
        ip_addresses = re.findall(r'Address: (\d+\.\d+\.\d+\.\d+)', output)
        #valid_ip_addresses = [ip for ip in ip_addresses if ip != "127.0.0.53"]
        
        if ip_addresses:
            return host, ip_addresses[-1]  # Prendi l'ultimo indirizzo IP valido trovato
        else:
            return host, "No IP found"
    except Exception as e:
        return host, f"Error: {str(e)}"

def domain2IP(json_data):
    hosts = [host_entry.split(':')[0] for host_entry in json_data['domini']]  # Prendi solo l'host prima dei due punti
    resolved_hosts = {}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_host = {executor.submit(resolve_host, host): host for host in hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                host, ip = future.result()
                if ip != "No IP found":
                    resolved_hosts[host] = ip
            except Exception as e:
                resolved_hosts[host] = f"Error: {str(e)}"

    json_data['resolved_hosts'] = resolved_hosts
    json_data['numResolvedHosts'] = len(resolved_hosts)
    return json_data

def merge_json(json1, json2,json3,json4):
    merged = {}

    # Unisci indirizzi
    indirizzi_set = set(json1.get('IP', [])) | set(json2.get('IP', [])) | set(json3.get('ips', [])) | set(json1.get('mail server', []))
    merged['IP'] = list(indirizzi_set)

    # Unisci server mail
    mail_set = set(json1.get('mail server', [])) | set(json2.get('mail server', []))
    merged['server mail'] = list(mail_set)
    merged['numServerMail'] = len(merged['server mail'])

    conf_set = set(json1.get('conf', []))
    merged['conf'] = list(conf_set)
    
    if json3 is not None and json4 is not None:
        hosts_set = set(json3.get('hosts', [])) | set(json4.get('hostnames', []))
        merged['domini'] = list(hosts_set)
        merged['numDomini'] = len(merged['domini'])
    elif json4 is None:
        hosts_set = set(json3.get('hosts', []))
        merged['domini'] = list(hosts_set)
    #aggiungi altra condizione e le numeriche del caso
    
    emails_set = set(json3.get('emails', []))
    merged['emails'] = list(emails_set)
    merged['numEmail'] = len(merged['emails'])
    
    urls_set = set(json3.get('interesting_urls', []))
    merged['interesting_urls'] = list(urls_set)
    merged['numUrls'] = len(merged['interesting_urls'])

    
    translated_json = domain2IP(merged)
    return rmDuplicati(translated_json)

def run_theharvester(domain, output_file):
    command = f"theHarvester -d {domain} -b anubis,baidu,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,subdomaincenter,subdomainfinderc99,threatminer,urlscan,yahoo -f {output_file}"
    subprocess.run(command, shell=True)

def searchShodan(IP):
    api_key = '9h1GRXYcYIWVhxr9bqk3aXCfkCvnMxAE'
    api = shodan.Shodan(api_key)
    try:
    # Esegui una ricerca host su Shodan
        informations = api.host(IP)
        filtered_services = []
        
        for item in informations['data']:
            service_info = {
                        "port": item['port'],
                        "service": item.get('product', 'N/A'),
                        "version": item.get('version', 'N/A'),
                        "banner": item.get('data', 'N/A').split('\n')[0]
                    }
            if 'http' in item:
                status_code = item['http'].get('status', None)
                if status_code is not None and not (400 <= status_code < 600):
                    http_data = item.get('data', None)
                    location_regex = r'Location: (http[^\r\n]+)'
                    match = re.search(location_regex, http_data, re.IGNORECASE)
                    if match:
                        service_info['location'] = match.group(1)
                    else: 
                        service_info['location'] = "/"
                    filtered_services.append(service_info)
                    
            else:
                filtered_services.append(service_info)
        #DA PROVARE e sistemare
        # Costruisci il dizionario dei risultati
        result = {
            "ip": informations['ip_str'],
            "organization": informations.get('org', 'N/A'),
            "os": informations.get('os', 'N/A'),
            "services": filtered_services,
            "vulnerabilities": [],
            "lowVulns": 0,
            "mediumVulns": 0,
            "highVulns": 0,
            "criticalVulns": 0
        }

        counterLow = 0
        counterMedium = 0
        counterHigh = 0
        counterCritical = 0
        for item in informations['data']:
            if 'vulns' in item:
                for vuln in item['vulns']:
                    vuln_info = {
                        "vulnerability": vuln,
                        "cvss": item['vulns'][vuln].get('cvss', 'N/A'),
                        "description": item['vulns'][vuln].get('summary', 'N/A')
                    }
                    if isinstance(vuln_info['cvss'], (int, float)):
                        if 0.0 <= vuln_info['cvss'] <= 3.9:
                            counterLow += 1
                        elif 4.0 <= vuln_info['cvss'] <= 6.9:
                            counterMedium += 1
                        elif 7.0 <= vuln_info['cvss'] <= 8.9:
                            counterHigh += 1
                        elif 9.0 <= vuln_info['cvss'] <= 10.0:
                            counterCritical += 1

                    result["vulnerabilities"].append(vuln_info)

        result['lowVulns'] = counterLow
        result['mediumVulns'] = counterMedium
        result['highVulns'] = counterHigh
        result['criticalVulns'] = counterCritical
                    
        if not filtered_services:
            return None


    # Converti il dizionario in JSON e stampalo
        return result

    #Sotto la stampa di può anche togliere
    except shodan.APIError as e:
        error_result = {
            "ip" : IP,
            "error": str(e)
        }
        print(json.dumps(error_result, indent=2))
        return None

def rmDuplicati(json):
    indirizzi = set(json['IP'])
    resolved_hosts = json['resolved_hosts']

    for host, ip in resolved_hosts.items():
        if ip != "No IP found":
            indirizzi.add(ip)

    json['IP'] = list(indirizzi)
    json['numIP'] = len(json['IP'])
    return json

def eyewitness(results, urls):
    url_set = set(urls)
    for entry in results:
        ip = entry["ip"]
        for service in entry["services"]:
            location = service.get("location", "")
            banner = service.get("banner", "")
            port = service.get("port", 80)

        # Aggiungiamo l'URL dal campo location
            if "/" in location and "200 OK" in banner:
                url_set.add(create_url(ip, port))
            else:
                url_set.add(location)

# Creiamo il nuovo JSON
    output = {
        "urls": list(url_set)
    }
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_eyewitness, url) for url in output["urls"]]
        concurrent.futures.wait(futures)

def create_url(ip, port):
    if port == 443:
        return f"https://{ip}"
    else:
        return f"http://{ip}:{port}"


def run_gowitness(url):
    command = f"gowitness -P /tmp/ --screenshot-filter 200 --disable-db single \"{url}\""
    subprocess.run(command, shell=True)

def gowitness(results, urls):
    url_set = set(urls)
    for entry in results:
        ip = entry["ip"]
        for service in entry["services"]:
            location = service.get("location", "")
            banner = service.get("banner", "")
            port = service.get("port", 80)

        # Aggiungiamo l'URL dal campo location
            if "/" in location and "200 OK" in banner:
                url_set.add(create_url(ip, port))
            else:
                url_set.add(location)

# Creiamo il nuovo JSON
    output = {
        "urls": list(url_set)
    }
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_gowitness, url) for url in output["urls"]]
        concurrent.futures.wait(futures)

def linkedinDumper(linkedinUrl):
    os.chdir("LinkedInDumper-main")
    li_at = 'AQEDAS4TeJYEgzKGAAABhlmefTcAAAGQ2b-mUU4AEhi3cbC5_OCVjENtJhHSPaa9DzAt2CNeP8UH7lU_1XGsZkDg7pHQlZaq_Sa6-sBSp7cy_kehJoq234tB7RUXgHN4VCMfzf_ApwL5DY9ZIOF08rZO'
    command = [
        'python3', 'linkedindumper.py', '--url', linkedinUrl, 
        '--cookie', li_at, 
        '--quiet'
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    #result = subprocess.run(command, stdout=sys.stdout, stderr=sys.stderr, text=True)
    
    
    if result.returncode != 0:
        # Gestione errore
        raise Exception(f"Errore nell'esecuzione del comando: {result.stderr}")
    
    output_lines = result.stdout.split('\n')
    csv_lines = [line for line in output_lines if not line.startswith('Progress')]
    
    f = io.StringIO('\n'.join(csv_lines))
    reader = csv.DictReader(f, delimiter=';')
    data = [row for row in reader]
    print(data)
    
    headers = data[0]["null"]

    # Creazione di un array di dizionari con i dati
    true_data = []
    for row in data[1:]:
        row_data = row["null"]
        entry = {headers[i]: row_data[i] for i in range(len(headers))}
        data.append(entry)
    return true_data

def linkedinDumperTry():
    # Output simulato ricevuto direttamente
    simulated_output = [
        {
            "null": [
                "Firstname",
                "Lastname",
                "Position",
                "Gender",
                "Location",
                "Profile"
            ]
        },
        {
            "null": [
                "Angelo",
                "Bernunzo",
                "Vice direttore presso Supermercato Conad Lodi",
                "N/A",
                "Lodi",
                "https://www.linkedin.com/in/angelo-bernunzo-a97007ab"
            ]
        },
        {
            "null": [
                "Maria Morena",
                "Castrianni",
                "conad",
                "N/A",
                "Milan",
                "https://www.linkedin.com/in/maria-morena-castrianni-774441227"
            ]
        },
        {
            "null": [
                "Stefano",
                "Gadda",
                "Store Manager Conad presso Cernuscostore s.r.l.",
                "N/A",
                "Cernusco sul Naviglio",
                "https://www.linkedin.com/in/stefano-gadda-21569013b"
            ]
        },
        {
            "null": [
                "Giuseppe",
                "Zuliani",
                "Store Manager Conad presso Cernuscostore s.r.l.",
                "N/A",
                "Cernusco sul Naviglio",
                "https://www.linkedin.com/in/stefano-gadda-21569013b"
            ]
        }

    ]
    
    # Estrazione delle intestazioni
    headers = simulated_output[0]["null"]
    
    # Creazione di un array di dizionari con i dati
    data = []
    for row in simulated_output[1:]:
        row_data = row["null"]
        entry = {headers[i]: row_data[i] for i in range(len(headers))}
        data.append(entry)
    return data

def domain_search(domain):
    api_key = '38efac4a66dbb53ea2ee81fa9dc60770fe57d4c4'  # Inserisci qui la tua API key di Hunter.io
    
    # URL dell'API di Hunter.io
    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}'

    # Fai la richiesta GET all'API
    response = requests.get(url)

    # Controlla lo stato della risposta
    if response.status_code == 200:
        # Converte la risposta JSON in un dizionario Python
        data = response.json()
        extracted_data = {}
    
        add_if_not_null(extracted_data, "pattern", data["data"].get("pattern"))

        social_networks = {}
        add_if_not_null(social_networks, "twitter", data["data"].get("twitter"))
        add_if_not_null(social_networks, "facebook", data["data"].get("facebook"))
        add_if_not_null(social_networks, "linkedin", data["data"].get("linkedin"))
        add_if_not_null(social_networks, "instagram", data["data"].get("instagram"))
        add_if_not_null(social_networks, "youtube", data["data"].get("youtube"))

        if social_networks:
            extracted_data["social_networks"] = social_networks

        emails = []
        for email in data["data"].get("emails", []):
            email_info = {}
            add_if_not_null(email_info, "value", email.get("value"))
            add_if_not_null(email_info, "first_name", email.get("first_name"))
            add_if_not_null(email_info, "last_name", email.get("last_name"))
            add_if_not_null(email_info, "position", email.get("position"))
            add_if_not_null(email_info, "seniority", email.get("seniority"))
            add_if_not_null(email_info, "department", email.get("department"))
            add_if_not_null(email_info, "linkedin", email.get("linkedin"))
            add_if_not_null(email_info, "twitter", email.get("twitter"))
            add_if_not_null(email_info, "phone_number", email.get("phone_number"))
        
            if email_info:
                emails.append(email_info)

        if emails:
            extracted_data["emails"] = emails

        linked_domains = data["data"].get("linked_domains", [])
        if linked_domains:
            extracted_data["linked_domains"] = linked_domains
    
        return extracted_data

    else:
        return jsonify({'error': 'Impossibile ottenere i dati'}), response.status_code

def createEmail(pattern,domain,json):
    emails = []

    for person in json:
        # Ottieni i campi necessari
        first_name = person.get('Firstname', '').lower().replace(' ', '.')
        last_name = person.get('Lastname', '').lower().replace(' ', '.')
        
        # Applica il pattern
        #Qua andrà cambiato per fare altre prove, così è solo con fist.last
        email = pattern.replace('{first}', first_name).replace('{last}', last_name)
        email = f"{email}@{domain}"

        #DA FARE validazione dell'email per vedere se esiste

        # Aggiungi l'email al risultato
        emails.append({
            "Firstname": person.get('Firstname'),
            "Lastname": person.get('Lastname'),
            "Email": email
        })

    return emails

def domainShodan(domain):
    api_key = '9h1GRXYcYIWVhxr9bqk3aXCfkCvnMxAE'
    api = shodan.Shodan(api_key)
    try:
        # Fai la query a Shodan DA VERIFICARE SE VA
        query = f'hostname:*.{domain} country:"IT"'
        result = api.search(query)
        all_hostnames = []
        matches = result.get("matches", [])
        if matches:       
            for match in matches:
            # Accedi alla lista di hostnames all'interno di ciascun elemento di "matches"
                hostnames = match.get("hostnames", [])
            # Stampa gli hostnames per ogni elemento di "matches"
            for hostname in hostnames:
                all_hostnames.append(hostname)
            json = {"hostnames": all_hostnames}
            return json
    except shodan.APIError as e:
        return jsonify({'error': str(e)}), 500

def add_if_not_null(dictionary, key, value):
        if value is not None:
            dictionary[key] = value