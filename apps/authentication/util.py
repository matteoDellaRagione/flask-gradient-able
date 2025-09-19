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
import time
import sys
import requests
from urllib.parse import urlparse
import tldextract
# Inspiration -> https://www.vitoshacademy.com/hashing-passwords-in-python/

def extract_base_domain(domain):
    # Usa tldextract per separare subdomain, domain e suffix
    extracted = tldextract.extract(domain)
    return extracted.domain + "." + extracted.suffix

def extract_org_name(domain):
    # Restituisce solo il nome del dominio, es: "juventus"
    extracted = tldextract.extract(domain)
    return extracted.domain

def validateDomain(domain):
    if domain and re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return True
    else:
         return False

def validateLinkedInURL(url):
    pattern = r'^https:\/\/www\.linkedin\.com\/company\/[a-zA-Z0-9-]+\/$'
    if url and re.match(pattern, url):
        return True
    else:
        return False

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
        
        if ip_addresses:
            return host, ip_addresses[-1]  # Prendi l'ultimo indirizzo IP valido trovato
        else:
            return host, "No IP found"
    except Exception as e:
        return host, f"Error: {str(e)}"

def domain2IP(json_data):
    hosts = [host_entry for host_entry in json_data['domini']]  
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

def merge_json(json1, json2, json3, json4, json5, json6=None):
    merged = {}

    # Unisci indirizzi IP
    indirizzi_set = set(json1.get('IP', [])) \
        | set(json2.get('IP', [])) \
        | set(json3.get('ips', [])) \
        | set(json1.get('mail server', [])) \
        | set(json5.get('ips', [])) \
        | set(json4.get('ips', []))
    
    if json6:
        indirizzi_set |= set(json6.get('ips', []))
    
    merged['IP'] = list(indirizzi_set)

    # Unisci mail server
    mail_set = set(json1.get('mail server', [])) | set(json2.get('mail server', []))
    merged['server mail'] = list(mail_set)
    merged['numServerMail'] = len(merged['server mail'])

    # Configurazioni
    conf_set = set(json1.get('conf', []))
    merged['conf'] = list(conf_set)
    
    # Domini
    hosts_set = set()
    if json3:
        hosts_set |= set(json3.get('hosts', []))
    if json4:
        hosts_set |= set(json4.get('hostnames', []))
    if json5:
        hosts_set |= set(json5.get('hostnames', []))
    if json6:
        hosts_set |= set(json6.get('domains', []))
    
    merged['domini'] = list(hosts_set)
    merged['numDomini'] = len(merged['domini'])

    # Email
    emails_set = set(json3.get('emails', [])) if json3 else set()
    merged['emails'] = list(emails_set)
    merged['numEmail'] = len(merged['emails'])

    # URL interessanti
    urls_set = set(json3.get('interesting_urls', [])) if json3 else set()
    merged['interesting_urls'] = list(urls_set)
    merged['numUrls'] = len(merged['interesting_urls'])

    translated_json = domain2IP(merged)

    # Aggiungi i resolved_hosts come URL
    if 'resolved_hosts' in translated_json:
        resolved_urls = [f"https://{host}" for host in translated_json['resolved_hosts'].keys()]
        translated_json['interesting_urls'].extend(resolved_urls)
        translated_json['interesting_urls'] = list(set(translated_json['interesting_urls']))
        translated_json['numUrls'] = len(translated_json['interesting_urls'])

    # Costruisci domain_urls
    translated_json['domain_urls'] = {}
    for domain in translated_json['domini']:
        matching_urls = [url for url in translated_json['interesting_urls'] if domain in url]
        if matching_urls:
            translated_json['domain_urls'][domain] = matching_urls
    translated_json['numDomain_urls'] = len(translated_json['domain_urls'])

    return rmDuplicati(translated_json)


def run_theharvester(domain, output_file):
    command = [
        "theHarvester",
        "-d", domain,
        "-b", "baidu,bing,bingapi,certspotter,crtsh,duckduckgo,hackertarget,otx,rapiddns,subdomaincenter,subdomainfinderc99,threatminer,urlscan,yahoo",
        "-f", output_file
    ]
    
    subprocess.run(command, check=True)

def run_amass(domain, output_file):
    command = [
        "amass",
        "enum", "-passive",
        "-d", domain,
        "-o", output_file
    ]
    
    subprocess.run(command, check=True)

def amass_json(file_path, base_domain):
    domains = set()
    ips = set()

    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ipv6_pattern = r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b"
    domain_pattern = r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    base = base_domain.lower()

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = ansi_escape.sub('', line.strip())  # rimuove i codici ANSI
            line_lower = line.lower()

            # IPs
            ips.update(re.findall(ipv4_pattern, line))
            ips.update(re.findall(ipv6_pattern, line, re.IGNORECASE))

            # Domains
            for domain in re.findall(domain_pattern, line_lower):
                if base in domain:
                    domains.add(domain)

    output = {
        "domains": sorted(domains),
        "ips": sorted(ips)
    }

    return output

def reverseDNSshodan(IP):
    with open('/ApiKeys/shodan.txt', 'r') as file:
        api_key = file.read().strip()
    api = shodan.Shodan(api_key)
    try:
    # Esegui una ricerca host su Shodan
        host = api.host(IP)
        return host.get('hostnames', [])
    except shodan.APIError as e:
        print(f"Errore API Shodan: {e}")
        return []

def fileDNSall(domain, json_data):
    filename = f"/tmp/{domain}_reverseDNS.json"
    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            reverse_json = json.load(f)
        return reverse_json

    ips = json_data.get("IP", [])

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for ip in ips:
            # Aggiungi un ritardo di 1 secondo prima di ogni richiesta
            time.sleep(1.5)
            futures.append(executor.submit(reverseDNSshodan, ip))

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.extend(result)
            except Exception as e:
                print({"ip": ip, "error": str(e)})

    # Rimuovi duplicati
    new_domains = list(set(results))

    # Aggiungili al campo 'domini' del JSON iniziale
    if 'domini' not in json_data:
        json_data['domini'] = []

    json_data['domini'] = list(set(json_data['domini']) | set(new_domains))
    json_data['numDomini'] = len(json_data['domini'])
    
    # Aggiungi eventuali nuovi domini a 'interesting_urls' se presenti lì
    if 'interesting_urls' not in json_data:
        json_data['interesting_urls'] = []

    for domain in new_domains:
        for url in json_data['interesting_urls']:
            if domain in url:
                break  # già presente
        else:
            # Se nessun URL lo contiene, prova ad aggiarne uno "generico"
            json_data['interesting_urls'].append(f"https://{domain}")

    json_data['interesting_urls'] = list(set(json_data['interesting_urls']))
    json_data['numUrls'] = len(json_data['interesting_urls'])

    # Ricostruisci il mapping dominio → URL
    json_data['domain_urls'] = {}
    for domain in json_data['domini']:
        matching_urls = [url for url in json_data['interesting_urls'] if domain in url]
        if matching_urls:
            json_data['domain_urls'][domain] = matching_urls
    json_data['numDomain_urls'] = len(json_data['domain_urls'])

    # Salva il risultato per usi futuri
    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=4)

    return json_data


def searchShodan(IP):
    with open('/ApiKeys/shodan.txt', 'r') as file:
        api_key = file.read().strip()
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
            "criticalVulns": 0,
            "totalVulns": 0
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
        result['totalVulns'] = counterCritical + counterHigh + counterMedium + counterLow
                    
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

def create_url(ip, port):
    if port == 443:
        return f"https://{ip}"
    else:
        return f"http://{ip}:{port}"


def run_gowitness(url,domain):
    if not checkURLgowitness(url):
        directory = f"/tmp/{domain}"
        if not os.path.exists(directory):
            os.makedirs(directory)
        command = [
            "gowitness",
            "scan",
            "single",
            "-s", directory,
            "--screenshot-format", "png",
            "-u",
            url
        ]
        subprocess.run(command)

def gowitness(results, urls, domain):
    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Error: Domain not valid")
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

    # Controlla e modifica gli URL se necessario
    updated_urls = set()
    for url in output["urls"]:
        if not url.startswith("http://") and not url.startswith("https://"):
            updated_urls.add(f"http://{url}")
            updated_urls.add(f"https://{url}")
        else:
            updated_urls.add(url)

    output["urls"] = list(updated_urls)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_gowitness, url, domain) for url in output["urls"]]
        concurrent.futures.wait(futures)

def linkedinDumper(linkedinUrl):
    os.chdir("LinkedInDumper-main")
    with open('/ApiKeys/linkedin.txt', 'r') as file:
        li_at = file.read().strip()
    command = [
        'python3', 'linkedindumper.py', '--url', linkedinUrl, 
        '--cookie', li_at, 
        '--quiet'
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    
    if result.returncode != 0:
        # Gestione errore
        raise Exception(f"Errore nell'esecuzione del comando: {result.stderr}")
    
    output_lines = result.stdout.split('\n')
    csv_lines = [line for line in output_lines if not line.startswith('Progress')]
    
    f = io.StringIO('\n'.join(csv_lines))
    reader = csv.DictReader(f, delimiter=';')
    data = [row for row in reader]

    #DA PROVARE
    headers = data[0][None]
    
    # Creare una lista di dizionari trasformati
    linkedin = []
    for entry in data[1:]:
        details = entry[None]
        transformed_entry = {headers[i]: details[i] for i in range(len(headers))}
        linkedin.append(transformed_entry)
    return linkedin

def domain_search(domain):
    with open('/ApiKeys/hunterio.txt', 'r') as file:
        api_key = file.read().strip()
    
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
    with open('/ApiKeys/shodan.txt', 'r') as file:
        api_key = file.read().strip()
    api = shodan.Shodan(api_key)
    info = api.info()
    try:
        query = f'hostname:"*.{domain}"'
        result = api.search(query)
        all_hostnames = []
        all_ips = []
        matches = result.get("matches", [])
        if matches:       
            for match in matches:
            # Accedi alla lista di hostnames all'interno di ciascun elemento di "matches"
                hostnames = match.get("hostnames", [])
                ip = match.get("ip_str")
                if ip:
                    all_ips.append(ip)
            # Stampa gli hostnames per ogni elemento di "matches"
                for hostname in hostnames:
                    all_hostnames.append(hostname)

            json = {
            "ips": all_ips,
            "hostnames": all_hostnames
            }
            return json
    except shodan.APIError as e:
        return jsonify({'error': str(e)}), 500

def shodanOrg(org, domain):
    filename = f"/tmp/{domain}_shodanOrg.json"
    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            reverse_json = json.load(f)
        return reverse_json
    with open('/ApiKeys/shodan.txt', 'r') as file:
        api_key = file.read().strip()
    api = shodan.Shodan(api_key)
    info = api.info()
    try:
        query = f'org:"{org}"'
        result = api.search(query)
        all_ips = []
        all_hostnames = []
        matches = result.get("matches", [])
        if matches:
            for match in matches:
                hostnames = match.get("hostnames", [])
                ip = match.get("ip_str")
                if ip:
                    all_ips.append(ip)
                for hostname in hostnames:
                    all_hostnames.append(hostname)
            jsons = {
            "ips": all_ips,
            "hostnames": all_hostnames
            }
            with open(filename, 'w') as f:
                json.dump(jsons, f, indent=4)
            return jsons
        else:
            return jsonify({'error': 'No informations found from shodanOrg'})
    except shodan.APIError as e:
        return jsonify({'error': str(e)}), 500

def checkURLgowitness(url):
     # Sostituzione per seguire lo schema di GoWitness
    filename = (
        url.replace('://', '---')  # Sostituisce il protocollo con ---
           .replace(':', '-')      # Sostituisce i due punti con -
           .replace('/', '-')      # Sostituisce gli slash con -
    )
    filename += '.png'

    # Verifica se il file esiste
    return os.path.isfile(filename)

def escape_latex(text):
    if not isinstance(text, str):
        return text
    
    text = re.sub(r'[^\x20-\x7E]', '', text)  # Rimuove tutti i caratteri non stampabili

    # Sostituzione dei caratteri speciali con le loro versioni LaTeX escapate
    replacements = {
        '\\': r'\textbackslash{}',
        '&': r'\&',
        '%': r'\%',
        '$': r'\$',
        '#': r'\#',
        '_': r'\_',
        '{': r'\{',
        '}': r'\}',
        '~': r'\~{}',
        '^': r'\^'
    }
    
    
    for original, replacement in replacements.items():
        text = text.replace(original, replacement)
    
    return text

def clean_hosts(hosts_list):
    cleaned_hosts = []
    for host in hosts_list:
        cleaned_host = host.split(':')[0]  
        cleaned_hosts.append(cleaned_host)
    return cleaned_hosts

def escape_latex_in_json(data):
    if isinstance(data, dict):
        return {key: escape_latex_in_json(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [escape_latex_in_json(item) for item in data]
    elif isinstance(data, str):
        return escape_latex(data)
    else:
        return data
