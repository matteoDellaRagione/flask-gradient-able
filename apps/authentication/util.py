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
        "indirizzi": addresses,
        "server mail": mail_servers
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
        'server mail': mail_servers,
        'indirizzi': addresses,
        'conf': conf
    }
    
    return data

def domain2IP(json):
    hosts = json['hosts']
    resolved_hosts = {}

    for host_entry in hosts:
        host = host_entry.split(':')[0]  # prendi solo l'host prima dei due punti
        try:
            # Esegui nslookup per l'host
            result = subprocess.run(['nslookup', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

             # Trova tutte le linee che contengono l'indirizzo IP
            ip_addresses = re.findall(r'Address: (\d+\.\d+\.\d+\.\d+)', output)
            if ip_addresses:
                resolved_hosts[host] = ip_addresses[-1]  # Prendi l'ultimo indirizzo IP trovato
            else:
                resolved_hosts[host] = "No IP found"
        except Exception as e:
            resolved_hosts[host_entry] = f"Error: {str(e)}"

    json['resolved_hosts'] = resolved_hosts
    return json

def merge_json(json1, json2,json3):
    merged = {}

    # Unisci indirizzi
    indirizzi_set = set(json1.get('indirizzi', [])) | set(json2.get('indirizzi', [])) | set(json3.get('ips', []))
    merged['indirizzi'] = list(indirizzi_set)

    # Unisci server mail
    mail_set = set(json1.get('server mail', [])) | set(json2.get('server mail', []))
    merged['server mail'] = list(mail_set)

    # Unisci conf se esiste(da modificare visto che potrebbe esserci o no conf solo nel json2)
    if 'conf' in json1:
        conf_set = set(json1.get('conf', []))
        merged['conf'] = list(conf_set)
    
    if 'hosts' in json3:
        hosts_set = set(json3.get('hosts', []))
        merged['hosts'] = list(hosts_set)
    
    if 'emails' in json3:
        emails_set = set(json3.get('emails', []))
        merged['emails'] = list(emails_set)
    
    if 'interesting_urls' in json3:
        urls_set = set(json3.get('interesting_urls', []))
        merged['interesting_urls'] = list(urls_set)

    #if 'shodan' in json3:
     #   shodan_set = set(json3.get('shodan', []))
      #  merged['shodan'] = list(shodan_set)
    #DA FARE aggiungere in caso ASNS
    
    return merged

def run_theharvester(domain, output_file):
    command = f"theHarvester -d {domain} -b anubis,baidu,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,subdomaincenter,subdomainfinderc99,threatminer,urlscan,yahoo -f {output_file}"
    subprocess.run(command, shell=True)

def searchShodan(IP):
    #DA FARE renderlo asincrono visto che ci mette un po' di tempo
    api_key = '9h1GRXYcYIWVhxr9bqk3aXCfkCvnMxAE'
    api = shodan.Shodan(api_key)
    try:
    # Esegui una ricerca host su Shodan
        informations = api.host(IP)

    # Costruisci il dizionario dei risultati
        result = {
            "ip": informations['ip_str'],
            "organization": informations.get('org', 'N/A'),
            "os": informations.get('os', 'N/A'),
            "services": [],
            "vulnerabilities": []
        }

    # Aggiungi i servizi aperti al dizionario
        for item in informations['data']:
            service_info = {
                "port": item['port'],
                "service": item.get('product', 'N/A'),
                "version": item.get('version', 'N/A'),
                "banner": item.get('data', 'N/A').split('\n')[0]
            }
            result["services"].append(service_info)

    # Aggiungi le vulnerabilità al dizionario
        if 'vulns' in informations:
            for vuln in informations['vulns']:
                cve = vuln.replace('!', '')
                vuln_info = {
                    "vulnerability": cve,
                    "description": informations['vulns'][vuln]['summary']
                }
                result["vulnerabilities"].append(vuln_info)

    # Converti il dizionario in JSON e stampalo
        return result

    except shodan.APIError as e:
        error_result = {
            "error": str(e)
        }
        print(json.dumps(error_result, indent=2))

