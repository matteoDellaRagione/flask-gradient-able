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

def merge_json(json1, json2):
    merged = {}

    # Unisci indirizzi
    indirizzi_set = set(json1.get('indirizzi', [])) | set(json2.get('indirizzi', []))
    merged['indirizzi'] = list(indirizzi_set)

    # Unisci server mail
    mail_set = set(json1.get('server mail', [])) | set(json2.get('server mail', []))
    merged['server mail'] = list(mail_set)

    # Unisci conf se esiste(da modificare visto che potrebbe esserci o no conf solo nel json2)
    if 'conf' in json1 or 'conf' in json2:
        conf_set = set(json1.get('conf', [])) | set(json2.get('conf', []))
        merged['conf'] = list(conf_set)
    
    return merged