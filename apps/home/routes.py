# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import subprocess
import re
import json
from apps.home import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound

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
    
    return json.dumps(host_data, indent=4)

def host(domain):
    # Esegui il comando whois
    result = subprocess.run(['host', domain], capture_output=True, text=True)
    return result.stdout    

@blueprint.route('/index')
@login_required
def index():
    domain = "nttdata.com"
    whois_json = whois_to_json(domain)
    host_json= parse_host_output(host(domain))
    return render_template('home/index.html', segment='index',whois_json=whois_json,host_json=host_json)


@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
