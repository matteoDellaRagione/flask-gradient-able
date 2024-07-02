# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request,jsonify
from flask_login import login_required
from jinja2 import TemplateNotFound
from apps.authentication.util import *
from threading import Thread
import os

  

@blueprint.route('/index')
@login_required
def index():
    domain = "conad.it"
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"
    whois_json = whois_to_json(domain)
    dnsrecon_json= dnsrecon(domain)
    host_json= host(domain)
    theharvester_thread = Thread(target=run_theharvester, args=(domain, theharvester_output_file))
    theharvester_thread.start()
    return render_template('home/index.html', segment='index',whois_json=whois_json,dnsrecon_json=dnsrecon_json,host_json=host_json)

@blueprint.route('/theharvester_status')
@login_required
def theharvester_status():
    domain = "conad.it"
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"

    if os.path.exists(theharvester_output_file):
        with open(theharvester_output_file, 'r') as f:
            theharvester_json = json.load(f)
        dnsrecon_json = request.args.get('dnsrecon_json')
        host_json = request.args.get('host_json')
        
        # Converti da stringa JSON a oggetto JSON
        dnsrecon_json = json.loads(dnsrecon_json)
        host_json = json.loads(host_json)    
        # Unisci i JSON
        combined_json = merge_json(dnsrecon_json, host_json, theharvester_json)
        return (combined_json)

    else:
        return jsonify({"status": "processing"})

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
