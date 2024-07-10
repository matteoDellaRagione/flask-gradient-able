# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request,jsonify,session
from flask_login import login_required
from jinja2 import TemplateNotFound
from apps.authentication.util import *
from threading import Thread
import os
import concurrent.futures
import time



  

@blueprint.route('/index')
@login_required
def index():
    domain = "conad.it"
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"
    whois_json = whois_to_json(domain)
    dnsrecon_json= dnsrecon(domain)
    host_json= host(domain)
    session['dnsrecon_json'] = dnsrecon_json
    session['host_json'] = host_json
    theharvester_thread = Thread(target=run_theharvester, args=(domain, theharvester_output_file))
    theharvester_thread.start()
    return render_template('home/index.html', segment='index',whois_json=whois_json)

@blueprint.route('/theharvester_status')
@login_required
def theharvester_status():
    domain = "conad.it"
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"

    if os.path.exists(theharvester_output_file):
        with open(theharvester_output_file, 'r') as f:
            theharvester_json = json.load(f)
        dnsrecon_json = session.get('dnsrecon_json', {})
        host_json = session.get('host_json', {})  
        # Unisci i JSON
        combined_json = merge_json(dnsrecon_json, host_json, theharvester_json)
        #true_json = domain2IP(combined_json)
        #nodupl_json = rmDuplicati(true_json)
        return (combined_json)

    else:
        return jsonify({"status": "processing"})

@blueprint.route('/search_shodan', methods=['GET'])
@login_required
def search_shodan_route_eyewitness():
    json_data = request.args.get('json')
    
    if not json_data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    try:
        json_obj = json.loads(json_data)
        ips = json_obj.get('indirizzi', [])
        urls = json_obj.get('urls', [])
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"}), 400

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for ip in ips:
            # Aggiungi un ritardo di 1 secondo prima di ogni richiesta
            time.sleep(1)
            futures.append(executor.submit(searchShodan, ip))

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as e:
                print({"ip": ip, "error": str(e)})
    #Funziona ma troppo tempo e CPU            
    #eyewitness(results,urls)
    return results

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
