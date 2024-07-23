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
    return render_template('home/sample-page.html', segment='sample-page')

@blueprint.route('/search', methods=['GET'])
@login_required
def searchDomain():
    domain = request.args.get('domain')
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"
    whois_json = whois_to_json(domain)
    if not os.path.exists(theharvester_output_file):
        theharvester_thread = Thread(target=run_theharvester, args=(domain, theharvester_output_file))
        theharvester_thread.start()
    return render_template('home/index.html', segment='index', domain=domain)

@blueprint.route('/theharvester_status',methods=['GET'])
@login_required
def theharvester_status():
    domain = request.args.get('domain')
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"

    if os.path.exists(theharvester_output_file):
        with open(theharvester_output_file, 'r') as f:
            theharvester_json = json.load(f)
        dnsrecon_json = dnsrecon(domain)
        host_json = host(domain)
        shodan_json = domainShodan(domain)  
        # Unisci i JSON
        combined_json = merge_json(dnsrecon_json, host_json, theharvester_json,shodan_json)
        return (combined_json)

    else:
        return jsonify({"status": "processing"})

@blueprint.route('/search_shodan', methods=['GET'])
@login_required
def search_shodan_route_gowitness():
    json_data = request.args.get('json')
    
    if not json_data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    try:
        json_obj = json.loads(json_data)
        ips = json_obj.get('IP', [])
        urls = json_obj.get('urls', [])
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"}), 400

    results = []
    total_ports_80 = 0
    total_ports_443 = 0
    total_other_ports = 0

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

                    total_ports_80 += sum(1 for service in result['services'] if service['port'] == 80)
                    total_ports_443 += sum(1 for service in result['services'] if service['port'] == 443)
                    total_other_ports += sum(1 for service in result['services'] if service['port'] not in [80, 443])
            except Exception as e:
                print({"ip": ip, "error": str(e)})
    #stand by per testing linkedin
    #gowitness(results,urls)
    final_result = {
        "results": results,
        "total_ports_80": total_ports_80,
        "total_ports_443": total_ports_443,
        "total_other_ports": total_other_ports
    }
    return final_result

@blueprint.route('/linkedinDump',methods=['GET'])
@login_required
def linkedinDump():
    linkedinUrl = request.args.get('url')
    domain = request.args.get('domain')
    #Commenti per non sprecare cpu e API
    #linkedin = linkedinDumperTry()
    #linkedin = linkedinDumper(linkedinUrl)
    emails = [
    {
      "Email": "angelo.bernunzo@conad.it",
      "Firstname": "Angelo",
      "Lastname": "Bernunzo"
    },
    {
      "Email": "maria.morena.castrianni@conad.it",
      "Firstname": "Maria Morena",
      "Lastname": "Castrianni"
    },
    {
      "Email": "stefano.gadda@conad.it",
      "Firstname": "Stefano",
      "Lastname": "Gadda"
    }
    ]
    #Commentate per non sprecare api
    #verified_emails = domain_search(domain)
    #pattern = verified_emails.get('pattern')
    pattern = r"{first}.{last}"
    #print("Pattern: ",pattern)
    #linkedin = linkedinDumper(linkedinUrl)
    
    #Da qui 
    data = [
    {None: ['Firstname', 'Lastname', 'Position', 'Gender', 'Location', 'Profile']},
    {None: ['Mattia', 'Erroi', "Double Degree Master's Graduate | Energy and Nuclear Engineer | Politecnico di Torino | KTH Royal Institute of Technology", 'N/A', 'Greater Turin Metropolitan Area', 'https://www.linkedin.com/in/mattia-erroi']},
    {None: ['Nicolo', 'Magnani', 'Edison S.p.a', 'N/A', 'Milan', 'https://www.linkedin.com/in/nicol%C3%B2-magnani-8a3527171']},
    {None: ['Bellacicco', 'Silvana', 'impiegato presso Edison SpA', 'N/A', 'Milan', 'https://www.linkedin.com/in/bellacicco-silvana-02a891a4']},
    {None: ['Alessio', 'Ramundo', 'Risk Mandate & Costing Analyst', 'N/A', 'Italy', 'https://www.linkedin.com/in/alessio-ramundo-298447185']},
    {None: ['Noemi', 'Falchi', '#Creditanalyst helping @Arval Italia determine the financial risks evaluating the financial health of a loan supporting business strategy', 'N/A', 'Milan', 'https://www.linkedin.com/in/noemifalchi']}
    ]
    # Estrarre le intestazioni
    headers = data[0][None]
    
    # Creare una lista di dizionari trasformati
    linkedin = []
    for entry in data[1:]:
        details = entry[None]
        transformed_entry = {headers[i]: details[i] for i in range(len(headers))}
        linkedin.append(transformed_entry)
    
    # A qui da mettere in util linkedin dumpreturn transformed_data
    emails = createEmail(pattern,domain,linkedin)
    combined_data = {
    #"verified_emails": verified_emails,
    "guessable_emails": emails,
    "linkedinDump": linkedin
    }
    return combined_data

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
