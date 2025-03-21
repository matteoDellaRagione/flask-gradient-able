# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template,request,jsonify,session,current_app,send_file
from flask_login import login_required
from jinja2 import TemplateNotFound,Template
from apps.authentication.util import *
from threading import Thread
import os
import shutil
import concurrent.futures
import time
import json

  

@blueprint.route('/index')
@login_required
def index():
    return render_template('home/sample-page.html', segment='sample-page')

@blueprint.route('/search', methods=['GET'])
@login_required
def searchDomain():
    domain = request.args.get('domain')
    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Error: Domain not valid")
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"
    if not os.path.exists(theharvester_output_file):
        theharvester_thread = Thread(target=run_theharvester, args=(domain, theharvester_output_file))
        theharvester_thread.start()
    return render_template('home/index.html', segment='index', domain=domain)

@blueprint.route('/theharvester_status',methods=['GET'])
@login_required
def theharvester_status():
    domain = request.args.get('domain')
    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Error: Domain not valid")
    theharvester_output_file = f"/tmp/{domain}_theharvester.json"

    if os.path.exists(theharvester_output_file):
        with open(theharvester_output_file, 'r') as f:
            theharvester_json = json.load(f)
        theharvester_json['hosts'] = clean_hosts(theharvester_json['hosts'])
        dnsrecon_json = dnsrecon(domain)
        host_json = host(domain)
        shodan_json = domainShodan(domain)  
        # Unisci i JSON
        combined_json = merge_json(dnsrecon_json, host_json, theharvester_json, shodan_json)
        return (combined_json)

    else:
        return jsonify({"status": "processing"})

@blueprint.route('/search_shodan', methods=['GET'])
@login_required
def search_shodan_route_gowitness():
    json_data = request.args.get('json')
    domain = request.args.get('domain')
    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Errore: Domain not valid")
    
    if not json_data:
        return render_template('home/sample-page.html',error="Error: Missing Json")
    
    # Definire il nome del file, puoi personalizzarlo in base alle tue esigenze
    filename = f"/tmp/{domain}_shodan.json"
    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            shodan_json = json.load(f)
            return shodan_json

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
    total_critical_vulns = 0
    total_high_vulns = 0
    total_medium_vulns = 0
    total_low_vulns = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for ip in ips:
            # Aggiungi un ritardo di 1 secondo prima di ogni richiesta
            time.sleep(1.5)
            futures.append(executor.submit(searchShodan, ip))

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)

                    total_ports_80 += sum(1 for service in result['services'] if service['port'] == 80)
                    total_ports_443 += sum(1 for service in result['services'] if service['port'] == 443)
                    total_other_ports += sum(1 for service in result['services'] if service['port'] not in [80, 443])

                    total_critical_vulns += result['criticalVulns']
                    total_high_vulns += result['highVulns']
                    total_medium_vulns += result['mediumVulns']
                    total_low_vulns += result['lowVulns']
            except Exception as e:
                print({"ip": ip, "error": str(e)})
    gowitness(results,urls,domain)
    final_result = {
        "results": results,
        "total_ports_80": total_ports_80,
        "total_ports_443": total_ports_443,
        "total_other_ports": total_other_ports,
        "total_critical_vulns": total_critical_vulns,
        "total_high_vulns": total_high_vulns,
        "total_medium_vulns": total_medium_vulns,
        "total_low_vulns": total_low_vulns,
        "total_vulns": total_critical_vulns + total_high_vulns + total_medium_vulns +total_low_vulns
    }

    # Scrivere il dizionario nel file JSON
    with open(filename, 'w') as json_file:
        json.dump(final_result, json_file, indent=4)
    return final_result

@blueprint.route('/linkedinDump',methods=['GET'])
@login_required
def linkedinDump():
    linkedinUrl = request.args.get('url')
    domain = request.args.get('domain')
    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Error: Domain not valid")
    if not validateLinkedInURL(linkedinUrl):
        return render_template('home/sample-page.html',error="Error: URL not valid")

    verified_emails = domain_search(domain)
    pattern = verified_emails.get('pattern')
    linkedin = linkedinDumper(linkedinUrl)
    
    emails = createEmail(pattern,domain,linkedin)

    combined_data = {
    "verified_emails": verified_emails,
    "guessable_emails": emails,
    "linkedinDump": linkedin
    }
    return combined_data

@blueprint.route('/get_chart_data',methods=['POST'])
@login_required
def get_chart_data():
    vulns = request.json
    series = vulns.get('series', [])
    data = {
        "labels": ["Critical", "High", "Medium", "Low"],
        "series": series
    }
    return data

@blueprint.route('/gowitness_images',methods=['GET'])
@login_required
def show_images():
    domain = request.args.get('domain')
    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Error: Domain not valid")
    src_directory = f"/tmp/{domain}"
    
    dst_directory = os.path.join(current_app.root_path, 'static/assets/gowitness')

    images = [f for f in os.listdir(src_directory) if f.endswith('.png')]

    # Copia le immagini dalla directory temporanea alla directory statica
    for image in images:
        shutil.copy2(os.path.join(src_directory, image), dst_directory)
    
     # Passa la lista dei nomi di file al template
    rendered_template = render_template('home/gowitness.html', images=images)
    #Da fare un crontab che elimina le immagini da static/assets/gowitness
    return rendered_template

@blueprint.route('/generateReport',methods=['POST'])
@login_required
def generate_report():
    # Ricevi i JSON dal client
    theharvester_json = request.json.get('json1')
    shodan_json = request.json.get('json2')
    domain = request.json.get('domain')

    if not validateDomain(domain):
        return render_template('home/sample-page.html',error="Errore: Domain not valid")

    if not theharvester_json or not shodan_json:
        return render_template('home/sample-page.html',error="Error: Missing Json")
    
    #output_directory = '/home/kali/flask-gradient-able/Reports'
    output_directory = '/Reports'

    # File LaTeX e PDF con nomi personalizzati
    latex_file = os.path.join(output_directory, f'{domain}.tex')
    pdf_file = os.path.join(output_directory, f'{domain}.pdf')

    # Genera il report LaTeX usando Jinja2
    with open('apps/templates/report_template.tex') as f:
        template = Template(f.read())
    
    escaped_shodan_json = escape_latex_in_json(shodan_json)
    escaped_theharvester_json = escape_latex_in_json(theharvester_json)
    escaped_domain = escape_latex(domain)
    
    report_content = template.render(json1=escaped_theharvester_json, json2=escaped_shodan_json, domain=escaped_domain)

    # Scrivi il contenuto LaTeX in un file temporaneo
    with open(latex_file, 'w') as f:
        f.write(report_content)
    
    # Compila il file LaTeX in PDF usando pdflatex due volte
    try:
        for _ in range(2):  # Esegui pdflatex due volte
            result = subprocess.run(
                ['pdflatex', '-output-directory=' + output_directory, latex_file],
                check=True
            )
    except subprocess.CalledProcessError as e:
        # Se c'è un errore durante la compilazione, lo gestisci qui
        return render_template('home/sample-page.html', error="Error: LaTeX compilation failed")
    
    # Restituisci il PDF al client
    if os.path.exists(pdf_file):
        return send_file(pdf_file, as_attachment=True)
    else:
        return render_template('home/sample-page.html',error="Error: Generation of Report Failed")

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
