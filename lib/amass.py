import os
import uuid
import subprocess
import json
import threading

def _exec_and_readlines(cmd):
    print (cmd)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    return [j for j in stdout.splitlines() if j != b'\n']

def run_amass(domain, config_path, temp_dir='/tmp', timeout=60):

    filename = str(uuid.uuid4())
    temp_path = os.path.join(temp_dir,'{0}.json'.format(filename))
    #temp_path = '{0}.json'.format(filename)

    run_passive = [
        'amass','enum',
        '-d', domain,
        '-config', config_path,
        '-timeout', str(timeout),
        '--passive'
    ]
    print (' '.join(run_passive))

    get_domains = [
        'amass','db',
        '-d', domain,
        '-names'
    ]
    print (' '.join(get_domains))

    results = []

    try:
        _exec_and_readlines(run_passive)
        domains = _exec_and_readlines(get_domains)
        print (domains)
        for subdomain in domains:
            doc_json = {"name":subdomain.decode('utf-8'),"domain":domain,"addresses":''}
            results.append(doc_json)

    except Exception as err:
        print (err)

    return results