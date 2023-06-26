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

def run_amass(domain, config_path, temp_dir='/tmp', timeout=1):

    filename = str(uuid.uuid4())
    temp_path = os.path.join(temp_dir,'{0}.json'.format(filename))
    #temp_path = '{0}.json'.format(filename)

    tool_cmd = [
        'amass','enum',
        '-d', domain,
        '-json', temp_path,
        '-config', config_path,
        '-timeout', str(timeout),
        '--passive'
    ]
    print (' '.join(tool_cmd))

    # for line in _exec_and_readlines(dirsearcher_cmd):
    #     if not line:
    #         continue

    results = []

    try:
        _exec_and_readlines(tool_cmd)

        with open(temp_path,'r') as f:
            documents = [doc.strip() for doc in f.readlines()]
            for doc in documents:
                results.append(json.loads(doc))
            os.remove(temp_path)
    except Exception as err:
        print (err)

    return results