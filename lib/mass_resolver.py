import gc
import json
import subprocess
import uuid
import os
from tld import get_tld, parse_tld
from pathlib import Path


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

class MassDnsResolver:
    def __init__(self, trusted_resolvers_path, mass_resolvers_path, threads=10000, temp_directory_path='/tmp'):
        self.trusted_resolvers_path = trusted_resolvers_path
        self.mass_resolvers_path = mass_resolvers_path
        self.temp_directory_path = temp_directory_path
        self.threads = threads
            

    def _generate_fake_domains(self, domains):
        fake_domains = set()
        wildcard_responses = []
        random = str(uuid.uuid4())

        for domain in domains:
            try:
                res = get_tld(domain, fix_protocol=True, as_object=True)
                top_domain = res.fld
                subdomain =  res.subdomain
                sub_subdomain = '.'.join(subdomain.split('.')[1:])
            except:
                continue

            fake_domain = '{0}.{1}'.format(random,top_domain)
            fake_domains.add(fake_domain)

            if sub_subdomain:
                fake_domain = '{0}.{1}.{2}'.format(random,sub_subdomain,top_domain)
                fake_domains.add(fake_domain)

        return list(fake_domains)

    @staticmethod
    def _exec_and_readlines(cmd, domains):

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        proc.stdin.write('\n'.join(domains).encode())
        stdout, stderr = proc.communicate()

        return [j.decode('utf-8').strip() for j in stdout.splitlines() if j != b'\n']

    def _simple_resolve(self, domains, resolvers_path, types=['A','CNAME'], blacklist=[]):

        print ('Simple resolve was requested for domains:{}...'.format(domains[:20]))
        results_set = set()

        for domains_chunk in chunks(domains, 100000):
            if len(results_set) > 10000:
                print ('It looks that wildcard defense was bypassed, return nothing')
                return []

            print ('simple chunk', len(domains_chunk))
            filename = str(uuid.uuid4())
            Path(self.temp_directory_path).mkdir(parents=True, exist_ok=True)
            temp_path = os.path.join(self.temp_directory_path, filename)

            #create dir

            massdns_cmd = [
                'massdns',
                '-s', str(self.threads),
                '-o', 'J',
                '-r', resolvers_path,
                '-w', temp_path,
                '--flush'
            ]

            for t in types:
                massdns_cmd += ['-t',t]

            print (' '.join(massdns_cmd))

            self._exec_and_readlines(cmd=massdns_cmd, domains=domains_chunk)

            with open(temp_path, 'r') as f:
                for line in f:
                    m_response = json.loads(line.strip())

                    if not 'data' in m_response.keys() or not 'answers' in m_response['data']:
                        continue

                    for answer in m_response['data']['answers']:

                        if answer['type'] not in types:
                            continue

                        name = answer['name']
                        if name[-1:]=='.':
                            name=name[:-1]

                        data = answer['data']
                        if data[-1:]=='.':
                            data=data[:-1]

                        if data in blacklist:
                            #print ('{} was blacklisted'.format(data))
                            continue

                        response = (('name',name),('data',data),('type',answer['type']))
                        results_set.add(response)

            if os.path.exists(temp_path):
                os.remove(temp_path)

        results = [dict(result) for result in results_set]

        return results

    def trusted_resolve(self, domains, types=['A','CNAME'], strict=True, ignore_wildcard = True):
        return self.mass_resolve(
            domains=domains,
            types=types, 
            resolvers_path=self.trusted_resolvers_path, 
            ignore_wildcard=ignore_wildcard,
            strict=strict,
            recheck = False
            )

    def mass_resolve(self, domains, types=['A','CNAME'], resolvers_path=None, ignore_wildcard = True, strict=True, recheck=True):

        #print ('Mass resolve was requested for domains:{}...'.format(domains[:20]))
        results = []

        if not resolvers_path:
            resolvers_path = self.mass_resolvers_path

        blacklist = []
        if ignore_wildcard:
            fake_domains = self._generate_fake_domains(domains)

            #print('Fakedomains generated:{}'.format(len(fake_domains)))

            print ('Fakedomains candidates to check ', len(fake_domains))

            wildcard_results = self._simple_resolve(domains = fake_domains, resolvers_path=self.mass_resolvers_path, types=types)

            #print('Wildcard results: {}'.format(wildcard_results))

            blacklist = set([result['data'] for result in wildcard_results])

            #print('Blacklist:{}'.format(blacklist))

        results = self._simple_resolve(domains = domains, resolvers_path=resolvers_path, blacklist=blacklist, types=types)

        #to add wildcart cname domains. dirty
        if blacklist:
            cname_blacklist = list(set([result['data'] for result in wildcard_results if result['type']=='CNAME']))
            cname_results = self._simple_resolve(domains = cname_blacklist, resolvers_path=resolvers_path, blacklist=[], types=types)

            for result in cname_results:
                if not result in results:
                    results.append(result)

        if recheck:
            #print ('recheck')
            domains = list(set([domain['name'] for domain in results]))
            domains.sort()
            results = self.trusted_resolve(domains=domains, ignore_wildcard = ignore_wildcard, strict=True, types=types)

        return results

if __name__ == "__main__":
    trusted_resolvers_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/trusted_resolvers.txt")
    mass_resolvers_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/mass_resolvers.txt")

    resolver = MassDnsResolver(
        trusted_resolvers_path=trusted_resolvers_path,
        mass_resolvers_path=mass_resolvers_path,
        temp_directory_path = '/tmp'
        )

    domains = ['goog.com']
    resolved_domains = resolver.mass_resolve(domains=domains, types=['A','CNAME'], recheck=False)
    #resolved_domains = resolver.trusted_resolve(domains=domains, types=['A','CNAME'])
    print (resolved_domains)