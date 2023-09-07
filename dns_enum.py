import os
import sys
import argparse
import csv

import dnsgen

from lib.update_resolvers import DnsResolverProvider
from lib.mass_resolver import MassDnsResolver

from lib.amass import run_amass
from lib.ip_enrichment import IPEnricher
from lib.dnsgen import generate

args = {'dns_checker_threads':100}

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg)
    sys.exit()

def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0])
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('--update-mass-resolvers', help="check mass resolvers", action='store_true')
    parser.add_argument('--enrich', help="enrich resolved domains with data from whois", action='store_true')
    parser.add_argument('--amass', help="check with passive amass checks", action='store_true')
    parser.add_argument('--brute', help="try to domain bruteforce", action='store_true')
    parser.add_argument('--altmutations', help="try to find mutations", action='store_true')
    parser.add_argument('--amass-timeout', help="amass timout", default=120)
    parser.add_argument('--debug', help="debug", action='store_true')

    parser.add_argument('-w','--wordlist', help="dns names wordlist", default='n0kovo_subdomains_small.txt')
    parser.add_argument('--alt-wordlist', help="alt mutations wordlist", default='altmutations.txt')
    parser.add_argument('-d','--domain', help="domain to brute")
    parser.add_argument('-df','--domain-file', help="file with domains to brute")

    parser.add_argument('-o','--output-dir', help="directory for results", default='output')

    return parser.parse_args()


def main():
    args = parse_args()

    trusted_resolvers_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/trusted_resolvers.txt")
    mass_resolvers_unchecked_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/mass_resolvers_unchecked.txt")
    mass_resolvers_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/mass_resolvers.txt")
    wordlist_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/" + args.wordlist)
    altmutations_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/" + args.alt_wordlist)

    temp_directory_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/temp/")
    results_directory_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/results/")

    amass_config_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/3rdparty/amass/config.yaml")

    debug = args.debug

    resolver = MassDnsResolver(
        trusted_resolvers_path = trusted_resolvers_path,
        mass_resolvers_path = mass_resolvers_path,
        temp_directory_path = temp_directory_path,
        threads=1000
        )

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    #load and update dns resolvers list
    if args.update_mass_resolvers or not os.path.exists(mass_resolvers_path):

        if not os.path.exists(mass_resolvers_path):
            print ('mass_resolvers.txt doesn\'t exist. Is it a first launch? We need to upgrade the mass resovler list')

        print ('(*) Updating mass resolvers...')

        dns_provider = DnsResolverProvider(1000)
        with open (mass_resolvers_unchecked_path) as f:
            resolver_list = [s.strip() for s in f.readlines()]

        candidate_resolver_list = list(set(resolver_list))
        good_resolvers = dns_provider.get_good_resolvers(resolver_list=candidate_resolver_list)

        with open(mass_resolvers_path,'w') as f:
            f.write('\n'.join(good_resolvers))

        print ('\n')   
        print ('(*) Done')


    #load the subdomain wordlist
    with open(wordlist_path) as f:
        subodomains = [s.strip() for s in f.readlines()]
        print (f"(*) {len(subodomains)} subdomains have been loaded")

    #load domains
    root_domains = []
    if args.domain:
        root_domains = [args.domain]
    elif args.domain_file:
        with open(args.domain_file) as f:
            root_domains = [s.strip() for s in f.readlines()]


    print (f"(*) We\'re going to check the following root domains: {','.join(root_domains)}")

    for root_domain in root_domains:
        resolved_results = []

        #amass
        if args.amass:
            print (f"(*) Running Amass. Timeout is set to {args.amass_timeout}")
            amass_domains = run_amass(
                domain=root_domain,
                config_path=amass_config_path,
                temp_dir=temp_directory_path,
                timeout=args.amass_timeout)

            print (f"(+) {len(amass_domains)} domains found")
            for d in amass_domains:
                print (d)

            print ("(*) Resolving Amass results...")
            domains_to_check = [domain['name'] for domain in amass_domains]
            domains_to_check = list(set(domains_to_check))

            resolved_domains = resolver.trusted_resolve(domains=domains_to_check, types=['A','CNAME'])
            resolved_names = [d['name'] for d in resolved_domains if root_domain in d['name']]

            print (f"(+) {len(resolved_names)} domains were resolved:")
            for d in resolved_domains:
                print (d)

            for result in resolved_domains:
                if not result in resolved_results:
                    resolved_results.append(result)
                  
        #bruteforce
        if args.brute:
            print ("(*) Running bruteforce...")
            #subodomains = subodomains[:10]
            domains_to_check = [f"{subdomain}.{root_domain}" for subdomain in subodomains]

            #print (f"Domains to check: {domains_to_check}")

            resolved_domains = resolver.mass_resolve(domains=domains_to_check, types=['A','CNAME'],  recheck=True)
            for result in resolved_domains:
                if not result in resolved_results:
                    resolved_results.append(result)

            resolved_names = [d['name'] for d in resolved_results if root_domain in d['name']]

        print (f"(+) {len(resolved_domains)} records were found (CNAME+A)")
        print ( "(+) Domains:")
        for name in resolved_names:
            print (f"{name}")
        

        if args.altmutations:
            print (f"(*) Generating altmutations for {len(resolved_names)} domains")
            mutated = list(generate(domains=resolved_names, wordlist=altmutations_path))
            print (mutated[:10])
            print (f"(+) {len(mutated)} permutations were generated")

            print (f"(*) Resolving altmutations...")
            resolved_domains_mutated = resolver.mass_resolve(domains=mutated, types=['A','CNAME'],  recheck=True)
            for result in resolved_domains_mutated:
                if not result in resolved_results:
                    resolved_results.append(result)

            print (f"(+) {len(resolved_domains_mutated)} records were found (CNAME+A)")

        #additinly add amass results which were not resolved
        if args.amass:
            resolved_results_names = [d['name'] for d in resolved_results]

            for d in amass_domains:
                if not d['name'] in resolved_results_names:
                    print (f"unresolved amass domain: {d}")
                    resolved_results.append({'name':d['name'],'data':'','type':'A'})

        if args.altmutations:
            #print (list(mutated))
            resolved_names_mutated = [d['name'] for d in resolved_domains_mutated if root_domain in d['name']]
            for name in resolved_names_mutated:
                print (f"{name}")

                if len(resolved_results) < 1:
                    continue

        output_filepath = os.path.join(args.output_dir, f"raw_{root_domain}.csv")
        with open(output_filepath, 'w', encoding='utf8', newline='') as output_file:
            fc = csv.DictWriter(output_file, fieldnames=resolved_results[0].keys())
            fc.writeheader()
            fc.writerows(resolved_results)

            print (f"(+)Results saved to raw_{root_domain}.csv")

        if args.enrich:
            print (f"(*) Doing enrichment...")

            enricher = IPEnricher()
            enriched_records = []

            for result in resolved_results:
                
                additional_data = enricher.get_ip_data(result['data'])
                enriched_record = {**result, **additional_data}
                enriched_records.append(enriched_record)
                print (enriched_record)


            resolved_results = enriched_records

        output_filepath = os.path.join(args.output_dir, f"enriched_{root_domain}.csv")
        with open(output_filepath, 'w', encoding='utf8', newline='') as output_file:
            fc = csv.DictWriter(output_file, fieldnames=resolved_results[0].keys())
            fc.writeheader()
            fc.writerows(resolved_results)

            print (f"(+) Enriched results saved to enriched_{root_domain}.csv")

if __name__ == "__main__":
    main()