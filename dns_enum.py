import os
import sys
import argparse

import dnsgen

from lib.update_resolvers import DnsResolverProvider
from lib.mass_resolver import MassDnsResolver
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
    parser.add_argument('-w','--wordlist', help="dns names wordlist", default='n0kovo_subdomains_small.txt')
    parser.add_argument('--alt-wordlist', help="alt mutations wordlist", default='altmutations.txt')
    parser.add_argument('-d','--domain', help="domain to brute")
    parser.add_argument('-df','--domain-file', help="file with domains to brute")

    return parser.parse_args()


def main():
    args = parse_args()
    print (args)

    trusted_resolvers_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/trusted_resolvers.txt")
    mass_resolvers_unchecked_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/mass_resolvers_unchecked.txt")
    mass_resolvers_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/mass_resolvers.txt")
    wordlist_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/" + args.wordlist)
    altmutations_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/dicts/" + args.alt_wordlist)

    temp_directory_path = os.path.normpath(os.path.realpath(os.path.dirname(__file__)) + "/temp/")

    resolver = MassDnsResolver(
        trusted_resolvers_path = trusted_resolvers_path,
        mass_resolvers_path = mass_resolvers_path,
        temp_directory_path = temp_directory_path,
        threads=1000
        )

    #load and update dns resolvers list
    if args.update_mass_resolvers or not os.path.exists(mass_resolvers_path):

        if not os.path.exists(mass_resolvers_path):
            print ('mass_resolvers.txt doesn\'t exist. Is it a first launch? We need to upgrade the mass resovler list')

        print ('(*) Updating mass resolvers...')

        dns_provider = DnsResolverProvider(100)
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
        domains_to_check = [f"{subdomain}.{root_domain}" for subdomain in subodomains]
        domains_to_check = domains_to_check[:100]

        resolved_domains = resolver.mass_resolve(domains=domains_to_check, types=['A','CNAME'],  recheck=True)
        resolved_names = [d['name'] for d in resolved_domains if root_domain in d['name']]
        print (f"(+) {len(resolved_domains)} records were found (CNAME+A)")
        
        print (f"(*) Generating altmutations for {len(resolved_names)} domains")
        mutated = list(generate(domains=resolved_names, wordlist=altmutations_path))
        print (f"(+) {len(mutated)} permutations were generated")

        print (f"(*) Resolving per altmutations...")
        resolved_domains_mutated = resolver.mass_resolve(domains=mutated, types=['A','CNAME'],  recheck=True)
        print (f"(+) {len(resolved_domains_mutated)} records were found (CNAME+A)")

        #print (list(mutated))
        print (resolved_domains_mutated)



if __name__ == "__main__":
    main()