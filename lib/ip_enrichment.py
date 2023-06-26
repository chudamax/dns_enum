
import urllib3
urllib3.disable_warnings()

import time
import requests
import ipaddress
import socket
import sys
import argparse
import csv

import dns.resolver

class IPEnricher():
    def __init__(self, cache={}, delay=1):
        self.cache = cache
        self.delay = delay
    
    def get_ip_data(self, ip):
        enriched_data = {}
        enriched_data['ISP'] = ''
        enriched_data['ORG'] = ''
        enriched_data['AS'] = ''
        enriched_data['Route'] = ''

        try:
            ipaddress.ip_address(ip)
        except:
            return enriched_data
        
        if ipaddress.ip_address(ip).is_private:
            return enriched_data
        
        if ip in self.cache:
            return self.cache[ip]
        
        time.sleep(self.delay)
        r = requests.get(f"https://ip-db.io/api/{ip}", verify=False)
        data = r.json()

        enriched_data['ISP'] = data['isp']
        enriched_data['ORG'] = data['org']
        enriched_data['AS'] = data['as']
        enriched_data['Route'] = data['route']

        self.cache[ip] = enriched_data

        return enriched_data

class IPResolver():
    def __init__(self, cache={}, report_not_resolved=False):
        self.report_not_resolved = report_not_resolved
    
    @staticmethod
    def strip_last_dot(addr):
        return addr[:-1] if addr.endswith('.') else addr

    
    def _resolve(self, name, rtype):
        results = []

        try:
            answers = dns.resolver.resolve(name, rtype)
        except (dns.exception.Timeout, dns.resolver.NXDOMAIN,
            dns.resolver.YXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.name.EmptyLabel, socket.error):
            if self.report_not_resolved:
                return [{'Type':rtype,'Name':name, 'Address':'', 'Target':''}]
            else:
                return []
        
        for rdata in answers.response.answer:
            if rdata.rdtype == 5:
                #CNAME
                for item in rdata.items:
                    name = self.strip_last_dot(rdata.name.to_text())
                    target = self.strip_last_dot(item.target.to_text())

                    new_result = {'Type':'CNAME','Name':name, 'Address':'', 'Target':target}
                    results.append(new_result)
            else:
                for item in rdata.items:
                    name = self.strip_last_dot(rdata.name.to_text())
                    address = item.to_text()

                    new_result = {'Type':rtype,'Name':name, 'Address':address, 'Target':''}
                    results.append(new_result)

        return results
    
    def resolve(self, name):
        resolved_results = self._resolve(name, rtype="A")
        resolved_results += self._resolve(name, rtype="AAAA")
        return resolved_results


def format_str(item):
    return f"{item['Type']},{item['Name']},{item['Address']},{item['Target']},{item['ISP']},{item['ORG']},{item['AS']},{item['Route']}"

def handle_a_item(item):
    enriched_item = enrich_ipdb(item, cache=enriched_item_cache)
    print (format_str(enriched_item))

def handle_cname_item(item, all_items):
    items = []

    #print the CNAME item itself
    enriched_item = enrich_ipdb(item, cache=enriched_item_cache)
    print (format_str(enriched_item))

    for related_item in all_items:
        if related_item['Type'] == "A" and related_item['Name'] == enriched_item['Target']:
            handle_a_item(related_item)
        
        elif related_item['Type'] == "CNAME" and related_item['Name'] == enriched_item['Target']:
            handle_cname_item(item=related_item, all_items=all_items)

def main(args):
    resolver = IPResolver()
    enricher = IPEnricher()

    domains_to_resolve = []
    final_results = []

    with open(args.input_file,'r') as f:
        domains_to_resolve = [item.strip() for item in f.readlines() if item]
    
    for domain in domains_to_resolve:
        resolved_records = resolver.resolve(domain)

        #make them uniq
        #resolved_records = [dict(t) for t in {tuple(d.items()) for d in resolved_records}]

        for record in resolved_records:
            additional_data = enricher.get_ip_data(record['Address'])
            enriched_record = {**record, **additional_data}
            final_results.append(enriched_record)

            print (enriched_record)
    
    with open(args.output_file, 'w', encoding='utf8', newline='') as output_file:
        fc = csv.DictWriter(output_file, fieldnames=final_results[0].keys())
        fc.writeheader()
        fc.writerows(final_results)

    print (f'[+] Results have been saved to {args.output_file}')
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates a csv file with resolved domains and enriched data (ORG,AS,ISP,Route)"
    )

    parser.add_argument(
        "-i",
        "--input-file",
        required=True,
        help="file with domains to resolve"
    )

    parser.add_argument(
        "-o",
        "--output-file",
        help="output csv file",
        required=True
    )

    args = parser.parse_args()

    main(args)

