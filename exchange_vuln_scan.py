#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/04/26
# @Author  : G3et
# @Site    : Exchange Vulnerability Scanner
# @File    : exchange_vuln_scan.py
# @Blog    : https://www.g3et.cn
import argparse
import requests
import urllib3
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init()
print('''    ______          __                              _____                                 
   / ____/  _______/ /_  ____ _____  ____ ____     / ___/_________ _____  ____  ___  _____
  / __/ | |/_/ ___/ __ \/ __ `/ __ \/ __ `/ _ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /____>  </ /__/ / / / /_/ / / / / /_/ /  __/   ___/ / /__/ /_/ / / / / / / /  __/ /    
/_____/_/|_|\___/_/ /_/\__,_/_/ /_/\__, /\___/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                  /____/        
                                                        @AUTHOR:G3et    @DATE:2023/04/26                                      
                                  ''')


def read_file(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f.readlines()]


parser = argparse.ArgumentParser(description='Exchange Vulnerability Scanner')
parser.add_argument('-f', '--file', metavar='FILE', type=str, required=True,
                    help='a file containing a list of URLs to scan')
args = parser.parse_args()

urls = read_file(args.file)
exchanges = read_file('exchange_version.txt')
versions_ex = read_file('versions_safe.txt')


def check_vuln(url):
    for ex in exchanges:
        payload = f"{url}/ecp/{ex}/exporttool/"
        try:
            resp = requests.get(payload, verify=False)
            if resp.status_code == 200:
                version = re.search(r'/ecp/(\d+\.\d+\.\d+\.\d+)/', payload).group(1)
                if version in versions_ex:
                    break
                else:
                    with open('success.txt', 'a') as f:
                        parsed_url = urlparse(payload)
                        url_without_path = parsed_url.scheme + '://' + parsed_url.netloc
                        f.write(url_without_path + '\n')
                    print(Fore.GREEN + '[+]There may be a vulnerability:' + Style.RESET_ALL + url_without_path + '\n' + Fore.CYAN + '[*]Version is:' + Style.RESET_ALL + version)
                    pass
        except:
            pass


with ThreadPoolExecutor(max_workers=100) as executor:
    results = list(executor.map(check_vuln, urls))

print(Fore.YELLOW + '[+]Done!' + Style.RESET_ALL)
