# modified by prestinn, credits to https://github.com/juerkkil/securityheaders

import http.client
import argparse
import socket 
import ssl
import sys
import re

from urllib.parse import urlparse

class SecurityHeaders():
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):
        warn = 1
        print(header)

        if header == 'X-Frame-Options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = 0
            else:
                warn = 1

        if header == 'strict-transport-security':
            warn = 0

        if header == 'content-security-policy':
            warn = 0

        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = 1
            else:
                warn = 0
    
        if header.lower() == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = 0
            else:
                warn = 1

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = 0
            else:
                warn =1

        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = 1
            else: 
                warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def check_headers(self, url, follow_redirects = 0):
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''}, 
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''} 
        }

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = http.client.HTTPConnection(hostname)
        elif (protocol == 'https'):
                ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(hostname, context = ctx )
        else:
            return {}
    
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
            print (headers)
            
        except socket.gaierror:
            print('HTTP request failed')
            return False

        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    redirect_url = header[1]
                    if not re.match('^https?://', redirect_url):
                        redirect_url = protocol + '://' + hostname + redirect_url
                    return self.check_headers(redirect_url, follow_redirects - 1) 
                
        for header in headers:
            headerAct = header[0].lower()

            if (headerAct in retval):
                retval[headerAct] = self.evaluate_warn(headerAct, header[1])

        return retval

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers', \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int, help='Max redirects, set 0 to disable')
    args = parser.parse_args()
    url = args.url

    redirects = args.max_redirects
    foo = SecurityHeaders()

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided

    headers = foo.check_headers(url, redirects)

    if not headers:
        print ("Failed to fetch headers, exiting...")
        sys.exit(1)

    for header, value in headers.items():
        if value['warn'] == 1:
            if value['defined'] == False:
                print('[-] ' + header +  ' is missing')
            else:
                print('[+] ' + header +  ' contains value: ' + value['contents'])

        elif value['warn'] == 0:
            if value['defined'] == False:
                print('[-] ' + header + ' is missing')
            else:
                print('[+] ' + header + ' contains value: ' + value['contents'])
