# Bypass403

Using this tool, you can fuzz your 403/401 endpoint and try to access it without any restrictions
<br>You can also customize your payloads and update them regularly

# How To Use?
1) git clone https://git.mihanhosting.net/rezasarvani/bypass403<br>
2) cd bypass403<br>
3) python main.py -u "TargetURL"<br>
Note: more examples are at the end of the page

# Prerequisite
1) **Python 3.6+**<br>
2) **requests**<br>
3) **json**<br>

# Why This Tool?

Two main reasons to use this tool:<br>
1) the **current signatures** of the tool are updated and it is based on multiple **Bug Bounty Writeups**<br>
2) You can **customize** signatures and add new ones based on your own methodology **Super Easy**<br>

# Signatures

## bypassList.txt

In this file, there are general bypasses for both Domain/Subdomain restrictions (*secret.example.tld*) and Path restrictions (*example.tld/secret*)<br>
format: each line must contain one **json** containing below parameters<br>

Parameter | Values
--- | ---
**http_method** | You can specify which method you want to use to send your request with.<br>Possible Values: GET, POST, OPTIONS, PUT, DELETE, PATCH<br>**Mandatory** Paramter
**path** | You can specify a path which you want to append to your request during sending the request.<br>Example: /.json<br>Output: https://example.tld/.json<br>If you dont want to add any path, leave this parameter **empty**<br>**Mandatory** Paramter
**protocol** | You can specify which schema to use while sending the request<br>Possible Values: http, https, {{schema}}<br>Note: if you add {{schema}} it means that you want to use deafult target schema<br>Note: if you specify rev:{{schema}} it means that you want to use a reverse schema based on your target.<br>Target: https --> Request: http<br>**Mandatory** Paramter
**header** | You can specify custom headers to send along with the request<br>Format: headerName:headerValue~headerName2:valueName2<br>Example: X-HTTP-Method-Override:PUT<br>Example2: X-HTTP-Method-Override:PUT~Host:google.com<br>**Optional** Paramter
<br>

### Example

{"http_method": "GET", "path": "", "protocol": "{{schema}}", "header": "X-HTTP-Method-Override:PUT"}

## pathBasedBypassList.txt

In this file, there are bypasses mostly used for bypassing Path restrictions (*example.tld/secret*)<br>
format: each line must contain one **json** containing below parameters<br>

Parameter | Values
--- | ---
**http_method** | You can specify which method you want to use to send your request with.<br>Possible Values: GET, POST, OPTIONS, PUT, DELETE, PATCH<br>**Mandatory** Paramter
**protocol** | You can specify which schema to use while sending the request<br>Possible Values: http, https, {{schema}}<br>Note: if you add {{schema}} it means that you want to use deafult target schema<br>Note: if you specify rev:{{schema}} it means that you want to use a reverse schema based on your target.<br>Target: https --> Request: http<br>**Mandatory** Paramter
**pattern** | You can specify a pattern in order to edit **restricted path** and prepend or append something to it.<br>Format: POSITION~PAYLOAD\|POSITION~PAYLOAD<br>Possible Positions: before, after<br>Example: before~/%2e/<br>Input: example.tld/secret<br>Output: example.tld/%2e/secret<br>**Mandatory** Paramter
<br>

### Example

{"http_method": "GET", "protocol": "{{schema}}", "pattern": "before~/%ef%bc%8f"}

# Tool Switches

Switch | Description
--- | ---
**-u** | You can specify you target domain using this switch<br>example: -u "https://target.tld"<br>**Mandatory** Paramter
**-p** | Using this switch you specify whether or not you want to use **Path-Based Payloads**<br>Valid Paramters: y, n<br>Default: n<br>**Optional** Paramter
**-o** | If you want to save output somewhere besides stdout, use this switch and pass your desired file name to it<br>Default: -<br>**Optional** Paramter
**-o** | There is a function named 'CustomAttacks' in the code, which you can create some custom requests but requiers a very little python knowledge<br>There are already two attacks in there, if you want to use them, pass 'y' to this switch<br>Default: n<br>**Optional** Paramter
<br>

### Example

python main.py -u "https://target.tld" -p "y"<br>
<br>
<br>
<br>

**Note:** If you got multiple Hits, consider checking Content-Length in order to check wheter or not it was **False Positive** caused by your payloads
