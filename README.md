# BlueMap - Azure OpSec Framework

# About BlueMap & Motivation

BlueMap helps cloud red teamers and security researchers identify IAM misconfigurations, information gathering, and abuse of managed identities in interactive mode without ANY third-party dependencies. No more painful installations on the customer's environment, No more need to custom the script to avoid SIEM detection!

The tool leaves minimum traffic in the network logs so it can help during red team engagements from on-prem to the cloud. Developed in Python and implemented all Azure integrations from scratch with zero dependencies on Powershell stuff. The idea behind the tool is to let security researchers and red team members the ability to focus on more Opsec rather than DevOps stuff.

The tool is currently in the Alpha version and with initial capabilities, but it will evolve with time :)

# Supported Capabilities

- Shadow Permissions Enumeration & IAM detailed scanner
- Automation for Service Principles Exploit
- App Service Attack surface detection
- Token Convert automation for local/remote identities (i.e., Managed Identity)
- Ability to connect remote/local identities
- ARM Template Quick Analysis

TodoList:

- Add WhoAmI feature to show local UPN + Role
- Run Command on VM
- Add support to extract stored password / information from automation accounts
- Add support in Managed Identity in Reader/ExposedAppServiceApps (need to login as Azure Admin and set one up)
- Detect of azureprofile.json ("Save-AzContext" as logged in Azure admin)
- Add support in Blob enumeration (Microbrust like)
- Add support to enumerate all Azure Container Registry
- Add capability of parsing token/convert (to Graph etc.)
- Add Azure Function App Support
- Add Option to Read Vault Secrets
- Add Option to View FW rules
- Added Support for Password Spray
- Add Option to Support Enumerate Owner for Enterprise Apps Only
- Add Global Administrator or Intune Administrator Privilege: Add new PowerShell script to enrolled Intune devices
- Add Support of Reset Password Functionality
