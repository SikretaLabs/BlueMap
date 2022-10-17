[![licence badge]][licence] 
[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg

### BlueMap: An Interactive Exploitation Toolkit for Azure

BlueMap helps penetration testers and red teamers to perform Azure auditing, discovery & enumeration, and exploitation in interactive mode that saves complex opsec and overhead that usually exists in Azure penetration testing engagements.

The tool is currently in the Alpha version and with initial capabilities, but it will evolve with time :)

### Motivation

During cloud engagements, a red teamer and pentester need to use different tools (primarily based on Powershell), which require third-party dependencies such as Az Module and similar for practical exploitation.  BlueMap helps cloud red teamers and security researchers identify IAM misconfigurations, information gathering, and abuse of managed identities in interactive mode without ANY third-party dependencies. No more painful installations on the customer's environment. 
Developed in Python and implemented all Azure integrations from scratch. The idea behind the tool is to let security researchers and red team members have the ability to focus on more Opsec to bring practical results.

### Installation

The up-to-date release can be downloaded by cloning the master branch from here.
   
   git clone https://github.com/SikretaLabs/BlueMap.git

BlueMap works out of the box with [Python](https://www.python.org/download/) version **3.x** and above on any platform.
For more information about installtion and other setup, please refer our wiki.

### License

BlueMap is distributed under MIT License
