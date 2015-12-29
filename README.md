# Synopsis
This script will synchronize the AWS Public IPs with its corresponding SecurityCenter scan target configuration.

# Details
The script allows you to scan your Internet exposed instances with SecurityCenter. The script authenticates to all your AWS accounts and pulls out any instances with a public IP (including the instances belonging to Autoscale Groups). The script filters out any micro or small instance types (to conform to AWS scanning requirements), instances belonging to Autoscale Groups, as well as instances matching a specific key/value tag pair (if specified) and then finds the matching scan in SecurityCenter and updates the scanning targets.

# Requirements
The script has dependencies on the following python modules:
* boto
* json
* requests
* yaml

# Usage
Before you can begin using the script you will need to configure a couple of settings.

### aws_sc-sync.py file

* Set the location of the configuration file in the _CONFIG_FILE_PATH and _CONFIG_FILE variables. By default it assumes the configuration file is in the same location as the script.
* Set the location of the AWS credential file in the _AWS_CRED_FILE_PATH and _AWS_CRED_FILE variables. By default it assumes the AWS credential file is in the same location as the script.
* Set the key and value for each tag that you would like excluded from the scan in the _FILTERS variable.
* Define what text is prefixed to the AWS scans in SecurityCenter using the _PREFIXED_SCAN_NAME variable.

### aws-config.cfg
* Set the proxy settings
* Set the SecurityCenter API URL

### aws-creds.yml
* Set the credentials for each AWS account. The AWS account name in this file must match the scan name in SecurityCenter without the prefixed scan name. For example, if in SecurityCenter the scan name is *AWS:XYZ-PROD* then the account name in this file must be *XYZ-PROD* in order for the script to match them.

### creds.yml
* Set the credentials of the proxy server (if required)
* Set the credentials for SecurityCenter

# Disclaimer

As usual use at your risk. We assume no liability.