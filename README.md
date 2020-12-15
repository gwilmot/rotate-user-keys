# rotate-user-keys

rotate-user-keys is a Python script for the purpose of each user rotating their own AWS access keys.  It carries out the following steps:

1. Wait for internet connection and first API call to be successful
2. Call AWS IAM API, and clear down all access keys for current user apart from the active one being used to make the API calls
3. Generate new (additional) access key for user
4. Wait for new access key to become active on IAM (there is a short delay between creating access key and it being available for use)
5. Update DBeaver credential file to use new access key and secret (this step decrypts the DBeaver config file, updates contents and re-encrypts)
6. Update AWS Credentials file to use new access key and secret
7. Call AWS IAM API and delete the previously active access key

This script can be added to the Automator app on OSX.  This in turn can be triggered by adding to a Login Item under System Preferences | Users and Groups | <Username>.  This will allow the credentials to be rotated upon each login.  The script will wait until it can connect to the internet before continuing.
  
Note that if the credentials are rotated whilst DBeaver is open, the DBeaver application will need to be closed and reopened to pick up and use the new credentials.

