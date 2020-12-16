
import sys
import base64
import os
import json
import datetime
import boto3
import pytz
from shutil import copyfile
import time

from Crypto import Random
from Crypto.Cipher import AES

def pad(s):
    #Pre-encryption padding.  Creates a pad to ensure string can be split into 16 byte blocks.
    #Padding byte is given a value between 1 and 16, and represents the length of the padding string. eg 4 padding bytes, padding char=0x04
    pad_size = AES.block_size - (len(s) % AES.block_size)
    return s + bytes([pad_size]) * pad_size

def unpad(s):
    #Chop off all padding characters from the end of the string
    #DBeaver sets the value of the padding character equal to the number of padding bytes required. eg 4 padding bytes, padding char=0x04
    #DBeaver possible padding lengths are between 1 and 16 chars
    last_char = s[-1:]
    pad_len = ord(last_char)
    s = s[:-pad_len]
    return s

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    plaintext = unpad(plaintext)
    return plaintext

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

def encrypt_to_file(message, file_name, key):
    enc = encrypt(message, key)
    with open(file_name, 'wb') as fw:
        fw.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    return dec

def replace_in_file (file_name, orig_string, replacement_string):
   #replace with single file handle
   with open(file_name, "rt") as fin:
       with open(file_name + ".out", "wt") as fout:
          for line in fin:
            fout.write(line.replace(orig_string, replacement_string))
   copyfile(file_name + ".out", file_name)
   os.remove(file_name + ".out")

def update_dbeaver_creds(configstring, old_access_key, old_access_secret, new_access_key, new_access_secret):
    configstring = configstring.replace(old_access_key,new_access_key)
    configstring = configstring.replace(old_access_secret,new_access_secret)
    return configstring

def update_aws_creds_file(file_name, old_access_key, old_access_secret, new_access_key, new_access_secret):
    #Todo - refactor to tidy up 'replace' function
    #input file
    copyfile(file_name, file_name + ".bak") #create a backup in case it goes wrong!
    copyfile(file_name, file_name + ".tmp") #create a tmp file to work with
    replace_in_file (file_name + ".tmp", old_access_key, new_access_key) #1st pass to replace access key
    replace_in_file (file_name + ".tmp", old_access_secret, new_access_secret) #2nd pass to replace access secret
    copyfile(file_name + ".tmp", file_name) #replace master creds file
    os.remove(file_name + ".tmp")


def creds_updated (access_key, access_secret):
    #Create temporary session to make API call to AWS IAM.
    #Successful connection verifies creds have been updated successfully and function returns true
    test_client = boto3.client('iam',
            aws_access_key_id=access_key,
            aws_secret_access_key=access_secret)
    try:
        test_client.get_user()
        return 1
    except:
        return 0


#Hardcoded symmetric encryption key used by DBeaver
key = bytes([186, 187, 74, 159, 119, 74, 184, 83, 201, 108, 45, 101, 61, 254, 84, 74])


#possible locations of DBeaver creds file
default_paths = [
  '~/Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json',
  '~/.local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json',
  '~/.local/share/.DBeaverData/workspace6/General/.dbeaver/credentials-config.json',
]

aws_creds_path = os.path.expanduser('~/.aws/credentials')

# Create IAM and STS clients
iam = boto3.client('iam')
sts = boto3.client('sts')

#Initialise dicts
access_key_id = {}
access_key_date = {}
access_key_age = {}
access_key_last_used = {}

#Determine correct DBeaver creds path
if len(sys.argv) < 2:
  for path in default_paths:
    filepath = os.path.expanduser(path)
    try:
      f = open(filepath, 'rb')
      f.close()
      break
    except Exception as e:
      pass
else:
  filepath = sys.argv[1]

#Sense network connection and get current user info from AWS IAM API
i=0
established_connection = False
max_retries = 9999999
while not established_connection and i < max_retries:
   try:
      current_user_details = iam.get_user()
      established_connection = True
      print ("Established connection!")
   except:
      if i < 1:
        print ("Waiting for network connection...")
      else:
        print ("...")
      i = i + 1
      time.sleep(10)
if i >= max_retries:
    exit("Retry timeout expired")


session = boto3.Session()
credentials = session.get_credentials()
# Credentials are refreshable, so accessing access key / secret key
# separately can lead to a race condition. Use this to get an actual matched
# set.
credentials = credentials.get_frozen_credentials()
current_access_key = credentials.access_key
current_access_secret = credentials.secret_key

my_user_name = current_user_details["User"]["UserName"]
#Get access keys assigned to user
user_access_keys = iam.list_access_keys(UserName=my_user_name)

print ("############################################################################")
print ("                   Rotate Access Keys                              ")
print ()
print ("Rotating access keys for", current_user_details["User"]["UserName"])


#Create new Access Keys
#If there are access keys other than the current session, delete them
if len(user_access_keys["AccessKeyMetadata"]) > 1:
   for x in user_access_keys["AccessKeyMetadata"]:
       if x["AccessKeyId"] != current_access_key:
          print ("Deleting access key " + x["AccessKeyId"] + "...")
          print ()
          iam.delete_access_key(AccessKeyId=x["AccessKeyId"])
#Generate New Access key
response = iam.create_access_key(UserName=my_user_name)
new_access_key = response["AccessKey"]["AccessKeyId"]
new_access_secret = response["AccessKey"]["SecretAccessKey"]
print ("Created New Access Key: " + new_access_key)
print ()


#Create a session and test new access keys here.
#retry max_retries times at 2 second intervals
i = 0
max_retries = 20
print ("Waiting for new acess key to become active...")
while not creds_updated(new_access_key,new_access_secret) and i < max_retries:
    i = i + 1
    if i >= max_retries:
        exit("Credential update failed!  Aborting.")
    time.sleep(2)
print ()

#Set DBeaver to use new Access Key
print ("Updating DBeaver to use new access key...")

orig_creds = decrypt_file(filepath, key)
print (orig_creds)
updated_creds = update_dbeaver_creds(orig_creds.decode("utf-8"), current_access_key, current_access_secret, new_access_key, new_access_secret).encode("utf-8")
print (updated_creds)
encrypt_to_file(updated_creds, filepath, key)

print ("Updating local AWS credentials file...")
update_aws_creds_file(aws_creds_path, current_access_key, current_access_secret, new_access_key, new_access_secret)

#Delete old access key
iam.delete_access_key(AccessKeyId=current_access_key)

print ("Update complete. Don't forget to restart DBeaver to pick up new credentials!")
print()
print ("############################################################################")
print()
