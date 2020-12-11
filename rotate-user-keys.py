
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

def update_creds(config_string, new_access_key, new_access_secret):
    json_config = json.loads(config_string)
    for x in json_config:
        json_config[x]["#connection"]["user"] = new_access_key
        json_config[x]["#connection"]["password"] = new_access_secret

    #Replace password with updates secret key
    updated_config_string = json.dumps(json_config).encode('utf-8')
    #remove white space from string
    updated_config_string = updated_config_string.replace(b' ', b'')
    return updated_config_string

def update_aws_creds_file(file_name, old_access_key, old_access_secret, new_access_key, new_access_secret):
    #input file
    fin = open(file_name, "rt")
    #output file to write the result to
    fout = open(file_name + ".new", "wt")
    #for each line in the input file
    for line in fin:
	    #read replace the string and write to output file
        fout.write(line.replace(old_access_key, new_access_key))
    fin.close()
    fout.close()

    fin = open(file_name + ".new", "rt")
    #output file to write the result to
    fout = open(file_name + ".new1", "wt")


    for line in fin:
        fout.write(line.replace(old_access_secret, new_access_secret))
        #close input and output files
    fin.close()
    fout.close()

    copyfile(file_name + ".new1", file_name)
    os.remove(file_name + ".new")
    os.remove(file_name + ".new1")



#Hardcoded symmetric encryption key used by DBeaver
key = bytes([186, 187, 74, 159, 119, 74, 184, 83, 201, 108, 45, 101, 61, 254, 84, 74])


#possible locations of DBeaver creds file
default_paths = [
  '~/Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json',
  '~/.local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json',
  '~/.local/share/.DBeaverData/workspace6/General/.dbeaver/credentials-config.json',
]

aws_creds_path = "/Users/graham/.aws/credentials"

# Create IAM and STS clients
iam = boto3.client('iam')
sts = boto3.client('sts')

#pull in access key from env vars.  This will be replaced
new_access_key =os.environ['AWS_ACCESS_KEY']
new_access_secret = os.environ['AWS_ACCESS_SECRET']


# Get Caller Identity
#response = sts.get_caller_identity()
#print(response)

access_key_id = {}
access_key_date = {}
access_key_age = {}
access_key_last_used = {}

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

current_user_details = iam.get_user()

session = boto3.Session()
credentials = session.get_credentials()

# Credentials are refreshable, so accessing your access key / secret key
# separately can lead to a race condition. Use this to get an actual matched
# set.
credentials = credentials.get_frozen_credentials()
current_access_key = credentials.access_key
current_access_secret = credentials.secret_key

my_user_name = current_user_details["User"]["UserName"]
#Get access keys assigned to user
user_access_keys = iam.list_access_keys(UserName=my_user_name)


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
print ("Created New Access Secret: " + new_access_secret)

#Insert step to create a session and test new access keys here.
#retry 10 times with a lag starting 2 seconds and doubling each time
print ()
print ("Waiting for new secrets to become active...")

time.sleep(10)

print ()
#Set DBeaver to use new Access Key
print ("Updating DBeaver to use new access key...")
orig_creds = decrypt_file(filepath, key)
updated_creds = update_creds(orig_creds, new_access_key, new_access_secret)
encrypt_to_file(updated_creds, filepath, key)

print ("Writing new access key:")
print (current_access_secret)
update_aws_creds_file(aws_creds_path, current_access_key, current_access_secret, new_access_key, new_access_secret)

#Delete old access key
iam.delete_access_key(AccessKeyId=current_access_key)

print ("Complete")
