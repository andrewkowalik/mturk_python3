import sys, os, base64, datetime, hashlib, hmac, urllib
import requests


def request_signature(operation, timestamp, secret_key):
    msg = b'AWSMechanicalTurkRequester' + operation + timestamp
    sha256_hmac = hmac.new(secret_key, msg, hashlib.sha1).digest()
    return base64.encodestring(sha256_hmac).strip()



access_key = ''
secret_key = b''

now = datetime.datetime.utcnow().isoformat()
amz_date = bytes(now, 'utf-8')

signature = request_signature(b'GetAccountBalance', amz_date, secret_key)

service_url='https://mechanicalturk.sandbox.amazonaws.com/?Service=AWSMechanicalTurkRequester'

params = {
    "Operation":'GetAccountBalance',
    "Version":"2014-08-15",
    "AWSAccessKeyId":access_key,
    "Signature":signature,
    "Timestamp":now,
    "ResponseGroup.0":"Minimal",
    "ResponseGroup.1":"Request"
}

resp = requests.post(service_url, data=params)
