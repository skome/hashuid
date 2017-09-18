#!/usr/bin/python
# coding: utf-8
import sys
import ConfigParser
import base64
import uuid
import re
import csv
from hashlib import sha256
doc=""" 
%prog [input file] [output file] 
input file contains the user ids to be hashed. User ID takes form 'name@domain'
Outputfile will include everything in the input file but uids will have been securely hashed
"""
DELIM = '\t'
PTYPE_POS = 2
def hash_uid(uname, salt=None):
    if salt is None:
        salt = uuid.uuid4().hex
    hashed_uid = sha256(uname.lower() + salt).hexdigest()
    return (hashed_uid)

def verify_password(uid, hashed_uid, salt):
    re_hashed, salt = hash_uid(uid, salt)
    return re_hashed == hashed_uid
	
def getUIDPos(logLine, reString):
    doc="""
    return the uid and its start and end positions 
    """
    match = re.search(reString, logLine.lower().strip())
    if match:
        return match.group(), match.span()

def getCampus(uid):
    campus = uid.split('@')[1].split('.')[0].lower().strip()
    return campus

def getpType(logLine):
    pType=logLine.split(DELIM)[PTYPE_POS].strip('"\r\n').lower()
    return pType.strip()
     
def getSession(lLogLine):
    return lLogLine.split(' ')[0]

def getIPSubnet(lLogLine):
    match = re.search('([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})', lLogLine)
    if match:
        return match.group()

config = ConfigParser.RawConfigParser()
config.read('uidHash.cfg')
UNAMESALT = config.get('Auth', 'salt')

if __name__ == '__main__':
    uidFile=sys.argv[1] 
    outputfile = sys.argv[2]
    with open(uidFile,'r') as uidsf, open(outputfile, 'w') as hasheduidsf:
        csvf = csv.writer(hasheduidsf,delimiter=',', quoting=csv.QUOTE_MINIMAL)
        csvf.writerow(['uuid','campus','patronType'])
        for line in uidsf:
            if line.find('N/A')==-1:
                uidInfo = getUIDPos(line, r'[\w.-]+@[\w.-]+')                
                try:
                    uid = uidInfo[0]
                    huid = hash_uid(uid.split('@')[0],UNAMESALT)
                    campus = getCampus(uid)
                    print('Parsed: {},{}').format(uid,campus)
                except:
                    print("Parsing error uid, campus values: {}").format(line)
                else:
                    remainder = getpType(line)
                    print('{}, {}, {}').format(huid, campus, remainder)
                    csvf.writerow([huid,campus,remainder])
