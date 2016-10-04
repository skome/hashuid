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
Outputfile will include everthing in the input file but uids will have been securely hashed
"""
	
config = ConfigParser.RawConfigParser()
config.read('uidHash.cfg')
UNAMESALT = config.get('Auth', 'salt')

def getUIDStartPos(logLine):
    doc="""
    return the uid and its start and end positions 
    """
    match = re.search(r'[\w.-]+@[\w.-]+', logLine)
    if match:
        return match.group(), match.span()
def getCampus(uid):
    campus = uid.split('@')[1].split('.')[0]
    return campus
    
def hash_uid(uname, salt=None):
    if salt is None:
        salt = uuid.uuid4().hex
    hashed_uid = sha256(uname + salt).hexdigest()
    return (hashed_uid)

def verify_password(uid, hashed_uid, salt):
    re_hashed, salt = hash_uid(uid, salt)
    return re_hashed == hashed_uid

def getSession(lLogLine):
    return lLogLine.split(' ')[0]

def getIPSubnet(lLogLine):
    match = re.search('([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})', lLogLine)
    return match.group()


if __name__ == '__main__':
    uidFile=sys.argv[1] 
    outputfile = sys.argv[2]
    with open(uidFile,'r') as uidsf, open(outputfile, 'w') as hasheduidsf:
        csvf = csv.writer(hasheduidsf,delimiter='\t')
        #find the uids start position (per line)
        for line in uidsf:
            try:
                uidInfo = getUIDStartPos(line)                
                uid = uidInfo[0]
                huid = hash_uid(uid,UNAMESALT)
                campus = getCampus(uid)
                uidPos = uidInfo[1]
                preamble = line[0:uidPos[0]].strip('"')
                remainder = line[uidPos[1]:].strip().split('\t')[1].strip('"')#for WMS report
                #remainder = line[uidPos[1]:].strip()#for ezp
                #print ("preamble: {}\nuid:{}\nhuid:{}\ncampus:{}\nremainder: {}").format(preamble, uid,huid, campus, remainder)
                #csvf.writerow([huid,campus,preamble,getSession(remainder), getIPSubnet(remainder)])#for ezp report data
                csvf.writerow([huid,campus,remainder])#for WMS
            except TypeError:
                print "Error value: {}".format(line)
        #find the end of the uid (per line)
        #create a new line with the pre-uid text, hashed uid, post-uid text
        #write that to the new file.
