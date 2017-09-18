# hashuid
Hashuid is a utility for hashing user ids present in EZProxy Report files, OCLC WMS circulation reports, and other text files where user id is stored in the format 'user@domain'.  The hash includes provision for a single salt.  If a salt value isn't provided at runtime, the script creates a salt.  Anything preceding the userid and anything following are captured for (optional) output. E.g. campus (part of domain) and 'Undergraduate' 

##Processing Steps:
###WMS:
* from WMS Analytics create a circulation report of patrons. For excellent value, include patron type.

###EZProxy:
* use the monthly report file from OCLC
