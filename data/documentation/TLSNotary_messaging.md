TLSNotary Messaging Protocol
============================

The auditor and auditee must communicate in real time in order to create the shared SSL session secrets. This messaging must occur over a channel which has the following features:

 - Reasonable performance
 - Good reliability
 - Privacy is highly desirable if not always strictly necessary
 - Anonymity is also desirable

 It isn\t completely easy to find an architecture which will give all these properties without some centralisation. For the time being, auditors will register channels on IRC and the messaging will be carried out there. There are a lot of reasonable alternatives which can be swapped in to replace IRC if that proves desirable.

## Message formatting ##

 1.  Messages (except handshake, see below) are assumed to pass over a public channel, 
 so must be prefixed with <userid>
