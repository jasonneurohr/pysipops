'''
pySipOp is a utility for exchanging various SIP messages
with a target SIP device. TCP port 5060 is assumed for all exchanges.

To-do List
 - Delayed offer ACK

Author Jason Neurohr
'''

import random
import socket
import sys
import argparse

# CONSTANTS
PORT = 5060

# Command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-sp", type=int, required=True, help="The source TCP port")
parser.add_argument("-dst", required=True, help="The destination IP")
parser.add_argument("-uri", required=True, help="The destination URI user part")
parser.add_argument("-src", required=True, help="The source IP")
parser.add_argument("-mode", required=True, help="Choose early, delayed, options")
args = parser.parse_args()

# Initialise variables from arguments
sourcePort = args.sp
destinationIp = args.dst
destinationUserPart = args.uri
sourceIp = args.src
mode = args.mode

# Initialise variables for use in the SIP messages
callId = str(random.randint(10000, 99999))
cseq = "1"
randomPort = str(random.randint(1025, 65535))


# SIP delayed offer string
delayedOffer = ("INVITE sip:" + destinationUserPart + "@" + destinationIp + ":5060;transport=tcp SIP/2.0\r\n"
              "Via: SIP/2.0/TCP " + sourceIp + ":5060;branch=1234\r\n"
              "From: <sip:99999@" + sourceIp + ">;tag=456\r\n"
              "To: <sip:" + destinationUserPart + "@" + destinationIp + ":5060>\r\n"
              "Call-ID: " + callId + "@" + sourceIp + "\r\n"
              "CSeq: " + cseq + " INVITE\r\n"
              "Content-Type: application/sdp\r\n"
              "Contact: <sip:99999@" + sourceIp + ":5060;transport=tcp>\r\n"
              "User-Agent: SIP Probe\r\n"
              "Max-Forwards: 10\r\n"
              "Supported: replaces,timer\r\n"
              "P-Asserted-Identity: <sip:99999@" + sourceIp + ">\r\n"
              "Allow: INVITE,BYE,CANCEL,ACK,REGISTER,SUBSCRIBE,NOTIFY,MESSAGE,INFO,REFER,OPTIONS,PUBLISH,PRACK\r\n"
              "Content-Type: application/sdp\r\n"
              "Content-Length: 0\r\n\r\n")

# SIP early offer string
earlyOffer = ("INVITE sip:" + destinationUserPart + "@" + destinationIp + ":5060;transport=tcp SIP/2.0\r\n"
              "Via: SIP/2.0/TCP " + sourceIp + ":5060;branch=1234\r\n"
              "From: <sip:99999@" + sourceIp + ">;tag=456\r\n"
              "To: <sip:" + destinationUserPart + "@" + destinationIp + ":5060>\r\n"
              "Call-ID: " + callId + "@" + sourceIp + "\r\n"
              "CSeq: " + cseq + " INVITE\r\n"
              "Content-Type: application/sdp\r\n"
              "Contact: <sip:99999@" + sourceIp + ":5060;transport=tcp>\r\n"
              "User-Agent: SIP Probe\r\n"
              "Max-Forwards: 10\r\n"
              "Supported: replaces,timer\r\n"
              "P-Asserted-Identity: <sip:99999@" + sourceIp + ">\r\n"
              "Allow: INVITE,BYE,CANCEL,ACK,REGISTER,SUBSCRIBE,NOTIFY,MESSAGE,INFO,REFER,OPTIONS,PUBLISH,PRACK\r\n"
              "Content-Type: application/sdp\r\n"
              "Content-Length: 207\r\n\r\n"
              "o=SP 12345 IN IP4 " + sourceIp + "\r\n"
              "s=-\r\n"
              "p=11111\r\n"
              "t=0 0\r\n"
              "m=audio " + randomPort + " RTP/AVP 8 101\r\n"
              "c=IN IP4 " + sourceIp + "\r\n"
              "a=rtpmap:8 PCMA/8000\r\n"
              "a=rtpmap:101 telephone-event/8000\r\n"
              "a=fmtp:101 0-15\r\n"
              "a=ptime:20\r\n"
              "a=sendrecv\r\n\r\n") 

# SIP OPTIONS string
options = ("OPTIONS sip:" + destinationIp + ":5060;transport=tcp SIP/2.0\r\n"
            "Via: SIP/2.0/TCP " + sourceIp + ":5060;branch=1234\r\n"
            "From: \"SIP Probe\"<sip:99999@" + sourceIp + ":5060>;tag=5678\r\n"
            "To: <sip:" + destinationIp + ":5060>\r\n"
            "Call-ID: " + callId + "\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Max-Forwards: 0\r\n"
            "Content-Length: 0\r\n\r\n")
              
# Initialise a new socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as s:
    s.connect((destinationIp, PORT))

    if mode == "early":
        s.sendall(earlyOffer.encode("utf-8"))
    elif mode == "delayed":
        s.sendall(delayedOffer.encode("utf-8"))
    elif mode == "options":
        s.sendall(options.encode("utf-8"))

    # Receive response data and output
    sentinal = True;
    while sentinal:
        data = s.recv(4096)
        if not data: break
        data = str(data,'utf-8').splitlines()
        
        for line in data:
            print(line)
            if "200 OK" in line or "486 Busy Here" in line:
                sentinal = False
