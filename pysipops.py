import random
import socket
import sys
import argparse
import logging

# create logger
logger = logging.getLogger("sip_logger")
logger.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handler
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
# add the handler to the logger
logger.addHandler(ch)

def main():
    PORT = 5060

    parser = argparse.ArgumentParser()
    parser.add_argument("-dst", required=True, help="The destination IP")
    parser.add_argument("-uri", required=True, help="The destination URI")
    parser.add_argument("-src", required=True, help="The source IP")
    parser.add_argument("-mode", required=True, help="Choose early, delayed, options")
    args = parser.parse_args()

    # Initialise variables from arguments
    destinationIp = args.dst
    
    split_uri = args.uri.split("@")
    destinationUserPart = split_uri[0]
    destinationHostPart = split_uri[1]

    sourceIp = args.src
    mode = args.mode

    # Initialise variables for use in the SIP messages
    callId = str(random.randint(10000, 99999))
    cseq = "1"
    randomPort = str(random.randint(1025, 65535))

    # SIP delayed offer string
    delayedOffer = ("INVITE sip:" + destinationUserPart + "@" + destinationHostPart + ":5060;transport=tcp SIP/2.0\r\n"
                "Via: SIP/2.0/TCP " + sourceIp + ":5060;branch=1234\r\n"
                "From: <sip:99999@" + sourceIp + ">;tag=456\r\n"
                "To: <sip:" + destinationUserPart + "@" + destinationHostPart + ":5060>\r\n"
                "Call-ID: " + callId + "@" + sourceIp + "\r\n"
                "CSeq: " + cseq + " INVITE\r\n"
                "Content-Type: application/sdp\r\n"
                "Contact: <sip:99999@" + sourceIp + ":5060;transport=tcp>\r\n"
                "User-Agent: SIP Probe\r\n"
                "Max-Forwards: 10\r\n"
                "Supported: replaces,timer\r\n"
                "P-Asserted-Identity: <sip:99999@" + sourceIp + ">\r\n"
                "Allow: INVITE,BYE,CANCEL,ACK,REGISTER,SUBSCRIBE,NOTIFY,MESSAGE,INFO,REFER,OPTIONS,PUBLISH,PRACK\r\n"
                "Content-Length: 0\r\n\r\n")

    # SIP early offer string
    earlyOffer = ("INVITE sip:" + destinationUserPart + "@" + destinationHostPart + ":5060;transport=tcp SIP/2.0\r\n"
                "Via: SIP/2.0/TCP " + sourceIp + ":5060;branch=1234\r\n"
                "From: <sip:99999@" + sourceIp + ">;tag=456\r\n"
                "To: <sip:" + destinationUserPart + "@" + destinationHostPart + ":5060>\r\n"
                "Call-ID: " + callId + "@" + sourceIp + "\r\n"
                "CSeq: " + cseq + " INVITE\r\n"
                "Content-Type: application/sdp\r\n"
                "Contact: <sip:99999@" + sourceIp + ":5060;transport=tcp>\r\n"
                "User-Agent: SIP Probe\r\n"
                "Max-Forwards: 10\r\n"
                "Supported: replaces,timer\r\n"
                "P-Asserted-Identity: <sip:99999@" + sourceIp + ">\r\n"
                "Allow: INVITE,BYE,CANCEL,ACK,REGISTER,SUBSCRIBE,NOTIFY,MESSAGE,INFO,REFER,OPTIONS,PUBLISH,PRACK\r\n"
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as s:
            s.connect((destinationIp, PORT))

            if mode == "early":
                logger.debug("Early Offer message:\n" + earlyOffer)
                s.sendall(earlyOffer.encode("utf-8"))
            elif mode == "delayed":
                logger.debug("Delayed Offer message:\n" + delayedOffer)
                s.sendall(delayedOffer.encode("utf-8"))
            elif mode == "options":
                logger.debug("Options message:\n" + options)
                s.sendall(options.encode("utf-8"))

            # Receive response data and output
            sentinal = True;
            while sentinal:
                data = s.recv(4096)
                if not data:
                    break

                data = str(data,'utf-8').splitlines()
                
                logger.debug("SIP Response:\n")
                for line in data:
                    lineUpper = line.upper()  # to negate different cases across responses
                    print(line)
                    if "200 OK" in line in lineUpper:
                        sentinal = False
                    if "486 BUSY HERE" in lineUpper:
                        sentinal = False
                    if "404 NOT FOUND" in lineUpper:
                        sentinal = False
                    if "480 TEMPORARILY NOT AVAILABLE" in lineUpper:
                        sentinal = False

    except ConnectionRefusedError as e:
        logger.error("Connection refused")

if __name__ == "__main__":
    main()