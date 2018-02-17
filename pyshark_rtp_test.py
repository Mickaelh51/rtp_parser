#!/usr/bin/env python2.7
import pyshark
import os

AllCallsData = {}
cap = pyshark.FileCapture('/data/home/mike/Documents/test_RTP_python/capt_outgoing_call.pcap', display_filter='sip or rtp')


for i in cap:
    CallsData = []
    try:
        if i.sip.get_field_value('Method') == 'INVITE':
            if i.sip.get_field("sdp.media.proto") == "RTP/AVP" and i.sip.get_field("Content-Type") == "application/sdp":
                CalleeIpPort = i.sip.get_field("sdp.media.port")
                CalleeSipFromTag = i.sip.get_field("sip.from.tag")
                CalleeSipCallID = i.sip.get_field("sip.Call-ID")
                print "< =========== >"
                print "INVITE call Method with media port: " + CalleeIpPort
                print "From TAG: " + CalleeSipFromTag
                print "CallID: " + CalleeSipCallID
                print "< =========== >"

                AudioFileName = 'my_audio_callee_' + str(CalleeSipFromTag)
                AllCallsData[CalleeIpPort] = {}
                AllCallsData[CalleeIpPort]["filename"] = AudioFileName
    except:
        pass

    try:
        if i.sip.get_field("sip.Status-Line") == 'SIP/2.0 200 OK' and i.sip.get_field("Status-Code") == "200":
            if i.sip.get_field("sdp.media.proto") == "RTP/AVP" and i.sip.get_field("Content-Type") == "application/sdp":
                CallerIpPort = i.sip.get_field("sdp.media.port")
                CallerSipFromTag = i.sip.get_field("sip.from.tag")
                CallerSipToTag = i.sip.get_field("sip.to.tag")
                CallerSipCallID = i.sip.get_field("sip.Call-ID")
                print "< =========== >"
                print "200OK Method with media port: " + CallerIpPort
                print "From TAG: " + CallerSipFromTag + " // To TAG: " + CallerSipToTag
                print "CallID: " + CallerSipCallID
                print "< =========== >"

                AudioFileName = 'my_audio_caller_' + str(CalleeSipFromTag)
                CallsData.append(AudioFileName)
                AllCallsData[CallerIpPort] = {}
                AllCallsData[CallerIpPort]["filename"] = AudioFileName
    except:
        pass

    #print AllCallsData

    try:
        #print i[2]._all_fields
        Ssrc = i[3].get_field("rtp.ssrc")
        if Ssrc:
            destPort = i[2].get_field("udp.dstport")
            if AllCallsData.get(destPort):
                Payload = i[3].payload.split(":")

                try:
                    if AllCallsData[destPort]["payload"]:
                        AllCallsData[destPort]["payload"].append(Payload)
                except:
                    data = []
                    data.append(Payload)
                    AllCallsData[destPort]["payload"] = data
    except:
        #raise
        pass

for key, value in AllCallsData.iteritems() :
    filename =  AllCallsData[key]["filename"]
    raw_audio = open(filename + '.raw','wb')
    for rtp_packet in AllCallsData[key]["payload"]:
        packet = " ".join(rtp_packet)
        audio = bytearray.fromhex(packet)
        raw_audio.write(audio)

    os.system("/usr/bin/sox -t raw -r 8000 -c 1 -e a-law " + filename + ".raw " + filename + ".wav")
