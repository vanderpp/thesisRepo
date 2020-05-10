#! /usr/bin/env python

from Crypto.Cipher import AES, DES3
from Crypto.Hash import SHA
import codecs
from scapy.layers.inet import IP, UDP, Ether
from scapy.all import *
from scapy.layers.isakmp import *
from Crypto.Cipher import *
from Crypto.Hash import *
# -------------------------------------------------------------------------------------------------------------------------
# In this file we address two issues:
# (1) the decryption problem (it fails) and
# (2) the  AttributeError: 'NoneType' object error in the payload strategy when trying to remove the first ISAKMP payload
#
# For 1, it appeared that the framework only allows a fixed length key of 128 bits (some [:32] truncating in the source code.
# This file is based on a capture where AES256-CBC was forced in Openswan. The 256 bit key and 128 bit IV's were taken from
# the Pluto log file, and are hardcoded in the file. We decrypt the packet with the key and select the IV based on the order
# of appearance in the Pluto logfile, aligned with the sequential position of a packet in the capture. The reserved field is
# indeed a suitable indicator to conclude succesful decryption. it has to be 0 at all times.
# CONCLUSION:   the decryption works for 256 bit keys. We presume the only modification that is necessary to the framework is
#               replacing the [:32] by a [:64] to have the whole key length.
#
# For 2, it appeared that no distinction was made in the original framework between accessing the next_payload field in
# the The ISAKMP Header and the The Generic Payload Header. While the latter can be accessed using the 'underlayer',
# the fomer cannot. This is why the framework crashes while trying to access the No 2 payload. No 1 payload cannot be
# removed since this is the ISAKMP header that contains all ISAKMP payloads. The next (No 2) can be modified. This is
# why there is a random choice of an int between 2 and length of the payloads. So the solution is that if we want to modify the
# payload 2, we need to update the ISAKMP header (pkt[ISAKMP]). If we want to update a generic payload header, we can
# access it with the underlayer statement.
#
# Continued with the payload_insert()
#
# When forcing insert at the end, it seems to work also if we add the +1 to the length of the array. This forces an insert
# at the very last position in the packet. The next_payload in the underlayer gets updated correctly.
# same logic applied: if you want to modify the ISAKMP header, you cannot use underlayer...
#
# Continued with payload_repeat()
# -------------------------------------------------------------------------------------------------------------------------

class PD_TYPE:
    SA = 1
    Transform = 3
    KE = 4
    ID = 5
    CERT = 6
    CR = 7
    Hash = 8
    SIG = 9
    Proposal = 10
    PD = 11
    VendorID = 13
    Header = -1

# ------------------------------------------------------------
# This class holds information about the current IKE
# session
# ------------------------------------------------------------
class Fuzz_session:
    fuzz = None
    enc_algo = None
    hash_algo = None
    enc_key = None
    iv = None
    init_cookie = None
    resp_cookie = None
    pkts_received = 0
    pkt_to_fuzz = 0


fuzz_session = Fuzz_session()

# ------------------------------------------------------------
# This function monitors the pluto.log file and captures
# when the encryption key is updated, it also keeps track
# of the current encryption scheme used, IV for CBC, etc.
# ------------------------------------------------------------
# PVDP: because this is an analysis, we dispose of the enc key and IV's we got
# from a pluto file. IV's in order of appearance in the pluto log file
# enc key (AES256):
pluto_key = 'f33f5bbf3e261399aa25d252a8965cd13a8f837cc46100825cfd42d033ee7c06'[:64]

pluto_IV = '1e c3 69 29  c7 95 05 f0  29 01 95 3b  83 9f 2d 4f 20 4d ae 3a'.replace(' ','')
#  pluto_IV = '88 ec ff bb  0b 9b e4 65  d9 40 0e 4d  08 78 96 9a'.replace(' ','')
#  pluto_IV = '15 ac 8a 11  85 4c f2 8b  51 15 0b a2  fd ef b8 52'.replace(' ','')
#pluto_IV = '55 9a fd 3c  df 49 3f 79  06 0d 06 eb  c0 b5 fe b2 7a 63 8d 63'.replace(' ','')
#  pluto_IV = '16 99 a1 30  f9 64 43 13  4e 13 b5 d5  60 63 87 a4'.replace(' ','')
#  pluto_IV = '15 ac 8a 11  85 4c f2 8b  51 15 0b a2  fd ef b8 52'.replace(' ','')
#pluto_IV = 'f0 bf df 6d  0b d8 0f 3c  26 e9 63 27  3e 99 fb 42 03 d7 c0 19'.replace(' ','')
#  pluto_IV = '91 45 38 2a  fb 13 f5 fe  c3 8a 0a c5  fb be d8 61'.replace(' ','')

def pluto_log_reader():
    print('---PLUTO_LOG_READER-----')
    # the opening of the file I changed to this location and I set the buffer to 96K
    global fuzz_session  # , pluto_log_fd
    # Here, there is lots of code in the fuzzer to determine Enc ALGO, Hash ALGO, KEY and IV.
    # omitted it for clarity of this script.
    fuzz_session.enc_key = pluto_key
    fuzz_session.iv = pluto_IV
    fuzz_session.enc_algo = AES
    fuzz_session.hash_algo = SHA
    print('key: ' + str(fuzz_session.enc_key))
    print('iv: ' + str(fuzz_session.iv))


# ------------------------------------------------------------
# This function reads the pluto log file and returns the
# current encryption key
# ------------------------------------------------------------
def get_key():
    pluto_log_reader()
    # log('Creating ' + str(fuzz_session.enc_algo) + ' key with enc key ' + fuzz_session.enc_key + ' and IV ' + fuzz_session.iv)
    #print('------get_key() debug info   START-------')
    # print(fuzz_session.enc_key[:64])  # .decode('hex')
    # print(fuzz_session.enc_key[:32])  # .decode('hex')
    #print('------get_key() debug info  END----------')

    AES256_KEY = codecs.decode(fuzz_session.enc_key[:64], 'hex')
    AES256_IV  = codecs.decode(fuzz_session.iv[:32], 'hex')
    return AES.new(AES256_KEY, AES.MODE_CBC, AES256_IV)
    # print(fuzz_session.iv[:32]).decode('hex')

    # if fuzz_session.enc_algo == AES:
    #    return AES.new(fuzz_session.enc_key[:32].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:32].decode('hex'))
    # elif fuzz_session.enc_algo == DES3:
    #   return DES3.new(fuzz_session.enc_key[:48].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:16].decode('hex'))
    # else:
    #   #log('Not supported encryption algorithm')
    #   sys.exit(0)


def read_pcap(pcap_file):
    pkt = rdpcap(pcap_file)
    if len(pkt) > 0:
        return pkt[0]
    else:
        return None


def decrypt(pkt):
   print('---DECRYPTING---')
   # log('Decrypting a packet')
   # log(str(pkt[ISAKMP]).encode('hex'))
   key = get_key()
   if pkt[ISAKMP].next_payload == PD_TYPE.ID:
      pkt[ISAKMP].payload = ISAKMP_payload_ID(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.KE:
      pkt[ISAKMP].payload = ISAKMP_payload_KE(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.Proposal:
      pkt[ISAKMP].payload = ISAKMP_payload_Proposal(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.SA:
      pkt[ISAKMP].payload = ISAKMP_payload_SA(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.Transform:
      pkt[ISAKMP].payload = ISAKMP_payload_Transform(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.VendorID:
      pkt[ISAKMP].payload = ISAKMP_payload_VendorID(key.decrypt(pkt[ISAKMP].payload.load))
   else:
      pkt[ISAKMP].payload = ISAKMP_payload_Hash(key.decrypt(pkt[ISAKMP].payload.load))
   print('Decrypted packet:\n' + pkt.command() )
   # we assume the res field is not used and is set to 0, this allows us to check if the decryption was successful
   if pkt[ISAKMP].payload.res != 0:
      print('Decryption failed, probably the key was incorrect, this can happen if pluto has not written the latest key in its log file')
      pkt[ISAKMP].payload = ISAKMP_payload(next_payload=0)
      pkt[ISAKMP].next_payload = 6
   else:
      print('DECRYPTION SUCCESS!')
      #sys.exit(0)

#------------------------------------------------------------
# This function inserts a random payload in the packet
#------------------------------------------------------------
def payload_insert(pkt):
   print('---PAYLOAD_INSERT---')
   print('[DEBUG INFO] original packet:')
   print(pkt.command())

   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)

   insert_pd = random.randint(2,len(payloads)+1 )
   #insert_pd = len(payloads)+1 # force insert at the end !!! seems to work if we add the +1 to insert at the very last position.
   #insert_pd = 2

   print('[DEBUG INFO] inserting at payload No:  ' + str(insert_pd))
   cur_payload = pkt[ISAKMP]
   for i in range(1,insert_pd):
      cur_payload = cur_payload.payload

   print('[DEBUG INFO] cur_payload after iter:  ' + str(cur_payload.command()))

   r = random.choice( [ (fuzz(ISAKMP_payload()), 6), (fuzz(ISAKMP_payload_Hash()), 8), (fuzz(ISAKMP_payload_ID()), 5),
                             (fuzz(ISAKMP_payload_KE()), 4), (fuzz(ISAKMP_payload_Nonce()), 8), (fuzz(ISAKMP_payload_Proposal()), 10),
                             (fuzz(ISAKMP_payload_SA()), 1), (fuzz(ISAKMP_payload_Transform()), 3), (fuzz(ISAKMP_payload_VendorID()), 13) ] )

   print('[DEBUG INFO] r :')
   print(str(r[0].command()))
   print(str(r[1]))

   print('[DEBUG INFO] the payload where we cons-ed a payload in front:')
   print(r[0].command())

   # differentiate between inserting in generic payload header or ISAKMP Header
   if insert_pd > 2:
      r[0].payload = eval(cur_payload.command())
      r[0].next_payload = cur_payload.underlayer.next_payload
      cur_payload.underlayer.next_payload = r[1]
      cur_payload.underlayer.payload = r[0]
   else:
       r[0].payload = eval(cur_payload.command())
       r[0].next_payload = pkt[ISAKMP].next_payload
       pkt[ISAKMP].next_payload = r[1]
       pkt[ISAKMP].payload = r[0]

   print('[DEBUG INFO] modified packet:')
   print(pkt.command())

#------------------------------------------------------------
# This function removes a payload from the packet
#------------------------------------------------------------

def payload_remove(pkt):
   print('---PAYLOAD_REMOVE---')
   print('[DEBUG INFO] original packet:')
   print(pkt.command())

   cur_payload = pkt[ISAKMP]
   payloads = []

   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   print('[DEBUG INFO] total No of Payloads: ' + str(len(payloads)))

   remove_pd = random.randint(2,len(payloads) ) # start at 2 because we cannot remove the ISAKMP header
   print('[DEBUG INFO] removing payload No:  ' + str(remove_pd))

   cur_payload = pkt[ISAKMP]

   print('[DEBUG INFO] The pkt to treat is:  ' + str(cur_payload.command()))
   print('[DEBUG INFO] contents of the arr:  ' + str(payloads))

   for i in range(1,remove_pd):
      cur_payload = cur_payload.payload

   print('[DEBUG INFO] cur_payload after iter:  ' + str(cur_payload.command()))
   print('[DEBUG INFO] the next payload type I want to assign:  ' + str(cur_payload.next_payload))

   # differentiate between inserting in generic payload header or ISAKMP Header
   if  remove_pd > 2:
       # Case of the Generic Payload Header
       cur_payload.underlayer.next_payload = cur_payload.next_payload
       if cur_payload.payload.command() == '':
         del cur_payload.underlayer.payload
       else:
         cur_payload.underlayer.payload = eval(cur_payload.payload.command())
   else:
       # Case of the ISAKMP Header
       pkt[ISAKMP].next_payload = cur_payload.next_payload
       if cur_payload.payload.command() == '':
         del pkt[ISAKMP].payload
       else:
         pkt[ISAKMP].payload = eval(cur_payload.payload.command())

   print('[DEBUG INFO] modified packet:')
   print(pkt.command())

#------------------------------------------------------------
# This function repeats a payload in the packet
#------------------------------------------------------------
def payload_repeat(pkt):
   print('---PAYLOAD_REPEAT---')
   print('[DEBUG INFO] original packet:')
   print(pkt.command())

   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)

   repeat_pd = random.randint(2,len(payloads) )
   print('[DEBUG INFO] repeating payload No:  ' + str(repeat_pd))

   cur_payload = pkt[ISAKMP]
   for i in range(1,repeat_pd):
      cur_payload = cur_payload.payload

   #differentiate between inserting in generic payload header or ISAKMP Header
   if repeat_pd > 2:
       cur_payload.payload = eval(cur_payload.command())
       cur_payload.next_payload = cur_payload.underlayer.next_payload
   else:
       cur_payload.payload = eval(cur_payload.command())
       cur_payload.next_payload = pkt[ISAKMP].next_payload

   print('[DEBUG INFO] modified packet:')
   print(pkt.command())
def arrayFiller():
   arr = [(fuzz(ISAKMP_payload()), 6), (fuzz(ISAKMP_payload_Hash()), 8), (fuzz(ISAKMP_payload_ID()), 5),
                      (fuzz(ISAKMP_payload_KE()), 4), (fuzz(ISAKMP_payload_Nonce()), 8),
                      (fuzz(ISAKMP_payload_Proposal()), 10),
                      (fuzz(ISAKMP_payload_SA()), 1), (fuzz(ISAKMP_payload_Transform()), 3),
                      (fuzz(ISAKMP_payload_VendorID()), 13)]
   return arr

def pkt_tst():
    the_array = arrayFiller()
    print(the_array)
    for i in range(0, len(the_array)):
        print(the_array[i][0].command())

    print('-----PROP---------')
    Prop = fuzz(ISAKMP_payload_Proposal())
    print(Prop.command())

    Transform = fuzz(ISAKMP_payload_Transform())
    print(Transform.command())

    Prop.payload = Transform
    print(Prop.command())

    print('-----SA-----------')
    Sa = ISAKMP_payload_SA()
    print(Sa.command())

def main():
    # Path's for Windows
    # pcapFilePath = r"C:\Users\Van Der Paelt.P\OneDrive - Vrije Universiteit Brussel\VUB - Thesis\Captures-logs-outputs\isakmp_msg3.pcap"
    pcapFilePath = r"C:\Users\Van Der Paelt.P\OneDrive - Vrije Universiteit Brussel\VUB - Thesis\Captures-logs-outputs\CaptureForDecryption\isakmp_exchange_for_decryption_msg3.pcap"

    # Path's for Mac
    # pcapFilePath = "/Users/pietvanderpaelt/OneDrive - Vrije Universiteit Brussel/VUB - Thesis/Captures-logs-outputs/isakmp_msg1-5.pcap"
    # pcapFilePath = "/Users/pietvanderpaelt/OneDrive - Vrije Universiteit Brussel/VUB - Thesis/Captures-logs-outputs/isakmp_msg4.pcap"
    # pcapFilePath = "/Users/pietvanderpaelt/OneDrive - Vrije Universiteit Brussel/VUB - Thesis/Captures-logs-outputs/CaptureForDecryption/isakmp_exchange_for_decryption_msg3.pcap"

    #pkt = read_pcap(pcapFilePath)
    #decrypt(pkt)
    #payload_insert(pkt)
    #payload_remove(pkt)
    #payload_repeat(pkt)




    # hebben een subType:
    # ISAKMP_payload_Proposal(trans=Raw())
    # ISAKMP_payload_SA(prop=Raw())
    pkt = Raw()
    print(pkt.command())



if __name__ == "__main__":
    main()
