#! /usr/bin/env python

import fcntl
import os
import threading
import thread
import signal
import sys
import getopt
import datetime
import time
import random
from Crypto.Cipher import *
from Crypto.Hash import *
from scapy.all import *

#------------------------------------------------------------
# This class enumerates the different payload types
#------------------------------------------------------------
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

#------------------------------------------------------------
# This class holds information about the current IKE
# session
#------------------------------------------------------------
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


#------------------------------------------------------------
# Global variables
#------------------------------------------------------------
# prob_listi     - assigns a probability of applying the different
#                  fuzz categories
# fuzz_session   - keeps information about the current IKE session
# ip             - the IP of the local machine
# opp_ip         - the IP of the remote machine (under test)
# log_file       - stores fuzzing information
# iface          - the interface of the local machine (e.g. eth0)
# fuzz_mode      - boolean, specifies whether packets are fuzzed or not
# pluto_log_file - path to the pluto log file
# pluto_log_fd   - the file descriptor of the pluto log file
# running        - is the fuzzer running?
# ike_port       - the ike port (to which the packets are sent by default
# dest_port      - the ike port on which the remote machine is listening
# lock1, lock2   - semaphores used to synchronize the thread snooping 
#                  for packets (tcpdump) and the main fuzzer thread 
#                  sending the packets
#------------------------------------------------------------
prob_list = [('payload', 0.0), ('field', 1.0), ('packet', 0.0)] #config-fuzz-path
fuzz_session = Fuzz_session()
sut_ip = None
sut_mac = None
local_mac = None
log_file = None
log_dir = None
iface = None
fuzz_mode = False
pluto_log_file= None
pluto_log_fd = None
running = True
ike_port = 500
lock1 = threading.Semaphore(0)
lock2 = threading.Semaphore(1)
bomb_factor = 10         # number of bomber runs
targeted_state_to_bomb = 3 # state we want to bomb (0, 1, 2, 3, 4) => zero based correspondence to ISAKMP states
fuzz_path = []
bomber_mode =False

#------------------------------------------------------------
# This function logs all output to a file, if no file is
# specified, it prints to standard output
#------------------------------------------------------------
def log(msg):
   #log_msg = '[' + str(datetime.datetime.now()) + '] ' + msg
   log_msg = '[' + str(datetime.now()) + '] ' + msg
   if log_file is not None and msg is not None:
      log_file.write(log_msg + '\n')
      log_file.flush()
   else:
      print log_msg


#------------------------------------------------------------
# This function cleans temporary files and stop the fuzzer 
# upon Ctrl+c event
#------------------------------------------------------------
def signal_handler(signal, frame):
   running = False
   log('Cleaning up temporary pcap files')
   os.system('sudo rm -rf ' + log_dir + 'pkt*')
   log('Stopping')
   sys.exit(0)


#------------------------------------------------------------
# This function should be run in a separate thread. It
# runs tcpdump to capture packets into pcap format. It
# synchronizes with the fuzzer so that a packet is sent
# only after tcpdump is listening for the next packet.
#------------------------------------------------------------
def start_tcpdump():
   log('Tcpdump running')
   pkt_count = 1
   while running:
      # wait until the fuzzer sends the packet that was just captured
      lock2.acquire()
      pcap_file = log_dir + 'pkt_' + str(pkt_count) + '.pcap'
      os.system('tcpdump -i ' + iface + ' dst ' + sut_ip + ' and ether dst ' + local_mac + ' and port ' + str(ike_port) + ' -c 1 -w ' + pcap_file + ' &')
      if pkt_count > 1:
         # busy wait until tcpdump is up and running
         while int(os.popen('sudo ps x | grep "tcpdump -i ' + iface + '" | wc -l').read().rstrip()) < 1:
            pass
         # tcpdump is listening, safe to send the packet
         lock1.release()
      pkt_count += 1


#------------------------------------------------------------
# This function returns a random well-formed packet (that
# was captured from previous sessions of the protocol)
#------------------------------------------------------------
def get_random_pkt():
   num_pcap_pkts = int(os.popen('ls *.pcap | wc -l').read().rstrip())
   if num_pcap_pkts < 1:
      return None
   pcap_file = log_dir + 'pkt_'+str(random.randint(1,num_pcap_pkts-1))+'.pcap'
   rand_pkt = read_pcap(pcap_file)
   return rand_pkt
   

#------------------------------------------------------------
# This function reads a pcap file and returns a packet
# object.
#------------------------------------------------------------
def read_pcap(pcap_file):
   while not( os.path.isfile(pcap_file) and os.path.getsize(pcap_file) > 0 ):
      pass
   pkts=rdpcap(pcap_file)
   if len(pkts) > 0:
      return pkts[0]
   else:
      return None


#------------------------------------------------------------
# This function rewrites the packet port to the dest port and deletes
# the IP and UDP checksums, if the checksums do not match,
# the OS might (and should) ignore the packets.
#------------------------------------------------------------
def rewrite_port(pkt):
   pkt[UDP].dport = dest_port
   del pkt[IP].chksum
   del pkt[UDP].chksum


def rewrite_mac(pkt):
   pkt[Ether].dst = sut_mac
   pkt[UDP].chksum = 0
   #try:
   #   del pkt[ISAKMP_payload_Transform].length
   #except AttributeError:
   #   pass


#------------------------------------------------------------
# Chooses an item from a list defined as:
# [(item_1,prob_1), (item_2,prob_2),... ,(item_n,prob_n)]
# where prob_i is the probability of choosing item_i
#------------------------------------------------------------
def weighted_choice(items):
   weight_total = sum((item[1] for item in items))
   n = random.uniform(0, weight_total)
   for item, weight in items:
      if n < weight:
         return item
      n = n - weight
   return item


#------------------------------------------------------------
# When a new IKE session is detected, the fuzzer also starts
# a new session, i.e. it will fuzz a message/payload during
# that session
#------------------------------------------------------------
def init_new_session(pkt):
   global fuzz_session
   log('Starting a new session')
   fuzz_session = Fuzz_session()
   # choose a fuzzing approach depending on prob list
   fuzz_session.fuzz = weighted_choice(prob_list) #config-fuzz-path #fuzz_session.fuzz = 'field'
   log('[DEBUG INFO] (payload/field/packet) = ' + fuzz_session.fuzz )
   fuzz_path.append(fuzz_session.fuzz)
   # choose a random packet to fuzz
   fuzz_session.pkt_to_fuzz = random.randint(1,5) #config-fuzz-path
   fuzz_session.pkt_to_fuzz = 3
   fuzz_path.append(fuzz_session.pkt_to_fuzz)
   if fuzz_session.fuzz == 'payload':
      log('Prepare to fuzz a payload in packet ' + str(fuzz_session.pkt_to_fuzz))
   elif fuzz_session.fuzz == 'field':
      log('Prepare to fuzz a field in packet ' + str(fuzz_session.pkt_to_fuzz))
   elif fuzz_session.fuzz == 'packet':
      log('Prepare to insert random packet after packet ' + str(fuzz_session.pkt_to_fuzz))

   fuzz_session.init_cookie = pkt[ISAKMP].init_cookie
   fuzz_session.resp_cookie = pkt[ISAKMP].resp_cookie


#------------------------------------------------------------
# This function encrypts the packet
#------------------------------------------------------------
def encrypt(pkt):
   log('Encrypting a packet')
   key = get_key()
   try:
      pkt[ISAKMP].payload = Raw(key.encrypt( str(pkt[ISAKMP].payload) + '\x00'* ( (16 - len(pkt[ISAKMP].payload)%16 )%16 ) ) )
   except ValueError:
      if fuzz_session.fuzz == 'payload':
         log('Encryption failed, probably fuzzing a payload and length is unknown..')
         encrypt(pkt)
   log('Encrypted packet:\n' + pkt.command())
   return pkt




#------------------------------------------------------------
# This function reads the pluto log file and returns the
# current encryption key
#------------------------------------------------------------
def get_key():
   pluto_log_reader()
   log('Creating ' + str(fuzz_session.enc_algo) + ' key with enc key ' + fuzz_session.enc_key + ' and IV ' + fuzz_session.iv)
   if fuzz_session.enc_algo == AES:
      return AES.new(fuzz_session.enc_key[:32].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:32].decode('hex'))
   elif fuzz_session.enc_algo == DES3:
     return DES3.new(fuzz_session.enc_key[:48].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:16].decode('hex'))
   else:
     log('Not supported encryption algorithm')
     sys.exit(0)


#------------------------------------------------------------
# This function decrypts the packet
#------------------------------------------------------------

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

def decrypt(pkt):
   log('Decrypting a packet')
   log(str(pkt[ISAKMP]).encode('hex'))
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
   log('Decrypted packet:\n' + pkt.command() )
   # we assume the res field is not used and is set to 0, this allows us to check if the decryption was successful
   if pkt[ISAKMP].payload.res != 0:
      print 'DECRYPTION FAILED!'
      log('Decryption failed, probably the key was incorrect, this can happen if pluto has not written the latest key in its log file')
      pkt[ISAKMP].payload = ISAKMP_payload(next_payload=0)
      pkt[ISAKMP].next_payload = 6
   else:
      print 'DECRYPTION SUCCESS!'
      #sys.exit(0)


#------------------------------------------------------------
# This function monitors the pluto.log file and captures
# when the encryption key is updated, it also keeps track
# of the current encryption scheme used, IV for CBC, etc.
#------------------------------------------------------------
def pluto_log_reader():
   print 'pluto log reader'
   # the opening of the file I changed to this location and I set the buffer to 96K
   global pluto_log_fd,fuzz_session
   log('Initializing pluto log reader')
   pluto_log_fd = open(pluto_log_file, 'r', buffering=96*1024)

   # wait to make sure that pluto saved to pluto.log
   time.sleep(0.2)
   count=0
   line = pluto_log_fd.readline().rstrip()
   print 'first line: ' + str(line)
   while line != '':
      count += 1
      if '! enc key:' in line:
         fuzz_session.enc_key = line[12:].replace(' ', '')
         line = pluto_log_fd.readline().rstrip()
         if '! enc key:' in line:
            fuzz_session.enc_key += line[12:].replace(' ', '')
         else:
            continue
      elif '! IV:  ' in line:
         fuzz_session.iv = line[7:].replace(' ','')
         line = pluto_log_fd.readline().rstrip()
         if '! IV:  ' in line:
            fuzz_session.iv += line[7:].replace(' ', '')
         else:
            continue
      elif '| IV:' in line:
         line = pluto_log_fd.readline().rstrip()
         fuzz_session.iv = line[4:].replace(' ','')
      elif 'OAKLEY_AES_CBC' in line:
         fuzz_session.enc_algo = AES
      elif 'OAKLEY_3DES_CBC' in line:
         fuzz_session.enc_algo = DES3
      elif 'OAKLEY_SHA1' in line:
         fuzz_session.hash_algo = SHA
      elif 'OAKLEY_MD5' in line:
         fuzz_session.hash_algo = MD5
      line = pluto_log_fd.readline().rstrip()

   log('key: ' + str(fuzz_session.enc_key))
   log('iv: ' + str(fuzz_session.iv))
   log('enc: ' + str(fuzz_session.enc_algo))
   log('lines read: ' + str(count))

#------------------------------------------------------------
# This function repeats a payload in the packet
#------------------------------------------------------------
def payload_repeat(pkt):
   log('---PAYLOAD_REPEAT---')
   log('[DEBUG INFO] original packet:')
   log(pkt.command())

   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)

   repeat_pd = random.randint(2,len(payloads))
   log('[DEBUG INFO] repeating payload No:  ' + str(repeat_pd))
   fuzz_path.append(repeat_pd)

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

   log('[DEBUG INFO] modified packet:')
   log(pkt.command())


#------------------------------------------------------------
# This function removes a payload from the packet
#------------------------------------------------------------

def payload_remove(pkt):
   log('---PAYLOAD_REMOVE---')
   log('[DEBUG INFO] original packet:')
   log(pkt.command())

   cur_payload = pkt[ISAKMP]
   payloads = []

   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   log('[DEBUG INFO] total No of Payloads: ' + str(len(payloads)))

   remove_pd = random.randint(2,len(payloads)) # start at 2 because we cannot remove the ISAKMP header
   log('[DEBUG INFO] removing payload No:  ' + str(remove_pd))
   fuzz_path.append(remove_pd)

   cur_payload = pkt[ISAKMP]

   log('[DEBUG INFO] The pkt to treat is:  ' + str(cur_payload.command()))
   log('[DEBUG INFO] contents of the arr:  ' + str(payloads))

   for i in range(1,remove_pd):
      cur_payload = cur_payload.payload

   log('[DEBUG INFO] cur_payload after iter:  ' + str(cur_payload.command()))
   log('[DEBUG INFO] the next payload type I want to assign:  ' + str(cur_payload.next_payload))

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

   log('[DEBUG INFO] modified packet:')
   log(pkt.command())



#------------------------------------------------------------
# This function inserts a random payload in the packet
#------------------------------------------------------------
def payload_insert(pkt):
   log('---PAYLOAD_INSERT---')
   log('[DEBUG INFO] original packet:')
   log(pkt.command())

   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)

   insert_pd = random.randint(2,len(payloads))
   fuzz_path.append(insert_pd)
   #insert_pd = len(payloads)+1 # force insert at the end !!! seems to work if we add the +1 to insert at the very last position.
   #insert_pd = 2

   log('[DEBUG INFO] inserting at payload No:  ' + str(insert_pd))
   cur_payload = pkt[ISAKMP]
   for i in range(1,insert_pd):
      cur_payload = cur_payload.payload

   log('[DEBUG INFO] cur_payload after iter:  ' + str(cur_payload.command()))

   # r = random.choice( [    (fuzz(ISAKMP_payload()), 6),
   #                         (fuzz(ISAKMP_payload_Hash()), 8),
   #                         (fuzz(ISAKMP_payload_ID()), 5),
   #                         (fuzz(ISAKMP_payload_KE()), 4),
   #                         (fuzz(ISAKMP_payload_Proposal()), 10),
   #                         (fuzz(ISAKMP_payload_SA()), 1),
   #                         (fuzz(ISAKMP_payload_Transform()), 3),
   #                         (fuzz(ISAKMP_payload_VendorID()), 13) ] )
   r = random.choice( [    (ISAKMP_payload(), 6),
                           (ISAKMP_payload_Hash(), 8),
                           (ISAKMP_payload_ID(), 5),
                           (ISAKMP_payload_KE(), 4),
                           (ISAKMP_payload_Proposal(), 10),
                           (ISAKMP_payload_SA(), 1),
                           (ISAKMP_payload_Transform(), 3),
                           (ISAKMP_payload_VendorID(), 13) ] )
   fuzz_path.append(str(r[1]))

   # this one caused the fuzze to crash... lifted it from the list
   # (fuzz(ISAKMP_payload_Nonce()), 8),

   log('[DEBUG INFO] r was assigned by random choice:')
   log(str(r[0].command()))
   log(str(r[1]))

   log(r[0].command())

   # differentiate between inserting in generic payload header or ISAKMP Header
   if insert_pd > 2:
      r[0].payload = eval(cur_payload.command())
      log('[DEBUG INFO] marker1')
      r[0].next_payload = cur_payload.underlayer.next_payload
      log('[DEBUG INFO] marker2')
      cur_payload.underlayer.next_payload = r[1]
      log('[DEBUG INFO] marker3')
      cur_payload.underlayer.payload = r[0]
      log('[DEBUG INFO] marker4')
   else:
       r[0].payload = eval(cur_payload.command())
       log('[DEBUG INFO] marker5')
       r[0].next_payload = pkt[ISAKMP].next_payload
       log('[DEBUG INFO] marker6')
       pkt[ISAKMP].next_payload = r[1]
       log('[DEBUG INFO] marker7')
       pkt[ISAKMP].payload = r[0]
       log('[DEBUG INFO] marker8')

   log('[DEBUG INFO] modified packet:')
   log(pkt.command())


#------------------------------------------------------------
# A map from payload fuzz type to payload fuzz function
#------------------------------------------------------------
fuzz_payload_func = {}
fuzz_payload_func['repeat'] = payload_repeat
fuzz_payload_func['remove'] = payload_remove
fuzz_payload_func['insert'] = payload_insert



#------------------------------------------------------------
# This function fuzzes a payload
#------------------------------------------------------------
def fuzz_payload(pkt):
   fuzz_type = random.choice( ['repeat', 'remove', 'insert'] )
   fuzz_path.append(fuzz_type)
   log('[DEBUG INFO] (repeat/remove/insert): ' + fuzz_type)
   log('Fuzzing a payload ' + fuzz_type)

   encrypt_pkt = False
   if pkt[ISAKMP].flags == 1L:
     decrypt(pkt)
     encrypt_pkt = True

   fuzz_payload_func[fuzz_type](pkt)
   log('Fuzzed packet:\n'+pkt.command())
   pkt = eval(pkt.command())

   if encrypt_pkt:
      return_pkt = encrypt(pkt)
   else:
      return_pkt = pkt
   log('Fuzz_payload return: ' + return_pkt.command())
   return return_pkt


#------------------------------------------------------------
# This function fuzzes a field
#------------------------------------------------------------
def fuzz_field(pkt):
   log('Fuzzig a field')
   # Check if the packet is encrypted
   encrypt_pkt = False
   if pkt[ISAKMP].flags == 1L:
     decrypt(pkt)
     encrypt_pkt = True

   # Check what payloads are contained in the packet and
   # randomly choose one to fuzz a field in it
   cur_payload = pkt[ISAKMP]
   payloads = []
   payload_type = []
   # these two arrays are synchronised...
   payload_type.append(PD_TYPE.Header)
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      if cur_payload.next_payload != 0:
         payload_type.append(cur_payload.next_payload)
      cur_payload = cur_payload.payload
   if len(payloads) == 0:
      payloads.append(pkt[ISAKMP])
   pd_to_fuzz = random.randint(0,len(payloads)-1)
   fuzz_path.append(pd_to_fuzz)
   #pd_to_fuzz = 0 #config-fuzz-path # to fuzz the header, we need to fuzz the first payload (0) in the array
   fuzz_func[ payload_type[pd_to_fuzz] ](payloads[pd_to_fuzz])
   log('Fuzzed packet:\n'+pkt.command())

   #if encrypt_pkt:
   # encrypt(pkt)

   if encrypt_pkt:
      return_pkt = encrypt(pkt)
   else:
      return_pkt = pkt
   log('Fuzz_field return: ' + return_pkt.command())
   return return_pkt

#------------------------------------------------------------
# This function fuzzes a packet (sends a random packet)
#------------------------------------------------------------
def fuzz_packet(pkt):
   log('Fuzzing packet')
   rand_pkt = get_random_pkt()
   if rand_pkt != None:
      log('Sending random packet: ' + rand_pkt.command())
      rewrite_mac(rand_pkt)
      sendp(rand_pkt)
   else:
      log('Failed to fetch random packet')
   return pkt


#------------------------------------------------------------
# Fuzz a packet
#------------------------------------------------------------
def fuzz_pkt(pkt):
   if fuzz_session.fuzz == 'payload':
      return_pkt2 = fuzz_payload(pkt)
   elif fuzz_session.fuzz == 'field':
      return_pkt2 = fuzz_field(pkt)
   elif fuzz_session.fuzz == 'packet':
      return_pkt2 = fuzz_packet(pkt)
   return return_pkt2


#------------------------------------------------------------
# This function processes each new packet and decides whether
# we should fuzz it or not
#------------------------------------------------------------
def process_pkt(pkt,enabler):
   global fuzz_session, targeted_state_to_bomb
   fuzz_session.pkts_received += 1
   if (fuzz_session.pkt_to_fuzz == fuzz_session.pkts_received) and enabler:
      return_pkt3 = fuzz_pkt(pkt)
   else:
      return_pkt3 = pkt
   #log('[process_pkt pkt]' + pkt.command() )
   #log('[process_pkt pkt]' + return_pkt3.command())
   return return_pkt3

#def process_pkt_bomber(bomb_pkt):
def process_pkt_bomber(pcap_file_2):
   global fuzz_session, bomb_factor, fuzz_path

   #fuzz_session.pkts_received += 1 ==> Not necessary, the value will get updated after the bomber run by process_pkt()
   log("[BOMBER] call of proc")
   log('[BOMBER] starting a bomb run of size: ' + str(bomb_factor))
   log("[BOMBER] targeted_state_to_bomb: " + str(targeted_state_to_bomb))
   log("[BOMBER] fuzz_session.pkts_received: " + str(fuzz_session.pkts_received))
   #log("[BOMBER] packet passed to process_pkt_bomber: " + original_pkt.command() )
   #n = 0
   #while n < bomb_factor:
   for n in range(0,bomb_factor):
      bomb_pkt = read_pcap(pcap_file_2)
      log("[BOMBER] loop: " + str(n) + ' of ' + str(bomb_factor))
      log('[BOMBER] run_pkt (fresh packet for run): ' + bomb_pkt.command())

      #doing he actual fuzz here
      fuzz_return = fuzz_pkt(bomb_pkt)
      log('[BOMBER] fuzz_return (fuzzed packet for run): ' + fuzz_return.command())

      #sending and logging
      log('[BOMBER] Sending the fuzzed packet: ' + fuzz_return.command())
      rewrite_mac(fuzz_return)
      sendp(fuzz_return)

      #prepare for next loop
      fuzz_path = []
      time.sleep(0.1)

   log("[BOMBER] end of proc")
#------------------------------------------------------------
# The main fuzzer function
#------------------------------------------------------------
def start_fuzzer():
   global running, bomber_mode

   #  changed opening of the log file to the log_reader function

   #pluto_log_fd
   #log('Initializing pluto log reader')
   #pluto_log_fd = open(pluto_log_file, 'r')

   os.system('sudo rm -rf pkt*')
   thread.start_new_thread(start_tcpdump, () )
   log('Fuzzer started')
   pkt_count = 1
   while running:
      pcap_file = log_dir + 'pkt_' + str(pkt_count) + '.pcap'
      #log('Built pcap file path: ' + pcap_file)
      pkt = read_pcap(pcap_file)
      #original_pkt = read_pcap(pcap_file)
      if pkt is None:
         continue
      pkt_count = pkt_count + 1
      log('Received packet:\n' + pkt.command() + '\n')
      # Detect if the packets belongs to a new IKE session
      if fuzz_mode and pkt[ISAKMP].resp_cookie != fuzz_session.resp_cookie and pkt[ISAKMP].init_cookie != fuzz_session.init_cookie:
         init_new_session(pkt)

      # The repeat loop to bomb the DUT should start here: fuzz the packet n times and send it to the DUT
      # to get normal operation back, disable this call, and set "process_pkt(pkt, False)" to True

      if (targeted_state_to_bomb == fuzz_session.pkts_received) and bomber_mode :
         process_pkt_bomber(pcap_file)


      #process_pkt() is still necessary: we want the process_pkt() to update pkts_received. Fuzzing is no longer necessary here. We tried
      #turning it off with a switch passed to the process_pkt (enabler argument)
      if fuzz_mode:
         return_pkt4 = process_pkt(pkt, not bomber_mode)
      else:
         return_pkt4 = pkt

      #original code hereAfter: we send pkt to get the protocol execution in the next state. As if process_pkt was never called.


      #rewrite_mac(pkt)
      rewrite_mac(return_pkt4)
      lock2.release()
      lock1.acquire()
      #log('Sending packet\n' + pkt.command())
      #sendp(pkt)
      log('Sending packet\n' + return_pkt4.command())
      sendp(return_pkt4)


#------------------------------------------------------------
# The main function, reads the fuzzer arguments and starts
# the fuzzer
#------------------------------------------------------------
def main():
   global sut_ip, local_mac, sut_mac, log_file, fuzz_mode, log_dir, iface, pluto_log_file, prob_list

   opts, args = getopt.getopt(sys.argv[1:], 'i:l:fe:p:t:', ['sut-ip=', 'local-mac=', 'sut-mac=', 'log=', 'fuzz-mode', 'iface=', 'pluto-log=', 'type='])
   for o, a in opts:
      print o, a
      if o in ('-i', '--sut-ip'):
         sut_ip = a
      if o in ('--local-mac'):
         local_mac = a
      if o in ('--sut-mac'):
         sut_mac = a
      if o in ('-l', '--log'):
         log_file = open(a, 'w')
      if o in ('-f', '--fuzz-mode'):
         fuzz_mode = True
      if o in ('-e', '--iface'):
         iface = a
      if o in ('-p', '--pluto-log'):
         pluto_log_file = a
      if o in ('-t', '--type'):
         prob_list = [(a,1)]
         if a not in ['field', 'payload', 'packet']:
            prob_list = None

   if log_dir is None:
      log_dir = os.getcwd()+'/'
   else:
      log_dir=os.path.abspath(fp)[:os.path.abspath(fp).rfind('/')]+'/'

   if prob_list is None:
      log('Invalid fuzz type')
      sys.exit(0)

   if( sut_ip is None or sut_mac is None or local_mac is None or iface is None or pluto_log_file is None):
      print_usage()
      sys.exit(0)

   bind_layers(UDP, ISAKMP, sport=500)
   bind_layers(UDP, ISAKMP, dport=500)

   log('Fuzz mode: ' + str(fuzz_mode))
   log('SUT IP: ' + str(sut_ip))
   log('SUT MAC address: ' + str(sut_mac))
   log('Local MAC address ' + str(local_mac))
   log('Log file: ' + str(log_file))
   log('Log dir: ' + log_dir)
   log('Network interface: ' + iface)
   log('Pluto log file: ' + pluto_log_file)
   for item, weight in prob_list:
      log('Fuzzing ' + item + ' probability ' + str(weight))

   start_fuzzer()



def print_usage():
   print sys.argv[0], '--sut-ip (-i) <ip> --local-mac <mac> --sut-mac <mac> --log (-l) <log file> --fuzz-mode (-f) --iface (-e) <net interface> --pluto-log (-p) <pluto log file> --type (-t) <{field|payload|packet}>'



#------------------------------------------------------------
# The functions below fuzz fields
#------------------------------------------------------------

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,100))

def spec_ByteNulls(n):
   return b'\x00'*n


def init_cookie_fuzz():
   choice = weighted_choice([('allZero', 0.3), ('rand', 0.7)])
   if choice == 'allZero':
      retVal = spec_ByteNulls(8)
   elif choice == 'rand':
      retVal = os.urandom(8)
   return retVal

def rand_IntEnumField():
   return random.randint(0,100)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)


def rand_IntField():
   return random.randint(0,5000)

#------------------------------------------------------------
# The functions below fuzz payloads
#------------------------------------------------------------

def fuzz_SA(payload):
   log('fuzz SA')
   pd = random.choice([ISAKMP_payload_SA, ISAKMP_payload_Proposal, ISAKMP_payload_Transform])
   length = len(payload)
   if pd == ISAKMP_payload_SA:
      field = random.choice(['next_payload', 'length', 'DOI', 'situation'])
      log('Fuzzing field: ' + field)
      if field == 'next_payload':
         payload.next_payload = rand_ByteEnumField()
      elif field == 'length':
         payload.length = rand_FieldLenField()
      elif field == 'DOI':
         payload.DOI = rand_IntEnumField()
      elif field == 'situation':
         payload.situation = rand_IntEnumField()
      else:
         log('Error')
      if field != 'length':
         payload.length += ( len(payload) - length )
   elif pd == ISAKMP_payload_Proposal:
      fuzz_Proposal(payload)
   elif pd == ISAKMP_payload_Transform:
      fuzz_Transform(payload)
   else:
      log('Error')
      sys.exit(0)

def fuzz_KE(payload):
   log('fuzz KE')
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_ID(payload):
   log('fuzz ID')
   field = weighted_choice([('next_payload', 0.1), ('length', 0.1), ('IDtype',0.1), ('ProtoID', 0.1), ('Port', 0.1), ('load',0.5)])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'IDtype':
      payload.IDtype = rand_ByteEnumField()
   elif field == 'ProtoID':
      payload.ProtoID = rand_ByteEnumField()
   elif field == 'Port':
      payload.Port = rand_ShortEnumField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Hash(payload):
   log('fuzz Hash')
   length = len(payload)
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_VendorID(payload):
   log('fuzz VendorID')
   #field = random.choice(['next_payload', 'length', 'vendorID'])
   field = random.choice(['next_payload', 'length']) #todo check if we can re-enable vendorID (the call of rand_StrLenField didn't work very well)
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'vendorID':
      payload.vendorID = rand_StrLenField(payload.vendorID)
   else:
      log('Error')
      sys.exit(0)

def fuzz_Header(payload):
   log('fuzz Header')
   field = random.choice(['init_cookie', 'resp_cookie', 'next_payload', 'exch_type', 'flags', 'id', 'length'])
   # field = 'init_cookie' #config-fuzz-path



   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'init_cookie':
      # three operating mode options: fuzz the initcookie to 0000000000000000 (with certitude), to 8 random bytes, or a mixed probability of both
      payload.init_cookie = init_cookie_fuzz()
      #payload.init_cookie = os.urandom(8)  #this was the original call
      #payload.init_cookie = spec_ByteNulls(8)
   elif field == 'resp_cookie':
      payload.resp_cookie = os.urandom(8)
   elif field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'exch_type':
      payload.exch_type = rand_ByteEnumField()
   elif field == 'flags':
      if payload.flags == 0L:
         payload.flags = 1L
      else:
         payload.flags = 0L
   elif field == 'id':
     payload.id = rand_IntField()
   elif field == 'length':
     payload.length = rand_FieldLenField()
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_CERT(payload):
   log('fuzz CERT')
   fuzz_Payload(payload)


def fuzz_CR(payload):
   log('fuzz CR')
   fuzz_Payload(payload)


def fuzz_SIG(payload):
   log('fuzz SIG')
   fuzz_Payload(payload)


def fuzz_Proposal(payload):
   log(payload.command())
   log('fuzz Proposal')
   field = random.choice(['next_payload', 'length', 'proposal', 'proto', 'SPIsize', 'trans_nb'])#, 'SPI'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'proposal':
      payload.proposal = rand_ByteField()
   elif field == 'proto':
      payload.proto = rand_ByteEnumField()
   elif field == 'SPIsize':
      payload.SPIsize = rand_FieldLenField()
   elif field == 'trans_nb':
      payload.field = rand_ByteField()
   elif field == 'SPI':
      payload.SPI = rand_StrLenField(payload.SPI)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Payload(payload):
   log('fuzz Payload')
   length = len(payload)
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Transform(payload):
   log('fuzz Transform')
   num_transforms = 0
   cur_payload = payload
   length = len(payload)
   while cur_payload.next_payload != 0:
      num_transforms
      cur_payload = cur_payload.payload
   fuzz_transform = cur_payload
   for i in range(0,num_transforms-1):
      fuzz_transform = fuzz_transform.payload
   field = random.choice(['next_payload', 'length', 'num', 'id'])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'num':
      payload.num = rand_ByteField()
   elif field == 'id':
      payload.id = rand_ByteEnumField()
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )



#------------------------------------------------------------
# Map <payload id> <--> <function that fuzzes payload>
#------------------------------------------------------------
fuzz_func = {}
fuzz_func[1] = fuzz_SA
fuzz_func[4] = fuzz_KE
fuzz_func[5] = fuzz_ID
fuzz_func[6] = fuzz_CERT
fuzz_func[7] = fuzz_CR
fuzz_func[8] = fuzz_Hash
fuzz_func[9] = fuzz_SIG
fuzz_func[10] = fuzz_Proposal
fuzz_func[11] = fuzz_Payload
fuzz_func[13] = fuzz_VendorID
fuzz_func[-1] = fuzz_Header


if __name__ == '__main__':
   signal.signal(signal.SIGINT, signal_handler)
   main()
