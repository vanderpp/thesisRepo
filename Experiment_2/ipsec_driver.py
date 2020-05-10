#! /usr/bin/env python
import os
import time
import getopt
import sys
import signal

import subprocess



tmo = 10            #default timeout between actions
rng = 11            #default number of repetitions
bailout_count = 100    #counter indicating how many repetitions we had

#strCmd = 'time /T'

strCmd_start    = 'ipsec setup start'
strCmd_stop     = 'ipsec setup stop'
strCmd_status   = 'ipsec setup status'
strCmd_up       = 'ipsec setup status | grep "tunnels"'
confirm_mac     = 'arp -s 10.0.2.15 08:00:27:14:91:0f'

def makeStrCmd_cpPluto (n):
    strCmd_cpPluto  = 'cp /media/sf_Pluto_shared/pluto.log /media/sf_Pluto_shared/pluto' + str(n) + '.log' #for labo on MAC
    return strCmd_cpPluto

def check_tunnel_up():
    proc = subprocess.Popen(['ipsec setup status | grep "tunnels"'], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    vals = out.split(" ")
    if vals[0] == 'No':
        return 'NOK'
    else:
        return 'OK'

def command_sequence(ctr):
    #stop the opponent
    os.system(strCmd_stop)

    #confirm static mac entry
    os.system(confirm_mac)

    #save_logfile
    os.system(makeStrCmd_cpPluto(ctr))

    #wait 1 sec before restarting
    time.sleep(1)

    #start the opponent
    os.system(strCmd_start)

    #check if tunnel is up, if it is not, we will make the command sequence wait until it comes up.
    print ('[INFO]     waiting 3 sec before checking if tunnel is up...')
    time.sleep(3)
    up = check_tunnel_up()
    while up == 'NOK':
        print ('[FAIL]     tunnel was not up, waiting 3 sec before retry... start looping ')
        time.sleep(3)
        up = check_tunnel_up()
    print('[SUCCESS]  Tunnel up... end of this sequence')

def do_something_os():
    global repeat_count
    for i in range(0, rng+1):
        print( '[INFO]     ' +str(i) + '_th iteration')
        command_sequence(i)
        time.sleep(tmo)

def signal_handler(signal, frame):
   print('received stop signal... KILLING now')
   sys.exit(0)

def main():
    global rng, tmo

    opts, args = getopt.getopt(sys.argv[1:], 't:r:')

    for o, a in opts:
        print(o, a)
        if o == '-t':
            tmo = int(a)
        if o == '-r':
            rng = int(a)
    do_something_os()

if __name__ == '__main__':
   signal.signal(signal.SIGINT, signal_handler)
   main()

