#! /usr/bin/env python
import datetime
import getopt
import signal
import sys
import time
import os
import psutil
import shutil
from datetime import datetime

class runConf:
    class static:
        # static Agent Config Parameters

        procSearchName = 'pluto'                                           #psn
        procSearchCommand = '/pluto'
        sleepTimeout = 5                                                    #t
        plutoLogPath = '/media/sf_Right_shared/'                            #plp
        plutoLogFile = 'pluto.log'                                          #plf
        crashReporterLog = '/media/sf_Right_shared/crashReporter.log'       #crl
        printTerm = True                                                    #pt
        matchType = ''
        operatingmode = ''

        def set_matchType(self, value):
            if value not in ('looseMatch', 'exactMatch'):
                crashReporter_log(2,'Unknown matchtype for watched process name... defaulting to looseMatch','runConf')
                runConf.static.matchType = 'looseMatch'
            else:
                runConf.static.matchType = value

        def set_operatingmode(self, value):
            if value not in ('command', 'name'):
                crashReporter_log(2,'Unknown operatingmode for watched process... defaulting to name','runConf')
                runConf.static.operatingmode = 'name'
            else:
                runConf.static.operatingmode = value

    class dynamic:
        # to keep for next server loop
        previousProcessList = []

        # to reset after each loop
        newPidFound = False
        oldPidDisapeared = False
        newPidProcessList = []
        oldPidDisapearedList = []

        def resetDynamic(self):
            runConf.dynamic.newPidFound = False
            runConf.dynamic.oldPidDisapeared = False
            runConf.dynamic.newPidProcessList = []
            runConf.dynamic.oldPidDisapearedList = []

def crashReporter_log(severity, text, source):
    readableTimeStamp = datetime.now().strftime('%Y %m %d %H:%M:%S')
    msg = ''
    # 1 info
    # 2 warning
    # 3 crash
    if severity == 1:
        msg += '[INFO]     '
    elif severity == 2:
        msg += '[WARNING]  '
    elif severity == 3:
        msg += '[ERROR]    '
    msg += ' '
    msg += readableTimeStamp
    msg += ' '
    msg += text
    #msg += '\t\t\t(source: ' + source + ')' + '\n'
    msg += '\n'

    fileWriter = open(runConf.static.crashReporterLog, "a+")
    fileWriter.write(msg)
    fileWriter.close()

    if runConf.static.printTerm:
        print(msg)

def str2bool(v):
    #https: // stackoverflow.com / questions / 15008758 / parsing - boolean - values -with-argparse
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        return False

def findProcessIdByName(processName):
    # PVDP : borrowed this one from the internet
    '''
    Get a list of all the PIDs of a all the running process whose name contains
    the given string processName
    '''

    listOfProcessObjects = []

    # Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time', 'cmdline'])
            # Check if process name contains the given name string.
            if  (runConf.static.matchType == 'looseMatch') and (processName.lower() in pinfo['name'].lower()):
                listOfProcessObjects.append(pinfo)
            elif (runConf.static.matchType == 'exactMatch') and (processName.lower() == pinfo['name'].lower()):
                listOfProcessObjects.append(pinfo)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return listOfProcessObjects;

def findProcessIdByCommand(processCommand):
    # PVDP : borrowed this one from the internet
    '''
    Get a list of all the PIDs of a all the running process whose command contains
    the given string processCommand
    '''

    listOfProcessObjects = []

    # Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time', 'cmdline'])
            # Check if process cmd contains the given cmd string.
            if pinfo['cmdline'] != None and pinfo['cmdline'] != []:
                #if pinfo['cmdline'].__contains__(processCommand):
                #    listOfProcessObjects.append(pinfo)
                if processCommand in pinfo['cmdline'][0]:
                    listOfProcessObjects.append(pinfo)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return listOfProcessObjects;

def pp_prepare_processList(listOfProcessIds):
    if len(listOfProcessIds) > 0:
        result = ''
        for elem in listOfProcessIds:
            processID = elem['pid']
            processName = elem['name']
            processCreationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(elem['create_time']))
            processCmd = elem['cmdline'][0]
            result += '\t\t\t( ' + str(processID) + ', ' + processName + ', ' + processCreationTime + ', ' + str(processCmd) + ')\n'
        return result
    else:
        return 'List contained no processes'

def pp_processList(listOfProcessIds):
    print(pp_prepare_processList(listOfProcessIds))

def init_previousProcessList():
    global runConf
    if runConf.static.operatingmode == 'name':
        runConf.dynamic.previousProcessList = list(findProcessIdByName(runConf.static.procSearchName))
    elif runConf.static.operatingmode == 'command':
        runConf.dynamic.previousProcessList = list(findProcessIdByCommand(runConf.static.procSearchCommand))


def dutSafeguard():
    global runConf
    # we want to:

    # 1) report the crash with a timestamp
    readableTimeStamp = datetime.now().strftime('%Y %m %d %H:%M:%S')

    if runConf.static.operatingmode == 'name':
        term = runConf.static.procSearchName
    elif runConf.static.operatingmode == 'command':
        term = runConf.static.procSearchCommand
    term
    reportMsg = 'Detected crash of: ' + term + ' I Will safeguard the logfile.'
    crashReporter_log(3, reportMsg, 'dutSafeguard')

    # 2) safeguard the logfile

    srcLogFile = os.path.join(runConf.static.plutoLogPath, runConf.static.plutoLogFile)
    timeSuffix = datetime.now().strftime('%Y%m%d_%H-%M-%S')
    if os.path.exists(srcLogFile):
        dstLogFileName = 'SAFEGUARD_' + timeSuffix + runConf.static.plutoLogFile
        dstLogFile = os.path.join(runConf.static.plutoLogPath, dstLogFileName)
        shutil.copy(srcLogFile, dstLogFile)
        crashReporter_log(1,'logfile copied','dutSafeguard')
    else:
        crashReporter_log(3,'logfile did not exist','dutSafeguard')



def server_iter():
        global runConf

        #waiting n seconds... to avoid re-checking too often. should be smaller than te smallest time needed to restart the process
        print("Sleeping " + str(runConf.static.sleepTimeout) + " seconds...")
        time.sleep(runConf.static.sleepTimeout)


        #current iter
        #currentProcessList = findProcessIdByName(runConf.static.procSearchName) # OLD

        if runConf.static.operatingmode == 'name':
            currentProcessList = list(findProcessIdByName(runConf.static.procSearchName))
        elif runConf.static.operatingmode == 'command':
            currentProcessList = list(findProcessIdByCommand(runConf.static.procSearchCommand))

        #search for new PID (determine if the current list contains a PID not present in the previous)
        for proc in currentProcessList:
            if not(proc['pid'] in list(map(lambda x: x['pid'], runConf.dynamic.previousProcessList))):
                runConf.dynamic.newPidFound = True
                runConf.dynamic.newPidProcessList.append(proc)

        #search for disapeared PID
        for proc in runConf.dynamic.previousProcessList:
            if not(proc['pid'] in list(map(lambda x: x['pid'], currentProcessList))):
                runConf.dynamic.oldPidDisapeared = True
                runConf.dynamic.oldPidDisapearedList.append(proc)


        #prepare for next iteration: copy the current to the previous
        runConf.dynamic.previousProcessList = currentProcessList.copy()

        #if the supervised process crashed, perform safeguarding actions
        if runConf.dynamic.oldPidDisapeared:
            dutSafeguard()

        wrapUp()
        runConf.dynamic.resetDynamic(runConf.dynamic)

def wrapUp():
    global runConf

    if runConf.dynamic.newPidFound:
        crashReporter_log(1,"At least one new PID was found", 'wrapUp')
        crashReporter_log(1, '\n' + pp_prepare_processList(runConf.dynamic.newPidProcessList),'wrapUp')

    if runConf.dynamic.oldPidDisapeared:
        crashReporter_log(3,"At least one old PID disapeared", 'wrapUp')
        crashReporter_log(1, '\n' + pp_prepare_processList(runConf.dynamic.oldPidDisapearedList),'wrapUp')

def server_loop():
    while True:
        server_iter()

def start_server():
    global runConf
    crashReporter_log(1, 'crashreporter v0.1 started', 'main')

    # init runConf class
    init_previousProcessList()

    # start the server loop
    server_loop()

def main():
    global runConf
    #runConf.static.set_operatingmode(runConf.static, 'command')
    runConf.static.set_operatingmode(runConf.static, 'name')
    runConf.static.set_matchType(runConf.static, 'exactMatch') #command mode excludes matchtypes

    opts, args = getopt.getopt(sys.argv[1:], 'n:t:p:f:l:p',['psn=','st=','plp=','plf=','crl=','pt='])

    for o, a in opts:
        print(o, a)
        if o in ('-n','--psn'):
            runConf.static.procSearchName = a
        if o in ('-t','--st'):
            runConf.static.sleepTimeout = int(a)
        if o in ('-p','--plp'):
            runConf.static.plutoLogPath = a
        if o in ('-f','--plf'):
            runConf.static.plutoLogFile = a
        if o in ('-l','--crl'):
            runConf.static.crashReporterLog = a
        if o in ('-p','--pt'):
            runConf.static.printTerm = str2bool(a)
    start_server()

# --psn bash --st 4 --plp /Users/pietvanderpaelt/Desktop --plf plutoDummy.log --crl /Users/pietvanderpaelt/Desktop/crashReporter.log --pt True

def signal_handler(signal, frame):
    crashReporter_log(1, 'crashreporter v0.1 exit', 'main')
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()