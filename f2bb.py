#!/usr/bin/python
# -*- coding: utf-8 -*-


# F2BB Fail2Ban Broadcast
# (c) Thanat0s 2013
#
# Fail2Ban BroadCast is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban Broadcast is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban BroadCast; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import time,datetime,sys,re,socket,subprocess,traceback,argparse,shlex

try:
  import hashlib
except:
  print "Error: Need the following librarie: hashlib"
  print "Use your distrib packages or http://code.krypto.org/python/hashlib/"
  sys.exit()

try:
  import netifaces
except:
  print "Error: Need the following librarie : netifaces"
  print "Use your distrib packages or https://pypi.python.org/pypi/netifaces"
  sys.exit()

try:
  import ConfigParser
except:
  print "Error: Need the following librarie : ConfigParser"
  print "Use your distrib packages or http://wiki.python.org/moin/ConfigParser"
  sys.exit()

# Inifile location
INIFILE = "/etc/cfg-f2bb.conf"

# Don't touch it... if you don't know why
host = ''
delim = ";" 
version = '0.3.2'
header = "F2BB"
mdelay = 0.75  # maxtime of message in sec
verbose = False

# functions

# Sign message
def sign(msg,passwd):
  message = hashlib.sha1(hashlib.sha1(passwd).hexdigest()+hashlib.sha1(msg).hexdigest()).hexdigest()
  for i in range(1024):
        message = hashlib.sha1(message).hexdigest()
  return message

# Validate IP
def okip(param):
  try:
    socket.inet_aton(param)
    return True
  except socket.error:
    if ipv6:
      try:
        socket.inet_pton(socket.AF_INET6, param)
        return True
      except socket.error:
        return False
    return False

def okproto(param):
  if re.search(r'^(tcp|udp|icmp)$',param,re.I):
    return True
  else:
    return False

# Validate port xx , xx,xx or xx-xx
def okport(param):
  if re.search(r'^\d{1,5}[-:,]\d{1,5}$|^\d{1,5}(,\d{1,5}){0,}$',param):
    return True
  else:
    return False

def okstring(param):
  if re.search(r'^\S+$',param,re.I):
    return True
  else:
    return False

def okaction(param):
  if re.search(r'^(un)?ban+$',param,re.I):
    return True
  else:
    return False

def prtlog(arg):
  logc = log.replace('<timestamp>', datetime.datetime.utcnow().isoformat(' '))
  logc = logc.replace('<mode>',arg['mode'])
  logc = logc.replace('<ip_src>',arg['ip_src'])
  logc = logc.replace('<port>',arg['port'])
  logc = logc.replace('<protocol>',arg['protocol'])
  logc = logc.replace('<jail_name>',arg['jail_name'])
  logc = logc.replace('<client_name>',arg['client_name'])
  logc = logc.replace('<action>',arg['action'])
  logc = logc.replace('<ip_dst>',arg['ip_dst'])
  try: 
    with open(logfile,'a') as mylog:
      mylog.write(logc + '\n')
  except:
    dbgprint ("Write error logging event")

# Send program
def func_send(arg):

  # Validates parameters
  if ipv6 and ((arg.ip_src.find(':') >= 1) and (arg.ip_dst.find(':') == -1 )):
    enderror('Mixed IPv4 and IPv6')
  if ipv6 and ((arg.ip_src.find(':') == -1) and (arg.ip_dst.find(':') >= 1 )):
    enderror('Mixed IPv4 and IPv6')
  if (not ipv6) and ((arg.ip_src.find(':') >= 1) or (arg.ip_dst.find(':') >= 1) ):
    enderror('IPv6 Deactivated')
  
  if not okip(arg.ip_src):
    enderror('Invalid source ip')
  if not okport(arg.port):
    enderror('Invalid port')
  if not okproto(arg.protocol):
    enderror('Invalid protocol')
  if not okstring(arg.jail_name):
    enderror('Invalid jail')
  if not okstring(arg.client_name):
    enderror('Invalid client name')
  if not okaction(arg.action):
    enderror('Invalid action')
  if not okip(arg.ip_dst):
    enderror('Invalid destination ip')
  
  dbgprint ("All parameters correct...")
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  message = str(time.time())+delim+arg.ip_src+delim+arg.port+delim+arg.protocol+delim+arg.jail_name+delim+arg.client_name+delim+arg.action+delim+arg.ip_dst
  try:
    s.sendto(header+sign(message,password)+";"+message, (broadcast, port ))
    dbgprint ("Packet sent to " + broadcast + ':' + str(port))
    if int(logtype) & 1: 
      prtlog({'mode': 'client' , 'ip_src': arg.ip_src, 'port': arg.port, 'protocol': arg.protocol, 'jail_name': arg.jail_name, 'client_name': arg.client_name , 'action':arg.action, 'ip_dst': arg.ip_dst})
  except:
    dbgprint ("Error sending packet")
    traceback.print_exc()

def goodhash(lhash,lpayload,lpassword):
  if re.search(r'^[a-f0-9]{40}$',lhash,re.I): # Si len ok, lourde regex
    if sign(lpayload,lpassword) == lhash: # validate Hash
      return True
  else:
    return False

# Receive program
def func_recv(args):
  #print args.verbose
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  s.bind((host, port))

  dbgprint ("Daemon Started...")
  while True: # Endless Loop
    try:
      payload, address = s.recvfrom(8192)
      dbgprint ("Packet received")
      if payload[0:6] == header:  # si header valide
        dbgprint ("Packed header ok")
        vhash = payload[0+6:40+6]
        payload = ';'.join(payload.split(';')[1:])
        if goodhash(vhash,payload,password) == True:  # Verif signature
          dtick,ip_src,fport,proto,jail,client,action,ip_dst= payload.split(';')
          dtick = float(dtick)
          if (dtick > time.time()-mdelay) and (dtick < time.time()+mdelay): # Verif timestamp
            if okip(ip_src) and okport(fport) and okproto(proto) and okstring(jail) and okstring(client) and okaction(action) and okip(ip_dst):
              dbgprint (action + " from " + address[0] + " received" )
              if ipv6 and (ip_src.find(':') >= 1) and (ip_dst.find(':') >=1 ):
                if action.lower() == 'ban':
                  daction = action6_ban
                else:
                  daction = action6_uban
              else:
                if action.lower() == 'ban':
                  daction = action_ban
                else:
                  daction = action_uban
              daction = daction.replace('<ip_src>',ip_src)
              daction = daction.replace('<port>',fport)
              daction = daction.replace('<protocol>',proto)
              daction = daction.replace('<jail_name>',jail)
              daction = daction.replace('<client_name>',client)  #    Why used ??
              daction = daction.replace('<ip_dst>',ip_dst)
              dbgprint ("Executing :" + daction)
              try:
                rcode = subprocess.call(shlex.split(daction))   # Execute the action
                dbgprint ("Return code :" +str(rcode))
              except:
                dbgprint ("Error in execution")
              if int(logtype) & 2: 
                prtlog({'mode': 'daemon' , 'ip_src': ip_src, 'port': fport, 'protocol': proto, 'jail_name': jail, 'client_name': client , 'action':action, 'ip_dst': ip_dst})
            else:
              dbgprint("Invalid data")
          else:
            dbgprint("Invalid timestamp")
        else:
          dbgprint("Invalid packet signature")
      else:
        dbgprint ("Wrong packet header")
    except (KeyboardInterrupt, SystemExit):
      if verbose:
        raise
      else:
        sys.exit(0)
    except:
        traceback.print_exc()

def enderror(msg):
  print ('Error: %s') % ( msg)
  sys.exit(1)

def getparm(obj,section,oconf):
  try:
    tresult = obj.get(section,oconf)
    if (tresult[0] == '"') or (tresult[0] == "'"): # is it quoted ??
      tresult = re.search(r'^([\'\"])(.*)\1$',tresult) # Remove quotes, keep inside
      tresult = tresult.group(2)
  except:
    enderror('Invalid ' + oconf +' configuration')
  if (tresult.lower() == 'true'): # A magic true or false word ??
    tresult = True
    return tresult
  if (tresult.lower() == 'false'):
    tresult = False
  return tresult

def dbgprint(mystr):
  if verbose:
    print ("%s %s") % (datetime.datetime.utcnow().isoformat(' '),mystr)

def init():
  parser = argparse.ArgumentParser( description='F2BB v'+version+' (c) Thanatos 2013', usage='Broadcast Fail2Ban updates to a pool\n')
  parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode', dest='verbose')
  subparsers = parser.add_subparsers(help='sub-command help')
  
  parser_c = subparsers.add_parser('client', help='send a ban broadcast')
  parser_c.add_argument('-a','--action',required=True,  help='F2b action ban/unban')
  parser_c.add_argument('-s','--ip_src', required=True, help='source ip to block')
  parser_c.add_argument('-o','--port', required=True, help='destination port to block')
  parser_c.add_argument('-p','--protocol', required=True, help='protocol used')
  parser_c.add_argument('-j','--jail_name',  required=True, help='Jail name')
  parser_c.add_argument('-c','--client_name',required=True,  help='client name')
  parser_c.add_argument('-d','--ip_dst', required=True, help='destination ip')
  parser_c.set_defaults(func=func_send)

  parser_d = subparsers.add_parser('daemon',help='start the daemon mode' )
  parser_d.set_defaults(func=func_recv)

  args = parser.parse_args()
  argsdict = vars(args)
  if argsdict['verbose']:
    global verbose
    verbose = True

  global header,port,password,broadcast,action_ban,action_uban,log,logtype,logfile,ipv6,action6_ban,action6_uban
  vmaj,vmin,vsub = version.split('.')
  header = header + chr(int(vmaj)) + chr(int(vmin))

  # Read config File
  CONFIG = ConfigParser.ConfigParser()
  CONFIG.sections()
  CONFIG.read(INIFILE)
  section = 'DEFAULT'
  try:
    port = int(getparm(CONFIG,section,'port'))
  except:
    enderror('Invalid port configuration')
  broadcast = getparm(CONFIG,section,'broadcast')
  password = getparm(CONFIG,section,'password')
  action_ban =  getparm(CONFIG,section,'action_ban')
  action_uban = getparm(CONFIG,section,'action_uban')

  # IPv6 Processing
  ipv6 = getparm(CONFIG,section,'ipv6')
  if ipv6:
    action6_ban = getparm(CONFIG,section,'action6_ban')
    action6_uban = getparm(CONFIG,section,'action6_uban')

  log = getparm(CONFIG,section,'log')
  logfile = getparm(CONFIG,section,'logfile')
  logtype = getparm(CONFIG,section,'logtype')

  # Launche the right function
  args.func(args)

# Main programm
if __name__ == '__main__':
  init()
