#!/usr/bin/python

#
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

import time,sys,re,socket,subprocess,traceback

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


# You may change this
port = 10666  # BroadCast Port
password = 'Mous3l_C@ntine!!' # The Best of Luxembourg !!!
broadcast = '192.168.1.127'  # BroadCast Address
action_ban = '/bin/echo iptables -I fail2ban-<jail_name> -s <ip> -p <protocol> -d <ip_dst> -m multiport --dports <port> -m comment --comment "<client_name>" -j CHAOS '
action_uban = '/bin/echo iptables -D fail2ban-<jail_name> -s <ip> -p <protocol> -d <ip_dst> -m multiport --dports <port> -m comment --comment "<client_name>" -j CHAOS'


# Don't touch it... if you don't know why
host = ''
delim = ";" 
version = '0.1'
header = "F2BB"
mdelay = 0.5  # maxtime of message in sec

# functions
def sign(msg,passwd):
  message = hashlib.sha1(hashlib.sha1(passwd).hexdigest()+hashlib.sha1(msg).hexdigest()).hexdigest()
  for i in range(1024):
        message = hashlib.sha1(message).hexdigest()
  return message

def okip(param):
  try:
    socket.inet_aton(param)
    return True
  except socket.error:
    return False

def okproto(param):
  if re.search(r'^(tcp|udp|icmp)$',param,re.I):
    return True
  else:
    return False

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

def func_help():
  print 'F2BB Fail2BanBroadcast v'+version,
  print ' - (c) Thanat0s 2013 - Use at your own risk' 
  print 'Usage '+sys.argv[0]+' -s src_ip port protocol jailname clientname action dst_ip'
  print 'Usage '+sys.argv[0]+' -d '
  print ' -s send a ban broadcast, -d start a listen daemon, -h help'

# Send program
def func_send():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  ip,fport,proto,jail,client,action,dip = sys.argv[2:]

  if okip(ip) and okport(fport) and okproto(proto) and okstring(jail) and okstring(client) and okaction(action) and okip(dip):
    message = str(time.time())+delim+ip+delim+fport+delim+proto+delim+jail+delim+client+delim+action+delim+dip
    try:
      s.sendto(header+sign(message,password)+";"+message, (broadcast, port ))
    except:
      traceback.print_exc()
  else:
    print "BullShit en Input"

def goodhash(lhash,lpayload,lpassword):
  if re.search(r'^[a-f0-9]{40}$',lhash,re.I): # Si len ok, lourde regex
    if sign(lpayload,lpassword) == lhash: # validate Hash
      return True
  else:
    return False


# Receive program
def func_recv():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  s.bind((host, port))

  print ("Daemon Started...")
  while 1: # Endless Loop
    try:
      payload, address = s.recvfrom(8192)
      if payload[0:6] == header:  # si header valide
        vhash = payload[0+6:40+6]
        payload = ';'.join(payload.split(';')[1:])
        if goodhash(vhash,payload,password) == True:  # Verif signature
          dtick,ip,fport,proto,jail,client,action,dip = payload.split(';')
          dtick = float(dtick)
          if (dtick > time.time()-mdelay) and (dtick < time.time()+mdelay): # Verif timestamp
            if okip(ip) and okport(fport) and okproto(proto) and okstring(jail) and okstring(client) and okaction(action) and okip(dip):
              print "Got valid data from: ", address[0],
              print "->" ,action, ip
              if action.lower() == 'ban':
                daction = action_ban
              else:
                daction = action_uban
              daction = daction.replace('<ip>',ip)
              daction = daction.replace('<port>',fport)
              daction = daction.replace('<protocol>',proto)
              daction = daction.replace('<jail_name>',jail)
              daction = daction.replace('<client_name>',client)  #    Why used ??
              daction = daction.replace('<ip_dst>',dip)
              subprocess.call(daction.split(' '))   # Execute the action
    except (KeyboardInterrupt, SystemExit):
      raise
    except:
      traceback.print_exc()

def init():
  global header
  vmaj,vmin = version.split('.')
  header = header + chr(int(vmaj)) + chr(int(vmin))

# Main programm
if __name__ == '__main__':
  init()
  if len(sys.argv) >= 2:
    if sys.argv[1] == '-h':
      func_help()
      sys.exit()
    elif (sys.argv[1] == '-s') and (len(sys.argv) == 9):
      func_send()
      sys.exit()
    elif sys.argv[1] == '-d':
      func_recv()
      sys.exit()
    else:
      print "Error: Parameters not recognized"
      func_help()
      sys.exit()
  else:
    func_help()
    print "Error: i love many parameters"
    sys.exit(1)

