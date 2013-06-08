F2BB
====

Fail2Ban Broadcast<br>

A simple way for a Fail2ban agent to tell others that this ip is a bad guy !<br>

Consider the following network design with 3 servers:<br>

<code>
[A]---+---[FW]-----(Internet)
      |
[B]---|    
      |
[C]---+
</code>

<code>
[A]---+
      |
[B]---+-----(Internet)            
      |
[B]---+            
</code>

You may want to apply a fail2ban ban action on the frontend firewall or even on a each server of a pool.
F2BB will broadcast F2B updates to the network. Update are signed so only members of fail2ban domain will be updated

on each device f2bb.py as a listen daemon which ban and unban
on each device use f2bb.py as fail2ban action


Todo:
client configuration in file
use fail2ban client natively
ipv6 support
timestamp update to avoid replay


Security remarks : 
You may replay any of ban or unban broadcast. but broadcast don't pass routers
Update message are send in clear (Who cares)
Packed are signed with a hmac , 1024 sha1 are done to slow down bruteforce attempt



