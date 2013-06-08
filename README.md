F2BB
====

<b>Fail2Ban Broadcast</b><br>

<b>A simple way for a Fail2ban protected server to tell others friend that this ip is really a bad guy !<br></b>

Consider the following network design with 3 servers:<br>

<code>
[A]---+---[FW]-----(Internet)<br>
      |<br>
[B]---|<br>    
      |<br>
[C]---+<br>
</code>

<code>
[A]---+<br>
      |<br>
[B]---+-----(Internet)<br>            
      |<br>
[B]---+<br>            
</code>

You may want to apply a fail2ban ban action on the frontend firewall or even on a each server of a pool.<br>
F2BB will broadcast F2B updates to the network. Update are signed so only members of fail2ban domain will be updated.<br>

On each blocking device use f2bb.py as a listen daemon which ban and unban.<br>
On each detecting device use f2bb.py as fail2ban action.<br>

Fail2Ban is available at: https://github.com/fail2ban/fail2ban<br>

Todo:<br>
client configuration in a file<br>
use fail2ban client natively to ban/uban<br>
Log events<br>
ipv6 support<br>
timestamp update to avoid replay<br>


Security remarks:<br> 
You may replay any of ban or unban broadcast. but broadcast don't pass routers<br>
Update message are send in clear (Who cares)<br>
Packed are signed with a hmac , 1024 sha1 are done to slow down bruteforce attempt<br>

Have Fun
