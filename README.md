F2BB
====

<b>Fail2Ban Broadcast</b><br>

<b>A simple way for a Fail2ban protected server to tell others friends that this ip is really a bad guy for everyone !<br></b>

Consider the following networks designs with 3 servers:<br>

<pre><code>
[A]---+---[FW]-----(Internet)
      |
[B]---|    
      |
[C]---+
</code></pre>

<pre><code>
[A]---+
      |
[B]---+-----(Internet)
      |
[C]---+            
</code></pre>

You may want to apply a fail2ban ban action on the frontend firewall or even on a each server of a pool.<br>
F2BB will broadcast F2B updates to the network. Update are signed so only members of fail2ban domain will be updated.<br>
So if one server is attacked, everyone is blocking it<br>

On each blocking device use f2bb.py as a listen daemon which ban and unban.<br>
On each detecting device use f2bb.py as fail2ban action.<br>

Fail2Ban is available at: https://github.com/fail2ban/fail2ban or in your preferred distro<br>

<b>Todo:<br></b>
use fail2ban client natively to ban/uban<br>
ipv6 support<br>

<b>Features:<br></b>
fully customisable<br>
log event<br>
debug<br>

<b>Security remarks:<br></b>
You may not replay ban or unban broadcast they are timestamped. (Needs timed servers)<br> 
Remember:  Broadcasts don't pass routers<br>
Update message are send in clear (Who cares ?)<br>
Packed are signed with a hmac , 1024 sha1 are done to slow down bruteforce attempt<br>

Have Fun…
