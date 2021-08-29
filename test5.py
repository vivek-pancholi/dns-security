#!/usr/local/bin/python
"""Copyright (c) 2005 Scott Kitterman, spf2@kitterman.com
This module is free software, and you may redistribute it and/or modify
it under the same terms as Python itself, so long as this copyright message
and disclaimer are retained in their original form.

IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
THIS CODE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE.  THE CODE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS,
AND THERE IS NO OBLIGATION WHATSOEVER TO PROVIDE MAINTENANCE,
SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

For more information about SPF, a tool against email forgery, see
	http://www.openspf.org/"""

import re
import cgi
import cgitb; cgitb.enable()
import spf
import socket
RE_SPF = re.compile(r'^v=spf1$|^v=spf1 ',re.IGNORECASE)
res = False
exp = ""
ip = '1.1.1.1'
sender = False
helo = False
local = False
record = False
hrecord = False
form = cgi.FieldStorage()            # parse form data
print ("Content-type: text/html\r\n\r\n");
print ("")
print ("<p>Input accepted, querying now...<br><br>")
if form.has_key("ip"):
    ip = form["ip"].value
if form.has_key("mfrom"):
    sender = form["mfrom"].value
else:
    sender = 'example.com'
if form.has_key("helo"):
    helo = form["helo"].value
if form.has_key("record"):
    record = form["record"].value
    record = record.lower()
if form.has_key("hrecord"):
    hrecord = form["hrecord"].value
    hrecord = hrecord.lower()
if record:
    i = ip
    s = sender
    h = ip
    #print "Checking to see if the input SPF record starts with v=spf1. <br><br>"
    if RE_SPF.match(record):
        g = spf.query(i, s, h,local=None,receiver=None,strict=2)
        res, code, exp = g.check(record)
    else:
        res = "None"
        exp = "SPF records must start with 'v=spf1' please use the back button your browser and try the Mail From record again.<br><br>"
else:
    res, exp = spf.check2(ip, sender, helo)
print ("<br>")
print ("Mail sent from: ", ip, "<br>")
print ("Mail from (Sender): ", sender, "<br>")
if record:
    print ("Mail checked using this SPF policy: "), record
print ("<br>")
if not res:
    res = ['None', 'pySPF returned no result at all.  This is likely a pySPF bug.  Please contact us at <a href="mailto:spf2@kitterman.com">this address</a>.']
if res == 'temperror':
    print ("Results - TempError", exp, "</p>")
    print ("<p>If the error is 'syntax error', it may be either a problem with your SPF record or a problem with your input to the test tool.  Please do not enclose any of the inputs in quotation marks.</p>")
elif res == 'permerror':
    print ("Results - Permanent Error ", exp, "</p>")
elif res == 'pass':
    print ("Results - PASS", exp, "</p>")
elif res == 'fail':
    print ("Results - FAIL Message may be rejected</p>")
else:
    print ("Results - ", res, exp, "</p>")

if helo:
    hexp = ''
    if hrecord:
        i = ip
        s = helo
        h = ip
        print ("Checking to see if the input SPF record starts with v=spf1. <br><br>")
        if RE_SPF.match(hrecord):
            j = spf.query(i, s, h,local=None,receiver=None,strict=2)
            hres, hcode ,hexp = j.check(hrecord)
        else:
            hres = "None"
            hexp = "SPF records must start with 'v=spf1' please use the back button your browser and try the HELO record again.<br><br>"
    else:
        hres, hexp = spf.check2(ip, helo, helo)
    print ("<p><br>")
    print ("Mail sent from: ", ip, "<br>")
    print ("Mail Server HELO/EHLO identity: ", helo, "<br>")
    if hrecord:
        print ("HELO checked using this SPF policy: "), hrecord
    print ("<br>")
    if hres == 'temperror':
        print ("HELO/EHLO Results - ", hexp, "</p>")
        print ("<p>If the error is 'syntax error', it may be either a problem with your SPF record or a problem with your input to the test tool.  Please do not enclose any of the inputs in quotation marks.</p>")
    elif hres == 'permerror':
        print ("HELO/EHLO Results - Permanent Error ", hexp, "</p>")
    elif hres == 'pass':
        print ("HELO/EHLO Results - PASS", hexp, "</p>")
    elif hres == 'fail':
        print ("HELO/EHLO Results - FAIL Message may be rejected</p>")
    else:
        print ("HELO/EHLO Results - ", hres, hexp, "</p>")

tryagain = """<form method="get" action="http://www.kitterman.com/spf/validate.html">
<table border="0" width="460">
<tbody>
<tr>
<td> <input value="Return to SPF checking tool (clears form)" type="submit"></td>
</tr>
</tbody>
</table>
</form>"""
print (tryagain)
print ('<p>Use the back button on your browser to return to the SPF checking tool without clearing the form.</p></body></html>')

