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
	http://spf.pobox.com/"""
import cgi
import cgitb; cgitb.enable()
import spf
import socket
import DNS
import string

DNS.DiscoverNameServers()

form = cgi.FieldStorage()            # parse form data
formdomain = 'example.com'
print ("Content-type: text/html\r\n\r\n");
print ("")
print ("<p>Input accepted, querying now...<br>")

if form.has_key("domain"):
    formdomain = form["domain"].value
domaintuple = spf.split_email(formdomain, '')
domain = domaintuple[1]
if form.has_key("record"):
    record = form["record"].value
else:
    print ("No input found, please use the back button on your browser and try again.</p>")
    record = ''
if record[:7] != 'v=spf1 ' and record != 'v=spf1':
    print ("SPF records must start with v=spf1, this does not appear to be a valid SPF record.<br><br>")
    print ("Please use the back button on your browswer and try again.</p>")
    record = ""
if record:
    print ('evaluating ', record, '...<br>')
    if record.endswith('-all'):
        target = 'fail'
    elif record.endswith('~all'):
        target = 'softfail'
    elif record.endswith('?all'):
        target = 'neutral'
    elif record.endswith('all') or record.endswith('+all'):
        target = 'pass'
    else:
        target = 'neutral'
    i = '70.91.79.102'
    s = 'postmaster@' + domain
    h = domain
    g = spf.query(i, s, h,local=None,receiver=None,strict=2)
    q = g.check(record)
    if q[0] == target:
        print ('SPF record passed validation test with pySPF (Python SPF library)!</p>')
    elif q[0] == 'temperror':
        print ("Results - TempError", q[2], "</p>")
    elif q[0] == 'permerror':
        print ("Results - PermError", q[2], "</p>")
    elif target == 'redirected':
        print ("Results - Redirected to another SPF record.  Processed without error using pySPF (Python SPF library)!<br><br>")
        print ("The result of the test (this should be the default result of your record) was, ", q[0],".  The explanation returned was, ", q[2], "</p>")
    else:
        print ("Results - record processed without error.<br><br>")
        print ("The result of the test (this should be the default result of your record) was, ", q[0],".  The explanation returned was, ", q[2], "</p>")
else:
    print ("No valid SPF record identified</p>")
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
print ('<p>Use the back button on your browser to return to the SPF checking tool without clearing the form.</p>')
