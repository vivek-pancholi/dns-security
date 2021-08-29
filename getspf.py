#!/usr/local/bin/python
"""Copyright (c) 2005 Scott Kitterman, spf2@kitterman.com
Portions (from pySPF) Copyright (c) 2005 Stuart Gathman <stuart@bmsi.com>
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
if not hasattr(DNS.Type,'SPF'):
  # patch in type99 support
  DNS.Type.SPF = 99
  DNS.Type.typemap[99] = 'SPF'
  DNS.Lib.RRunpacker.getSPFdata = DNS.Lib.RRunpacker.getTXTdata
  #From pySPF
  
import string

def DNSLookup(name, qtype, strict=True):
    try:
        req = DNS.DnsRequest(name, qtype=qtype)
        resp = req.req()
	#resp.show()
        # key k: ('wayforward.net', 'A'), value v
	# FIXME: pydns returns AAAA RR as 16 byte binary string, but
	# A RR as dotted quad.  For consistency, this driver should
	# return both as binary string.
        return [((a['name'], a['typename']), a['data']) for a in resp.answers]
    except IOError, x:
        z =  'DNS IOError - ' + str(x)
        l = [('err',(z,),),]	
	return l
    except DNS.DNSError, x:
	z = 'DNS Error - ' + str(x)
        l = [('err',(z,),),]
	return l
    #from pySPF 108

def txtlookup(name):
    """
    convenience routine for doing an TXT lookup of a name. returns a
    list of TXT records.
    """
    #largely dervative of the MX lookup routine in pyDNS lazy
    # Homepage: http://pydns.sourceforge.net
    # This code is covered by the standard Python License.
    a = DNS.DnsRequest(name, qtype = 'txt').req().answers
    l = map(lambda x:x['data'], a)
    return l

def spflookup(name):
    """
    convenience routine for doing an SPF lookup of a name. returns a
    list of SPF records.
    """
    l = DNSLookup(name, qtype = 'SPF')
    b = []
    if l:
        a = l[0]
        b = [a[1],]
    return b

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
txtanswer = txtlookup(domain)
spfanswer = spflookup(domain)
if txtanswer:
    text = ""
    num = len(txtanswer)
    x = 0
    while x < num:
        txt_record = txtanswer[x]
        text += txt_record[0] + "<br>"
        x += 1
    print ('<br>')
    print ('SPF records are primarily published in DNS as TXT records.  The TXT \
    records found for your domain are:<br>')
    print ('<br>', text, '<br><br>')
#    if num > 1:
#        print '<br>PermError - Multiple SPF records found in type TXT <br><br>'
#        txtanswer = None
#        spfanswer = None
else:
    print ('SPF records are published in DNS as TXT records.  No TXT records \
    found for your domain.</p>')
print ('SPF records should also be published in DNS as type SPF records.  \
    This is new and most implementations do not support it yet.<br>')
if spfanswer:
    spfr = ""
    num = len(spfanswer)
    x = 0
    while x < num:
        spf_record = spfanswer[x]
        spfr += spf_record[0] + "<br>"
        x += 1
    print ('Type SPF records found for the domain are:<br>')
    print ('<br>', spfr, '<br><br>')
    if num > 1:
        print ('<br>PermError - Multiple SPF records found in type SPF')
        txtanswer = None
        spfanswer = None
else:
    print ('No type SPF records found.<br><br>')
if spfanswer or txtanswer:
    answer = ''
    print ("Checking to see if there is a valid SPF record. <br><br>")
    q = spf.query(i='127.0.0.1', s='localhost', h='unknown',
			    receiver=socket.gethostname(), strict='2')
    try:
        answer = q.dns_spf(domain)
    except spf.PermError,x:
        print ("Results - Permanent Error ", x.msg, '</p>')
    except spf.TempError,x:
        print ("Results - Temporary Error ", x.msg, '</p>')
        answer = ''
    if answer:
        print ('Found v=spf1 record for', domain, '<br>', answer, ' <br><br>\
        evaluating...<br>')
        if answer.endswith('-all'):
            target = 'fail'
        elif answer.endswith('~all'):
            target = 'softfail'
        elif answer.endswith('?all'):
            target = 'neutral'
        elif answer.endswith('all') or answer.endswith('+all'):
            target = 'pass'
        elif "redirect" in answer:
            target = 'redirected'
        else:
            target = 'neutral'
        ip = '192.111.219.0'
        helo = domain
        res, exp = spf.check2(ip, domain, helo)
        if res == target:
            print ('SPF record passed validation test with pySPF (Python SPF \
            library)!</p>')
        elif res == 'temperror':
            print ("Results - TempError", exp, "</p>")
        elif res == 'permerror':
            print ("Results - PermError", exp, "</p>")
        elif target == 'redirected':
            print ("Results - Redirected to another SPF record.  Processed \
            without error using pySPF (Python SPF library)!<br><br>")
            print ("The result of the test (this should be the default result \
            of your record) was, ", res,".  The explanation returned was, ")
            print (exp, "</p>")
        else:
            print ("Results - record processed without error.<br><br>")
            print ("The result of the test (this should be the default result \
            of your record) was, ", res,".  The explanation returned was, ")
            print (exp, "</p>")
    else:
        print ("No valid SPF record found of either type TXT or type SPF.</p>")

#fix me --> Post method not allowed
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
