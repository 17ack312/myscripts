
import json,re,datetime
import time,os,sys,requests

def byhost(file):
    data = open(file, 'r', encoding='utf-8').read()

    id=[]
    for i in data.replace('\n','').replace('<div class="clear"></div>','').replace('<li style="margin: 0 0 10px 0; color:','\n<li style="margin: 0 0 10px 0; color:').replace('</a></li>','</a></li>\n').split('\n'):
        if i.startswith('<li style="margin: 0 0 10px 0; color:') and not re.search('>Suggested Remediations<',i):
            id.append(i.split('href="#')[1].split('"')[0])

    data=data.replace('\n','').replace('<div class="clear"></div>','')
    for i in id:
        temp=('<div xmlns="" id="'+i+'"')
        data=data.replace(temp,'\n'+temp)

    host=[]
    data = data.split('\n')
    for i in data:
        x={}
        for j in (i.replace('<div xmlns="" class="details-header">Scan Information','\n<div xmlns="" class="details-header">Scan Information').replace('<div xmlns="" class="details-header">Host Information','\n<div xmlns="" class="details-header">Host Information').replace('<div xmlns="" class="details-header">Vulnerabilities','\n<div xmlns="" class="details-header">Vulnerabilities').split('\n')):
            if j.startswith('<div xmlns="" id="'):
                x['host']=str(j.split('">')[1].split('</div>')[0])

            if j.startswith('<div xmlns="" class="details-header">Host Information</div>'):
                for k in (j.replace('<tr class="">','\n<tr class="">').replace('</tr>','</tr>\n').split('\n')):
                    if k.startswith('<tr class="">'):
                        temp=(k.replace('<tr class="">','').replace('<td class="#ffffff" style="">','').replace('</td>','').replace('</tr>',''))
                        temp = temp.split(':', 1)
                        x[temp[0].replace(' ','_').lower()]=str(temp[1])

        if (len(x))>0:
            host.append(x)
    return host


def byplugin(file):
    data = open(file, 'r', encoding='utf-8').read()

    id=[]
    for i in data.replace('\n','').replace('<div class="clear"></div>','').replace('<li style="margin: 0 0 10px 0; color:','\n<li style="margin: 0 0 10px 0; color:').replace('</a></li>','</a></li>\n').split('\n'):
        if i.startswith('<li style="margin: 0 0 10px 0; color:') and not re.search('>Suggested Remediations<',i):
            id.append(i.split('href="#')[1].split('"')[0])

    data=data.replace('\n','').replace('<div class="clear"></div>','')
    for i in id:
        temp=('<div xmlns="" id="'+i+'"')
        data=data.replace(temp,'\n'+temp)

    vulnerability=[]
    data=data.split('\n')
    data.remove(data[0])
    for i in data:
        x={}
        for j in i.replace('<div class="details-header">','\n').split('\n'):
            if j.startswith('<div xmlns="" '):
                x['name']=str(j.split('"this.style.cursor=\'pointer\'">')[1].split('<div id="',1)[0].split(' - ',1)[1].removesuffix(' ').removesuffix(' '))

            if j.startswith('Synopsis</div>'):
                x['description']=str(j.removeprefix('Synopsis</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>').replace('<br>',';'))

            if j.startswith('Description</div>'):
                x['impact']=str(j.removeprefix('Description</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>').replace('<br>',';'))

            if j.startswith('Solution</div>'):
                x['solution']=str(j.removeprefix('Solution</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>').replace('<br>',';'))

            if j.startswith('Risk Factor</div>'):
                sev='Informational';val=0;sc=0.0;st=''
                base='cvss V3'
                risk=str(j.removeprefix('Risk Factor</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>').replace('<br>',';'))
                x['risk']=risk
                if risk=='None':
                    sev='Informational'
                    val=0
                    sc=0.0
                    st=''
                    base=''
                x['score']=sc
                x['string']=st
                x['severity']=sev
                x['value']=val
                x['base']='cvss V3'

            if re.search('CVSS v3.0 Base Score',i) and j.startswith('CVSS v3.0 Base Score</div>'):
                temp=(j.removeprefix('CVSS v3.0 Base Score</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>').replace('<br>',';')).split(' ',1)
                sc=float(temp[0])
                st=str(temp[1]).replace('(','').replace(')','')
                if 10.0 >= sc >= 9.0:
                    sev='Critical'
                    val=4
                elif 8.9 >= sc >= 7.0:
                    sev='High'
                    val=3
                elif 6.9 >= sc >= 4.0:
                    sev='Medium'
                    val=2
                elif 3.9 >= sc >= 0.1:
                    sev='Low'
                    val=1
                else:
                    sev='Informational'
                    val=0

                #print(sc,st,sev,val)
                x['score']=sc
                x['string']=st
                x['severity']=sev
                x['value']=val
                x['base']='cvss V3'

            if not re.search('CVSS v3.0 Base Score',i) and re.search('CVSS v2.0 Base Score</div>',i) and j.startswith('CVSS v2.0 Base Score</div>'):
                temp=(j.removeprefix('CVSS v2.0 Base Score</div><div style="line-height: 20px; padding: 0 0 20px 0;">').replace('</div>','').split(' ',1))
                sc=float(temp[0])
                st=str(temp[1]).replace('(','').replace(')','')

                if 10.0 >= sc >= 7.0:
                    sev='High'
                    val=3
                elif 6.9 >= sc >= 4.0:
                    sev='Medium'
                    val=2
                elif 3.9 >= sc >= 0.1:
                    sev='Low'
                    val=1
                else:
                    sev='Informational'
                    val=0

                #print(sc,st,sev,val)
                x['score']=sc
                x['string']=st
                x['severity']=sev
                x['value']=val
                x['base']='cvss V2'

            if j.startswith('Plugin Output</div>'):
                temp=[]
                for k in j.replace('<h2>','\n<h2>').replace('</h2>','</h2>\n').split('\n'):
                    if k.startswith('<h2>'):
                        temp.append(k.removeprefix('<h2>').removesuffix('</h2>').split(' ')[0])
                x['affected']=str(";".join(temp))

            if j.startswith('See Also</div>'):
                temp=[]
                for k in (j.replace('<a href=','\n<a href=').split('\n')):
                    if k.startswith('<a href='):
                        temp.append(k.split('=')[1].removeprefix('"').removesuffix('" target'))
                x['ref_link']=str(";".join(temp))

            if j.startswith('References</div>'):
                temp=[]
                for k in j.replace('<tr class="">','\n<tr class="">').replace('</tr>','</tr>\n').split('\n'):
                    if k.startswith('<tr class=""><td class="#ffffff" style="">'):
                        if re.search('CVE',(k.split('<td class="#ffffff" style="">')[-1])):
                            temp.append((k.split('<td class="#ffffff" style="">')[-1]).split('target="_blank">')[1].removesuffix('</a></td></tr>'))
                        if re.search('CWE',(k.split('<td class="#ffffff" style="">')[-1])):
                            temp.append((k.split('<td class="#ffffff" style="">')[-1]).split('target="_blank">')[1].removesuffix('</a></td></tr>'))
                x['classification']=str(";".join(temp))

        vulnerability.append(x)
        #time.sleep(3)
    return vulnerability


def createHTML(ip_details,vuln_details,name,out_path):
    f=open(out_path,'w')
    style = requests.get('https://raw.githubusercontent.com/17ack312/myscripts/main/style_report.css').content.decode()
    f.write('<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'+name+'</title><style>'+style+'</style><link rel="stylesheet" type="text/css" href="https://raw.githubusercontent.com/17ack312/myscripts/main/style_report.css"></head>\n')
    #"""
    f.write('<body>\n')
    f.write('<div class="ip_details" align="center">\n')

    count=1
    for i in ip_details:
        #f.write(i.keys())
        host=i['host']

        f.write('<table id="ip_details">\n')

        f.write('<h4> Host No.:&ensp;'+str(count)+'</h4>\n')

        f.write('<tr id="host">\n')
        f.write('<td id="point" colspan="2">HOST</td>\n')
        f.write('<td id="details" colspan="3">'+str(i['host'])+'</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="ip">\n')
        f.write('<td id="point" colspan="2">IP</td>\n')
        f.write('<td id="details" colspan="3">'+str(i['ip'])+'</td>\n')
        f.write('</tr>\n')

        try:
            dns=str(i['dns_name'])
            f.write('<tr id="dns">\n')
            f.write('<td id="point" colspan="2">DNS Name</td>\n')
            f.write('<td id="details" colspan="3">' + dns.upper() + '</td>\n')
            f.write('</tr>\n')
        except:
            pass

        try:
            net=str(i['netbios_name'])
            f.write('<tr id="netbios">\n')
            f.write('<td id="point" colspan="2">Net-BIOS Name</td>\n')
            f.write('<td id="details" colspan="3">' + net.upper() + '</td>\n')
            f.write('</tr>\n')
        except:
            pass

        try:
            mac=str(i['mac_address'])
            f.write('<tr id="mac">\n')
            f.write('<td id="point" colspan="2">MAC Address</td>\n')
            f.write('<td id="details" colspan="3">' + mac.replace(' ',', ') + '</td>\n')
            f.write('</tr>\n')
        except:
            pass

        try:
            OS=str(i['os'])
            f.write('<tr id="os">\n')
            f.write('<td id="point" colspan="2">Operating System</td>\n')
            f.write('<td id="details" colspan="3">' + OS.upper() + '</td>\n')
            f.write('</tr>\n')
        except:
            pass

        f.write('<br>\n')
        f.write('<tr class="vuln_list"><th>Sl</th><th>Severity</th><th>Vulnerability name</th><th>CVSS Score</th><th>CVSS Version</th></tr>\n')

        sl=1
        for j in vuln_details:
            #f.write(j.keys())
            if host in (j['affected']):
                f.write('<tr class="vuln_list">\n')

                f.write('<td id="sl">'+str(sl)+'</td>\n')
                f.write('<td id="risk_' + str(j['severity']).lower() + '">' + str(j['severity']) + '</td>\n')
                f.write('<td id="v_name"><a href="#'+str(j['name']).replace(' ','').lower()+'">'+str(j['name'])+'</a></td>\n')
                f.write('<td id="score">'+str(j['score'])+'</td>\n')
                f.write('<td id="version">'+str(j['base'])+'</td>\n')

                f.write('</tr>\n')
                sl+=1

        f.write('</table>\n')
        f.write('<h1 id="pagebreak"> </h1>\n')
        f.write('<!========================================================================-->\n')

        count+=1
    f.write('</div>\n')
    f.write('<h1 id="pagebreak"> </h1>\n')
    f.write('<!========================================================================-->\n')
    #"""

    f.write("<p>Detailed Information:<p>\n")
    count=1
    for i in vuln_details:
        #f.write(i.keys())
        #f.write(i)
        f.write('<div class="'+str(i['severity']).lower()+'" align="center">\n')
        f.write('<table class="vuln" id="'+str(i['name']).replace(' ','').lower()+'">\n')

        f.write('<tr id="vuln">\n')
        f.write('<td colspan=2>\n')
        f.write('<span id="sl">'+str(count)+'.</span>\n')
        f.write('<span id="point"><span id="name">Vulnerability Name:</span></span>\n')
        f.write('<span id="info"><span id="name">'+str(i['name']).upper()+'</span></span><br>\n')
        f.write('<span id="point"><span id="rate">Vulnerability Rating:</span></span>\n')
        f.write('<span id="info"><span id="rate">'+str(i['severity']).upper()+'</span></span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="classification">\n')
        f.write('<td colspan=2>\n')
        f.write('<span id="point">CVSS:</span>\n')
        f.write('<span id="info">'+str(i['score'])+' '+str(i['string'])+'</span>\n')
        try:
            for x in str(i['classification']).replace(';',', ').split(','):
                a=[]
                if str('CVE') in x:
                    f.write('<br>\n')
                    f.write('<span id="point">CVE:</span>\n')
                    f.write('<span id="info"><a target="_blank" href="https://nvd.nist.gov/vuln/detail/'+str(x)+'">'+str(x)+'</a></span>\n')
                b=[]
                if str('CWE') in x:
                    f.write('<br>\n')
                    f.write('<span id="point">CWE:</span>\n')
                    f.write('<span id="info"><a target="_blank" href="http://cwe.mitre.org/data/definitions/' + str(str(x).split(':')[1]) + '">' + str(x) + '</a></span>\n')
        except:
            pass
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="system">\n')
        f.write('<td colspan=2>\n')
        f.write('<span id="point"> Affected Systems:</span><br>\n')
        f.write('<span id="info">'+str(i['affected']).replace(';',', ')+'</span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="desc">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Vulnerability Description</span>\n')
        f.write('</td>\n')
        f.write('<td id="right">\n')
        f.write('<span id="info">'+str(i['description']).replace(';','<br>')+'</span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="imp">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Impact</span>\n')
        f.write('</td>\n')
        f.write('<td id="right">\n')
        f.write('<span id="info">'+str(i['impact']).replace(';','<br>')+'</span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="sol">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Remediation</span>')
        f.write('</td>')
        f.write('<td id="right">')
        f.write('<span id="info">'+str(i['solution']).replace(';','<br>')+'</span>')
        try:
            link=i['ref_link']
            f.write('<p id="reference"><span id="point">References:</span>\n')
            f.write('<ol>\n')
            for x in link.split(';'):
                f.write('<li><a href="'+str(x)+'">'+str(x)+'</a></li>\n')
            f.write('</ol></p>\n')
        except:
            pass
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="poc">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Proof of Concept</span>\n')
        f.write('</td>\n')
        f.write('<td id="right">\n')
        f.write('<span id="info"></span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')


        f.write('<tr id="auditee">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Auditee\'s Response</span>\n')
        f.write('</td>\n')
        f.write('<td id="right">\n')
        f.write('<span id="info"></span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="estimate">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Estimate Implementation Date</span>\n')
        f.write('</td>\n')
        f.write('<td id="right">\n')
        f.write('<span id="info"></span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="colsure">\n')
        f.write('<td id="left">\n')
        f.write('<span id="point">Closure Remark</span>\n')
        f.write('</td>\n')
        f.write('<td id="right">\n')
        f.write('<span id="info"></span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('<tr id="blank">\n')
        f.write('<td colspan=2>\n')
        f.write('<span id="info"></span>\n')
        f.write('</td>\n')
        f.write('</tr>\n')

        f.write('</table></div>\n')
        f.write('<h1 id="pagebreak"> </h1>\n')
        f.write('<!========================================================================-->\n')
        count+=1

    f.write('</body></html>\n')
    f.close()


name=input("Enter Project Name : ").replace(' ','_')

#file="C:/Users/Rajdeep Basu/Desktop/New/entire2_byhost.html"
file=input("[>] Path of file(By Host) : ").replace('\\','/').replace('"','').replace("'","")
ip_details=byhost(file)

#by_host(file)
#print(ip_details)

#file="C:/Users/Rajdeep Basu/Desktop/New/entire2_byplug.html"
file=input("[>] Path of file(By Plugin) : ").replace('\\','/').replace('"','').replace("'","")
vuln_details=byplugin(file)

scores=[]
for i in vuln_details:
    scores.append(i['score'])

scores=list(set(scores))
scores = sorted(scores, key=float,reverse=True)

vulnerability=[]
for i in scores:
    for j in vuln_details:
        if(j['score']==i):
            vulnerability.append(j)

x=file.split('/')
temp=x[-1]
x.remove(temp)
out_path=str("/".join(x))+'/'+name+'.html'


createHTML(ip_details,vulnerability,name,out_path)







