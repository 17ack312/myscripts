def test_initiate(secret,py):
    #print(secret)
    url='https://raw.githubusercontent.com/17ack312/myscripts/main/hex_decrypt.py'
    time_now=(str(datetime.datetime.now()).split(' ')[1].split('.')[0].replace(':', '') + '.py')
    f=open(time_now, 'w')
    f.write(requests.get(url).text.replace('#$#$',secret))
    f.close()
    temp=(requests.get(subprocess.check_output(py+time_now).strip().decode()).text).split(',')
    f=open(time_now,'r')
    x=(f.read().replace(secret,str(temp[0])))
    f=open(time_now,'w')
    f.write(x)
    f.close()
    x=((requests.get(subprocess.check_output(py+time_now).strip().decode()).text).replace('#$#$',str(temp[1]))).replace('\n','')
    y=((requests.get(subprocess.check_output(py + time_now).strip().decode()).text).replace('#$#$',str(temp[2]))).replace('\n','')
    z=((requests.get(subprocess.check_output(py + time_now).strip().decode()).text).replace('#$#$',str(temp[3]))).replace('\n', '')
    os.remove(time_now)
    time_now=(str(datetime.datetime.now()).split(' ')[1].split('.')[0].replace(':', '') + '.py')
    f = open(time_now, 'w')
    f.write(x)
    f.close()
    x=(subprocess.check_output(py+time_now).strip().decode())
    f = open(time_now, 'w')
    f.write(y)
    f.close()
    y=(subprocess.check_output(py + time_now).strip().decode())
    f=open(time_now, 'w')
    f.write(z)
    f.close()
    z=(subprocess.check_output(py + time_now).strip().decode())
    os.remove(time_now)
    return (int(x)*int(y)-int(z))



def get_vname(line):
    x=0
    line=line.replace('<div class="details-header">','\n<div class="details-header">')
    for i in line.split('\n'):
        if i.startswith('<div xmlns=""') and re.search('onclick="toggleSection',i):
            for j in (i.replace('">','">\n').replace('</div>','\n</div>\n').replace('<div','\n<div')).split('\n'):
                if not (re.search('<div',j)) and not (re.search('</div>',j)) and (len(j)>0) and not (j.strip().startswith('-')):
                    #x=int(j.strip().split(' ')[1].removeprefix('(').removesuffix(')'))
                    line=(j.strip().split('-',1))
                    line=line[1].strip()
    vname.append(line.replace(',',';').strip())
    #print(line)

def get_desc(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Synopsis')):
            for j in i.replace('<div','\n<div').replace('div>','div>\n').split('\n'):
                if j.startswith('<div style="line-height: 20px; padding: 0 0 20px 0;">'):
                    line=(j.replace('<div style="line-height: 20px; padding: 0 0 20px 0;">','').replace('</div>',''))
    desc.append(line.replace(',',';').strip())
    #print(line)

def get_imp(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Description')):
            for j in i.replace('<div', '\n<div').replace('div>', 'div>\n').split('\n'):
                if j.startswith('<div style="line-height: 20px; padding: 0 0 20px 0;">'):
                    line=(j.replace('<div style="line-height: 20px; padding: 0 0 20px 0;">','').replace('</div>',''))
    impact.append(line.replace(',',';').strip())
    #print(line)

def get_remedy(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Solution')):
            for j in i.replace('<div', '\n<div').replace('div>', 'div>\n').split('\n'):
                if j.startswith('<div style="line-height: 20px; padding: 0 0 20px 0;">'):
                    line = (
                        j.replace('<div style="line-height: 20px; padding: 0 0 20px 0;">', '').replace('</div>', ''))
    remedy.append(line.replace(',', ';').strip())
    #print(line)

def get_cvss(line):
    cvss_e = " "
    cvss_st = " "
    cvss_sc =0.0
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">CVSS')) and (re.search('Base Score<',i)):
            if (i.startswith('<div class="details-header">CVSS v3.0 Base Score<')) and (re.search('\(CVSS:3.0/',i)):
                x=(i.removeprefix('<div class="details-header">CVSS v3.0 Base Score</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>'))
                cvss_e=(x.strip())
                x=x.split(' ',1)
                cvss_sc=float(x[0].strip())
                cvss_st=x[1].strip()
                #print(x)
                break
            elif (i.startswith('<div class="details-header">CVSS v2.0 Base Score<')) and (re.search('\(CVSS2#',i)) and not ((i.startswith('<div class="details-header">CVSS v3.0 Base Score<')) and (re.search('\(CVSS:3.0/',i))):
                x=(i.removeprefix('<div class="details-header">CVSS v2.0 Base Score</div><div style="line-height: 20px; padding: 0 0 20px 0;">').removesuffix('</div>'))
                cvss_e=(x.strip())
                x=x.split(' ',1)
                cvss_sc=float(x[0].strip())
                cvss_st=x[1].strip()
                #print(x)
                break
            else:
                cvss_e = " "
                cvss_st = " "
                cvss_sc = 0.0

    cvss.append(cvss_e)
    score.append(float(cvss_sc))
    check.append(float(cvss_sc))
    strng.append(cvss_st)
    #print(cvss_sc)
    #print(cvss_st)
    #print(cvss_e)


def get_link(line):
    temp=[]
    url=' '
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">See Also')):
            for j in i.replace('<','\n<').replace('>','>\n').split('\n'):
                if j.startswith('http'):
                    url=j
                    temp.append(url)

    line=(" ; ".join(temp))
    link.append(line)
    #print(line)

def get_cve(line):
    temp=[]
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">References')):
            for j in (i.replace('<td','\n<td').replace('</','\n</')).split('\n'):
                if (j.startswith('<td class="#ffffff" style=""><')) and (re.search('href="http',j)) and ((re.search('CVE',j)) or (re.search('CWE',j))):
                    temp.append(j.split('_blank">')[1])
    line = (" ; ".join(temp))
    cve.append(line)
    #print(line)

def get_sys(line):
    temp = []
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Plugin Output')):
            for j in (i.replace('<h2','\n<h2').replace('</h2>','</h2>\n').split('\n')):
                if(j.startswith('<h2')):
                    line=(j.removeprefix('<h2>').removesuffix('</h2>').split(' '))
                    ip=line[0]
                    #port=line[1].split('/')[1]
                    #line=ip+':'+port
                    temp.append(ip)
                    #print(line)

    temp=(np.unique(temp))
    line = (" ; ".join(temp))
    systems.append(line)
    #print(line)

def get_risk(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Risk Factor')):
            line=(i.replace('<div class="details-header">Risk Factor</div><div style="line-height: 20px; padding: 0 0 20px 0;">','').replace('</div>','').strip())
    risk.append(line)
    #print(line)

def get_sorted(cut_off,risk):
    for i in data:
        if(i.startswith(cut_off)):
            content.append(risk+i)


#===============================================================================================================================================================================================
#===========================================================================================================================================================================================================================
import sys,os
print("[?] Checking For Requirements...")
try:
    import json,re,datetime,time,requests,subprocess,glob,csv
    import numpy as np
    import pandas as pd
    from pyexcel.cookbook import merge_all_to_a_book # pyexcel pyexcel-xlsx
    print('[✔] Successful')
except:
    print("[!] Error(0xR)!!, Please Contact with Developer")
    print("[!] Name : Rajdeep Basu -> 17ack312@gmail.com")
    exit()

dist=(sys.platform)
flag=False
if 'win' in dist:
    command='py '
if 'linux' in dist:
    command='python3 '

print("[?] Authenticating...")
try:
    f=open('secret.txt','r')
    secret=f.read().replace('\n','')
    f.close()
    flag=test_initiate(secret,command)
except:
    secret=input("Enter Secret Key :")
    if len(secret):
        f=open('secret.txt','w')
        f.write(secret)
        f.close()
        flag=test_initiate(secret, command)
    else:
        print("[!] Error(0xA)!!, Please Contact with Developer'")
        print("[!] Name : Rajdeep Basu -> 17ack312@gmail.com")
        exit()

if not(flag):
    print("[!] Error(0xK)!!, Please Contact with Developer'")
    print("[!] Name : Rajdeep Basu -> 17ack312@gmail.com")
    exit()
else:
    print('[✔] Successful')



#now =str(datetime.datetime.now()).split('.',1)
#now=(now[0]).replace(' ','_').replace(':','').replace('-','')

file='E:/prime/VAPT/DFPCL/rajdeep/19_01/static_s0tc4l.html'.replace('\\','/')
loc=file.split('/')
loc=("/".join(loc[:-1])+'/')

file_name='DFPCL_STATIC'.lower()
#file_name=input('[?] Enter Project Name :').replace(' ','_')
out_csv=loc+file_name+'_.csv'
out_xlsx=loc+file_name+'_.xlsx'
out_html=loc+file_name+'_.html'
'''
name=loc[-1].split('.')
name=name[0]
out_csv=loc+name+'_.csv'
out_html=loc+name+'_.html'
'''

#============================================================================================================================================================================================================================================================
#                        C     S      V                       C       R      E     A     T     I     O     N
#============================================================================================================================================================================================================================================================

print('[?] Creating CSV : '+out_csv)
f=open(file,'r')
rem='''  html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, a, abbr, acronym, address, big, cite, code, del, dfn, em, img, ins, kbd, q, s, samp, small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, table, caption, tbody, tfoot, thead, tr, th, td, article, aside, canvas, details, embed, figure, figcaption, footer, header, hgroup, menu, nav, output, ruby, section, summary, time, mark, audio, video {
                        margin: 0;
                        padding: 0;
                        border: 0;
                        font-size: 100%;
                        font: inherit;
                        vertical-align: baseline;
                        -webkit-text-size-adjust: none;
                    }

                    html, body {
                        font-family: 'Helvetica Neue', 'Segoe UI', helvetica, arial, sans-serif;
                        width: 100%;
                        color: #333;
                        font-size: 13px;
                        background: #efefef;
                    }

                    a, a:visited, a:active {
                        color: #67ACE1;
                        text-decoration: none;
                    }

                    a:hover {
                        color: #67ACE1;
                        text-decoration: underline;
                    }

                    .clear {
                        clear: both;
                        width: 0 !important;
                        height: 0 !important;
                        margin: 0 !important;
                        padding: 0 !important;
                    }

                    table {
                        table-layout: fixed;
                        width: 100%;
                        border-collapse: collapse;
                        border-spacing: 0;
                        margin-bottom: 20px;
                        margin-top: 20px;
                    }

                    .plugin-row-header {
                        height: 35px;
                        line-height: 35px;
                        background: #f5f5f5;
                        font-size: 12px;
                        border: 1px solid #ddd;
                    }

                    .plugin-row {
                        height: 40px;
                        border: 1px solid #ddd;
                    }

                    .plugin-row td {
                        padding: 10px 0;
                        line-height: 20px;
                    }

                    .table-wrapper.details,
                    .table-wrapper.see-also {
                        margin: 0 0 20px 0;
                    }

                    .table-wrapper.details > table > tbody > tr > td {
                        padding: 5px 0;
                    }

                    .button {
                        display: block;
                        float: left;
                        line-height: 30px;
                        background: #eee;
                        border-radius: 3px;
                        cursor: pointer;
                        padding: 0 15px;
                    }

                    .button:hover {
                        background: #ccc;
                    }

                    .expand {
                        display: block;
                        float:right;
                        font-size: 12px;
                        color: #67ACE1;
                        cursor: pointer;
                        font-weight: normal;
                        line-height: 20px;
                        margin: 0 0 0 10px;
                    }

                    .expand:hover {
                        text-decoration: underline;
                    }

                    .expand-spacer {
                        display: block;
                        float:right;
                        font-size: 12px;
                        font-weight: normal;
                        line-height: 20px;
                        margin: 0 0 0 10px;
                    }

                    .details-header {
                        font-size: 14px;
                        font-weight: bold;
                        padding: 0 0 5px 0;
                        margin: 0 0 5px 0;
                        border-bottom: 1px dotted #ccc;
                    }

                    .offline {
                        background-image: -webkit-repeating-linear-gradient(135deg, transparent, transparent 5px, rgba(255, 255, 255, .2) 5px, rgba(255, 255, 255, .2) 10px) !important;
                        background-image: repeating-linear-gradient(135deg, transparent, transparent 5px, rgba(255, 255, 255, .2) 5px, rgba(255, 255, 255, .2) 10px) !important;
                    }

                    .acas-header {
                        padding: 0 10px;
                    }

                    .acas-header,
                    .acas-footer > h1 {
                        color: #fff;
                        font-weight: bold;
                        font-size: 15px;
                        text-align: center;
                    }

                    .table-desc > h5 {
                        color: #000;
                        text-align: left;
                        padding: 3px;
                        font-size: 14px;
                        font-weight: 200;
                        letter-spacing: 1px;
                        padding-top: 15px;
                        padding-bottom: 15px;
                    }

                </style><script type="text/javascript">
                        var toggle = function (id) {
                            var div = document.getElementById(id);
                            var button = document.getElementById(id + '-show');

                            if (!div || !button) {
                                return;
                            }

                            if (div.style.display === '' || div.style.display === 'block') {
                                button.style.display = 'block';
                                div.style.display = 'none';
                                adjustWatermark();
                                return;
                            }

                            button.style.display = 'none';
                            div.style.display = 'block';

                            adjustWatermark();
                        };

                        var toggleAll = function (hide) {
                            if (document.querySelectorAll('div.section-wrapper').length) {
                                toggleAllSection(hide);
                                adjustWatermark();
                                return;
                            }

                            var divs = document.querySelectorAll('div.table-wrapper');

                            for (var i = 0, il = divs.length; i < il; i++) {
                                var id = divs[i].getAttribute('id');
                                var div = document.getElementById(id);
                                var button = document.getElementById(id + '-show');

                                if (div && button) {
                                    if (hide) {
                                        button.style.display = 'block';
                                        div.style.display = 'none';
                                        adjustWatermark();
                                        continue;
                                    }

                                    button.style.display = 'none';
                                    div.style.display = 'block';
                                }
                            }
                            adjustWatermark();
                        };

                        var toggleSection = function (id) {
                            var div = document.getElementById(id);
                            var toggleText = document.getElementById(id.split('-')[0] + '-toggletext');

                            if (!div) {
                                return;
                            }

                            if (div.style.display !== 'none') {
                                toggleText.innerText = '+';
                                div.style.display = 'none';
                                adjustWatermark();
                                return;
                            }

                            toggleText.innerText = '-';
                            div.style.display = 'block';

                            adjustWatermark();
                        };

                        var toggleAllSection = function (hide) {
                            var divs = document.querySelectorAll('div.section-wrapper');

                            for (var i = 0, il = divs.length; i < il; i++) {
                                var id = divs[i].getAttribute('id');
                                var div = document.getElementById(id);
                                var toggleText = document.getElementById(id.split('-')[0] + '-toggletext');

                                if (div) {
                                    if (hide) {
                                        toggleText.innerText = '+';
                                        div.style.display = 'none';
                                        continue;
                                    }

                                    toggleText.innerText = '-';
                                    div.style.display = 'block';
                                }
                            }
                            adjustWatermark();
                        };

                        var adjustWatermark = function () {
                          if (document.getElementById('nessus-watermark')) {
                            let el = document.getElementById('nessus-watermark');
                            let body = document.body;
                            let html = document.documentElement;
                            let height = Math.max( body.scrollHeight, body.offsetHeight,
                                html.clientHeight, html.scrollHeight, html.offsetHeight );
                            el.setAttribute('height', body.offsetHeight);
                          }
                        };'''

data=(f.read().replace(rem,''))

#print(data[:200000])
temp=[]
for i in data.split('\n'):
    if not (i.startswith('<html xmlns=')) and not (re.search('</script>',i)) and not (i.startswith('<ul xmlns=')) and not (i.startswith('<li style="font-size: 14px;">')) and not (re.search('>Vulnerabilities by Plugin<',i)) and not (re.search(">Compliance '",i)) and not (re.search('>Remediations<',i)) and not (i.startswith('<h6 xmlns=')) and not (i.startswith('</li>')) and not (i.startswith('</h6>')) and not (i.startswith('</ul>')) and not (i.startswith('<table')) and not (i.startswith('<thead')) and not (i.startswith('<tbody')) and not (i.startswith('</table>')) and not (i.startswith('</tbody>')) and not (i.startswith('</thead>')) and not (i.startswith('<div xmlns="" id="') and i.endswith('class="section-wrapper">')):
        temp.append(i)
data=("".join(temp).replace('<div class="clear"></div>','').replace('<div xmlns="" id="','\n<div xmlns="" id="').replace(',',';'))
data=(data.replace(',',';').split('\n'))

#print(data)

length=len(data)
total=(length-2)
i=1

vname=[]
risk=[]
cvss=[]
score=[]
strng=[]
check=[]
systems=[]
desc=[]
impact=[]
remedy=[]
cve=[]
link=[]

while i<=total:
    get_vname(data[i])
    get_risk(data[i])
    get_cvss(data[i])
    get_sys(data[i])
    get_desc(data[i])
    get_imp(data[i])
    get_remedy(data[i])
    get_cve(data[i])
    get_link(data[i])

    i+=1

check.sort(reverse=True,key=float)
check=dict.fromkeys(check)
check=list(check)

#print(check)
#print(score)

'''
print(risk)
print(vname)
print(score)
print(strng)
print(cvss)
print(desc)
print(impact)
print(remedy)
print(systems)
print(cve)
print(link)
'''

data=[]
if (len(risk)==len(vname)==len(score)==len(strng)==len(cvss)==len(desc)==len(impact)==len(remedy)==len(systems)==len(cve)==len(link)==total):
    i=0
    while i<total:
        line=str(score[i])+','+str(strng[i]).removeprefix('(').removesuffix(')')+','+str(vname[i]).replace(',',';').upper()+','+str(systems[i]).replace(',',';')+','+str(desc[i]).replace(',',';').replace('<br>','')+','+str(impact[i]).replace(',',';').replace('<br>','')+','+str(remedy[i]).replace(',',';').replace('<br>','')+','+str(cve[i]).replace(',',';')+','+str(link[i]).replace(',',';')+',$#'
        #print(line)
        data.append(line)
        i=i+1
'''
print(score)
print(check)
print(len(data))
'''

content=[]

for i in check:
    if 10.0>=float(i)>=9.0:
        cut_off=(str(i)+',')
        risk_factor='CRITICAL,'
    elif 8.9>=float(i)>=7.0:
        cut_off=(str(i)+',')
        risk_factor='HIGH,'
    elif 6.9>=float(i)>= 4.0:
        cut_off=(str(i) + ',')
        risk_factor='MEDIUM,'
    elif 3.9>=float(i)>=0.1:
        cut_off=(str(i)+',')
        risk_factor='LOW,'
    else:
        cut_off=(str(i)+',')
        risk_factor='INFORMATIONAL,'
    get_sorted(cut_off,risk_factor)


f=open(out_csv,'w')
line=('SL NO,SEVERITY,CVSS SCORE,CVSS STRING,VULNERABILITY NAME,AFFECTED SYSTEM,DESCRIPTION,IMPACT,REMEDIATION,CLASSIFICATION,REFERENCE LINK\n')
f.write(line)

content=("".join(content))
data=[]
sl=1
for i in content.split(',$#'):
    if re.search(',',i):
        f.write(str(sl)+','+i+'\n')
        data.append(str(sl)+','+i+'\n')
        sl=sl+1
f.close()
print('[✔] Done')

print('[?] Creating XLSX : '+out_xlsx)
merge_all_to_a_book(glob.glob(out_csv),out_xlsx)
print('[✔] Done')

#============================================================================================================================================================================================================================================================
#                        H   T   M   L                     C   R   E  A  T  I  O   N
#============================================================================================================================================================================================================================================================

html=[]
print('[?] Creating HTML : '+out_html)
f=open(out_html,'w')

line='\n<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'+file_name+'</title>\n<style type="text/css">\n'
f.write(line)
line=requests.get('https://raw.githubusercontent.com/17ack312/myscripts/main/style_report.css').text
f.write(line)
line='\n</style></head>\n<body style="font-family: Tahoma;">'
f.write(line)


def create_html(data):
    #print(data)
    i=data.split(',')

    line='\n<div class="'+i[1]+'" id="vuln" align="center"><table>\n'
    f.write(line)
    line='\n<tr id="name_rate"><td colspan="2">'
    f.write(line)
    line='<span id="sl">'+str(i[0])+'.</span>'
    f.write(line)
    line='\n<span id="name"><span id="point">&emsp;Vulnerability Name:</span>'
    f.write(line)
    line='\n<span id="info">&ensp;'+str(i[4])+'</span></span>\n<br>'
    f.write(line)
    line='\n<span id="rate"><span id="point">&emsp;&ensp;&ensp;Vulnerability Rating:</span>'
    f.write(line)
    line='\n<span id="info">&ensp;'+str(i[1])+'</span></span></td></tr>\n'
    f.write(line)


    line='\n<tr id="cvss_cve"><td colspan="2">'
    f.write(line)
    line='\n<span id="cvss"><span id="point">CVSS:</span>'
    f.write(line)
    line='\n<span id="info">'+str(i[2])+'&ensp;'+str(i[3])+'</span></span>'
    f.write(line)

    if 'CVE' in str(i[9]):
        line = '\n<br><span id="cve"><span id="point">CVE:&nbsp;&nbsp;</span>'
        f.write(line)
        temp_count = 1
        for j in (str(i[9]).strip().replace(' ;',',').split(', ')):
            if 'CVE' in j:
                if temp_count>1:
                    f.write(', ')
                line='\n<a id="info" href="https://nvd.nist.gov/vuln/detail/'+j+'">'+j+'</a>'
                f.write(line)
                temp_count+=1

    if 'CWE' in str(i[9]):
        line='<br><span id="cwe"><span id="point">CWE:&nbsp;</span>'
        f.write(line)
        temp_count=1
        for j in (str(i[9]).strip().replace(' ;', ',').split(', ')):
            if 'CWE' in j:
                if temp_count>1:
                    f.write(', ')
                line='\n<a id="info" href="http://cwe.mitre.org/data/definitions/'+j.removeprefix('CWE:') + '">' + j + '</a>'
                f.write(line)
                temp_count += 1
    line='\n</span></tr>'
    f.write(line)

    line='\n<tr id="system"><td colspan="2">'
    f.write(line)
    line='\n<span id="point">Affected Systems:</span><br>'
    f.write(line)
    line='\n<span id="info">'+i[5].replace(' ;',',')+'</span></td></tr>'
    f.write(line)


    line='\n<tr id="desc"><td id="left"><span id="point">Vulnerability Description:</span></td>'
    f.write(line)
    line='\n<td id="right"><span id="info">'+i[6]+'</span></td></tr>'
    f.write(line)

    line='\n<tr id="impact"><td  id="left"><span id="point">Impact:</span></td>'
    f.write(line)
    line='\n<td  id="right"><span id="info">'+i[7]+'</span></td></tr>'
    f.write(line)

    line='\n<tr id="remedy"><td  id="left"><span id="point">Remediation:</span></td>'
    f.write(line)
    line='\n<td id="right"><span id="info">'+i[8]+'</span>'
    f.write(line)

    if 'http' in i[10]:
        line = '\n<p id="ref_link">References:</p>'
        f.write(line)
        line = '\n<ol id="ref_link">'
        f.write(line)
        for j in i[10].replace('\n','').replace(' ;',',').split(','):
            line=str('\n<li><a href="'+j+'">'+j+'</a></li>')
            f.write(line)
        line='\n</ol>'
        f.write(line)
    line='\n</td></tr>'
    f.write(line)

    line='\n<tr id="poc"><td  id="left"><span id="point">POC:</span></td>'
    f.write(line)
    line='\n<td id="right"><span id="info"></span></td></tr>'
    f.write(line)

    line='\n<tr id="auditee"><td  id="left"><span id="point">Auditee&apos;s Response:</span></td>'
    f.write(line)
    line='\n<td id="right"></td></tr>'
    f.write(line)

    line='\n<tr id="estimate"><td  id="left"><span id="point">Estimated Implementation Date:</span></td>'
    f.write(line)
    line='\n<td id="right"><span id="info"></span></td></tr>'
    f.write(line)

    line='\n<tr id="closure"><td  id="left"><span id="point">Closure Remark:</span></td>'
    f.write(line)
    line='\n<td id="right"><span id="info"></span></td></tr>'
    f.write(line)

    line='\n<tr id="blank"><td colspan="2"  style="padding: 10px; background: #d4d4d4;"></td></tr>'
    f.write(line)

    line='\n</table></div><br>'
    f.write(line)

    line='\n<h1 id="pagebreak"> </h1>'
    f.write(line)

    line='\n<!========================================================================-->\n\n'
    f.write(line)

#    print(line)





#for i in data:
#    create_html(data[i])

for i in range(len(data)):
    create_html(data[i])

line='\n</body></html>'
f.write(line)
f.close()
print('[✔] Done')
