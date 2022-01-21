#by plugin with remedy and all in html format
import json,re,datetime,time
import numpy as np

cve_url='http://web.nvd.nist.gov/view/vuln/detail?vulnId='
cwe_url='http://cwe.mitre.org/data/definitions/'

now =str(datetime.datetime.now()).split('.',1)
now=(now[0]).replace(' ','_').replace(':','').replace('-','')

file='E:/prime/VAPT/DFPCL/rajdeep/19_01/static_s0tc4l.html'.replace('\\','/')
loc=file.split('/')
name=loc[-1].split('.')
name=name[0]
loc=("/".join(loc[:-1])+'/')
out_csv=loc+name+'_.csv'
out_html=loc+name+'_.html'

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

vname=[]

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

desc=[]
def get_desc(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Synopsis')):
            for j in i.replace('<div','\n<div').replace('div>','div>\n').split('\n'):
                if j.startswith('<div style="line-height: 20px; padding: 0 0 20px 0;">'):
                    line=(j.replace('<div style="line-height: 20px; padding: 0 0 20px 0;">','').replace('</div>',''))
    desc.append(line.replace(',',';').strip())
    #print(line)

impact=[]
def get_imp(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Description')):
            for j in i.replace('<div', '\n<div').replace('div>', 'div>\n').split('\n'):
                if j.startswith('<div style="line-height: 20px; padding: 0 0 20px 0;">'):
                    line=(j.replace('<div style="line-height: 20px; padding: 0 0 20px 0;">','').replace('</div>',''))
    impact.append(line.replace(',',';').strip())
    #print(line)

remedy=[]
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

cvss=[]
score=[]
strng=[]
check=[]
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

link=[]
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

cve=[]
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

systems=[]
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

risk=[]
def get_risk(line):
    line = line.replace('<div class="details-header">', '\n<div class="details-header">')
    for i in line.split('\n'):
        if (i.startswith('<div class="details-header">Risk Factor')):
            line=(i.replace('<div class="details-header">Risk Factor</div><div style="line-height: 20px; padding: 0 0 20px 0;">','').replace('</div>','').strip())
    risk.append(line)
    #print(line)


length=len(data)
total=(length-2)
i=1
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
def get_sorted(cut_off,risk):
    for i in data:
        if(i.startswith(cut_off)):
            content.append(risk+i)


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

sl=1
for i in content.split(',$#'):
    if re.search(',',i):
        f.write(str(sl)+','+i+'\n')
        sl=sl+1
f.close()
