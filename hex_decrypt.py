import requests,sys,os;text='#$#$'
url = 'https://online-toolz.com//functions/HEX-TEXT.php'
payload="input="+text
header={'Content-Type':'application/x-www-form-urlencoded'}
res = requests.post(url, data=payload ,headers=header)
res=(res.content.decode())
print(res)
