import requests,sys,os

def decrypt(text):
    url = 'https://online-toolz.com//functions/HEX-TEXT.php'
    payload="input="+text
    header={
        'Content-Type':'application/x-www-form-urlencoded',
        'Referer': 'https://online-toolz.com/tools/text-encryption-decryption.php',
        'Accept': '*/*',
        'Origin':'https://online-toolz.com',
        'Sec-Fetch-Site':'same-origin',
        'Sec-Fetch-Mode':'cors',
        'Sec-Fetch-Dest':'empty'
    }
    res = requests.post(url, data=payload ,headers=header)
    print(res.text)

decrypt('#$#$')




