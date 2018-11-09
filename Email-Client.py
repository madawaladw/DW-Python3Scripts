import smtplib
import base64
import subprocess

def send_email(e_address, e_sendto, e_password, e_content):
    try:
        mail_server = smtplib.SMTP('smtp.gmail.com', 587)
        mail_server.ehlo()             #extended smtp
        mail_server.starttls()         #encrypt everything comes next
        try:
            mail_server.login(e_address, e_password)
            print('[SUCCESSFUL] LOGGED IN TO MAIL SERVER')
        except:
            print('[FAILED] ERROR LOGIN TO MAIL SERVER')
    except:
        print('[FAILED] ERROR CONNECTING TO MAIL SERVER')

    try:
        try:
            mail_server.sendmail(e_address, e_sendto, e_content)
            print('[SUCCESSFUL] EMAIL SENT')
            mail_server.close()
        except:
            print('[FAILED] ERROR SENDING EMAIL')
    except:
        print('[FAILED] ERROR OCCURED')
        mail_server.close()

def decode_mailpassword(key, ciphertext):       #vigener's cipher is used
    try:
        decrypted_letters = []
        decode_ciphertext = base64.urlsafe_b64decode(ciphertext).decode()

        for i in range(len(decode_ciphertext)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(decode_ciphertext[i]) - ord(key_c)) % 256)
            decrypted_letters.append(dec_c)
        
        finish_decoding = ''.join(decrypted_letters)
        print('[SUCCCESFUL] EXTRACTED THE EMAIL PASSWORD')
        return finish_decoding
    except:
        print('[FAILED] ERROR DECRYPTING PASSWORD')

subprocess.call('clear', shell=True)

email_content = str(input('TYPE THE MESSEGE: '))
email_receiver = str(input('SEND TO: '))

email_address = 'lmorningstarthedevil@gmail.com'
email_password = decode_mailpassword('dwgod','wrTDmMOaw6LCpMKVwqnCmg==')

send_email(email_address, email_receiver, email_password, email_content)