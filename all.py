
import requests, json, sys, os, urllib
from requests.structures import CaseInsensitiveDict
# encry password
import base64
import struct
import datetime
import binascii
from urllib.parse import quote_plus
from Cryptodome import Random
from Cryptodome.Cipher import AES
from nacl.public import PublicKey, SealedBox


def encrypt_password(key_id, pub_key, password, version=10):
    key = Random.get_random_bytes(32)
    iv = bytes([0] * 12)

    time = int(datetime.datetime.now().timestamp())

    aes = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    aes.update(str(time).encode('utf-8'))
    encrypted_password, cipher_tag = aes.encrypt_and_digest(password.encode('utf-8'))

    pub_key_bytes = binascii.unhexlify(pub_key)
    seal_box = SealedBox(PublicKey(pub_key_bytes))
    encrypted_key = seal_box.encrypt(key)

    encrypted = bytes([1,
                       key_id,
                       *list(struct.pack('<h', len(encrypted_key))),
                       *list(encrypted_key),
                       *list(cipher_tag),
                       *list(encrypted_password)])
    encrypted = base64.b64encode(encrypted).decode('utf-8')

    return quote_plus(f'#PWD_INSTAGRAM_BROWSER:{version}:{time}:{encrypted}')


def Get_cookie_ins ():
    url = "https://www.instagram.com/"
    rq  = requests.get(url)
    cookie = rq.cookies.get_dict()
    return {"headers": rq.headers, "cookies": cookie}

def getData_info(getHeaders):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=getHeaders["cookies"]).json()
    return {
        'keyID': rq['encryption']['key_id'],
        'pub_key': rq['encryption']['public_key'],
        'version': rq['encryption']['version'],
        'csrf_token': rq['config']['csrf_token']
    }
    
def getInfoUser(cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    json_data = rq['config']['viewer']
    for x in json_data:
        name = (str(x) + '').replace('_', ' ').title()
        print(name, ':', json_data[x])
    print('Cookie: ', cookie)


def login (username, password, cookie, csrf_token):
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    data = "enc_password=" + password + "&username=" + username + "&queryParams=%7B%7D&optIntoOneTap=false&stopDeletionNonce=&trustedDeviceRecords=%7B%7D"
    resp = requests.post("https://www.instagram.com/accounts/login/ajax/", headers=headers, data=data, cookies=cookie)
    if (resp.json()['authenticated'] == False):
        print("Login failed")
        print(resp.json())
        sys.exit()
    else:
        print("Login success")
        return resp.cookies.get_dict()

def follow (id, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    resp = requests.post("https://www.instagram.com/web/friendships/" + id + "/follow/", headers=headers, cookies=cookie)
    try:
        return resp.json()['status'] == 'ok'
    except:
        return False
    
def unfollow (id, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    resp = requests.post("https://www.instagram.com/web/friendships/" + id + "/unfollow/", headers=headers, cookies=cookie)
    try:
        return resp.json()['status'] == 'ok'
    except:
        return False
def getIdPost (code, cookie):
    url = "https://www.instagram.com/p/" + code + "/"
    rq = requests.get(url, cookies=cookie).text
    return rq.split('content="instagram://media?id=')[1].split('"')[0]

def hearthPost (id, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    resp = requests.post("https://www.instagram.com/web/likes/" + id + "/like/", headers=headers, cookies=cookie)
    try:
        return resp.json()['status'] == 'ok'
    except:
        return False

def unHearthPost (id, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    resp = requests.post("https://www.instagram.com/web/likes/" + id + "/unlike/", headers=headers, cookies=cookie)
    try:
        return resp.json()['status'] == 'ok'
    except:
        return False

def Comment (id, content, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    data = "comment_text=" + content + "&replied_to_comment_id="
    resp = requests.post("https://www.instagram.com/web/comments/" + id + "/add/", headers=headers, cookies=cookie, data=data)
    try:
        return resp.json()
    except:
        return False

def removeComment(idPost, idComment, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    resp = requests.post("https://www.instagram.com/web/comments/" + idPost + "/delete/" + idComment + "/", headers=headers, cookies=cookie)
    try:
        return resp.json()['status'] == 'ok'
    except:
        return False

def changeAvatar (path, cookie):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    files = {'profile_pic': open(path, 'rb')}
    resp = requests.post("https://www.instagram.com/accounts/web_change_profile_picture/", headers=headers, cookies=cookie, files=files)
    try:
        return resp.json()
    except:
        return False

def changeProfie (name, pepName, pepWebsite, bio, email, sdt, cookie, chaining_enabled="on"):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    data = urllib.parse.urlencode({
        "first_name": name,
        "chaining_enabled": chaining_enabled,
        "email": email,
        "phone_number": sdt,
        "biography": bio,
        "external_url": pepWebsite,
        "username": pepName
    })

    resp = requests.post("https://www.instagram.com/accounts/edit/?__d=dis", headers=headers, cookies=cookie, data=data)
    try:
        return resp.json()['status'] == 'ok'
    except:
        return False

def changeGender(idGender, cookie, tuychinh = ""):
    url = "https://www.instagram.com/data/shared_data/"
    rq = requests.get(url, cookies=cookie).json()
    csrf_token = rq['config']['csrf_token']
    headers = CaseInsensitiveDict()
    headers["authority"] = "www.instagram.com"
    headers["accept"] = "*/*"
    headers["accept-language"] = "vi,en;q=0.9,en-US;q=0.8"
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://www.instagram.com"
    headers["referer"] = "https://www.instagram.com/"
    headers["sec-ch-prefers-color-scheme"] = "dark"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.77"
    headers["x-csrftoken"] = csrf_token
    headers["x-requested-with"] = "XMLHttpRequest"
    headers["x-instagram-ajax"] = "1005951515"
    headers["x-requested-with"] = "XMLHttpRequest"
    data = urllib.parse.urlencode({
        "gender": idGender,
        "custom_gender": tuychinh
    })
    rq = requests.post('https://www.instagram.com/accounts/set_gender/', headers=headers, data=data, cookies=cookie)
    try:
        return rq.json()['status'] == 'ok'
    except:
        return False
'''Login instagram'''
username = '<username>'
password = '<password>'
getHeaders = Get_cookie_ins()
getData    = getData_info(getHeaders)
encrypt_pass = encrypt_password(int(getData['keyID']), getData['pub_key'], password, int(getData['version']))
cookie = login(username, encrypt_pass, getHeaders["cookies"], getData['csrf_token'])
getInfoUser(cookie)


'''Follow user'''
# id_follow = "54485960659"
# checkFollow = follow(id_follow, cookie)
# if(checkFollow):
#     print("Follow success")
# else:
#     print("Follow failed")

'''Unfollow user'''
# id_unfollow = "54485960659"
# checkUnfollow = unfollow(id_unfollow, cookie)
# if(checkUnfollow):
#     print("Unfollow success")
# else:
#     print("Unfollow failed")

'''Heart post'''
# idPost = getIdPost("Cgv65ZHr82v", cookie)
# print('ID post: ' + idPost)
# checkHearth = hearthPost(idPost, cookie)
# if (checkHearth):
#     print("Heart success")
# else:
#     print("Heart failed")


'''Unheart post'''
# idPost = getIdPost("Cgv65ZHr82v", cookie)
# print('ID post: ' + idPost)
# checkUnHearth = unHearthPost(idPost, cookie)
# if (checkUnHearth):
#     print("Unheart success")
# else:
#     print("Unheart failed")

'''Comment post/ Remove comment post''' 
# idPost = getIdPost("Cgv65ZHr82v", cookie)
# print('ID post: ' + idPost)
# content = input("Nhập nội dung muốn gửi: ")
# checkComment = Comment(idPost, content, cookie)
# if (checkComment):
#     input("Enter để xóa comment")
#     idCmt = checkComment['id']
#     print('ID comment: ' + idCmt)
#     checkRemoveCmt = removeComment(idPost, idCmt, cookie)
#     if (checkRemoveCmt):
#         print("Remove comment success")
#     else:
#         print("Remove comment failed")

# else:
#     print("Comment failed")

'''Change avatar'''
'''Này viết cho có, up thì up cũng được, nhưng phải cùng pixel thì mới ok:)))'''
# checkChangeAvatar = changeAvatar("avatar.jpg", cookie)
# if(checkChangeAvatar):
#     print(checkChangeAvatar)
# else:
#     print("Change avatar failed")

'''Change info profile'''
# name = "Trần Văn Ngũ"
# pepName = "tranvanngu134"
# pepWebsite = "https://www.facebook.com/tranvanngu134"
# bio = "Đây là biểu tượng của tôi"
# email = "trantronghoa.hex@gmail.com"
# sdt = "0937653926"

# checkChange = changeProfie(name, pepName, pepWebsite, bio, email, sdt, cookie)
# if (checkChange):
#     print("Change info success")
# else:
#     print("Change info failed")

'''Change gender'''
# idGender = 4 # 1 = Nam, 2 = Nữ , 3 = Không tiết lộ, 4 = Tùy chỉnh
# tuychinh = "đẹp chai"
# changeGend = changeGender(idGender, cookie, tuychinh)
# if (changeGend):
#     print("Change thanh cong")
# else:
#     print("Change that bai")
