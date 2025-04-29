import json, os, itertools,time, string, re
from collections import Counter
from Cryptographic_change import ceaser_encode,ceaser_decode

from Frequency_analysis import determine_caesar_key

alphabet = ['а','б','в','г','д','е','ё','ж','з','и','й',
           'к','л','м','н','о','п','р','с','т','у','ф',
           'х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я',' ']

# разделение пользователей
"""
users_json_path = "users.json"

def get_users():

    if not os.path.exists(users_json_path):
        restrictions = {
            "lower_letters": True,
            "upper_letters": True,
            "digits": True,
            "special": True
        }
        admin={
            "username": "ADMIN",
            "password": "",
            "banned": False,
            "restrictions": restrictions
        }
        users = {"ADMIN": admin}
        with open(users_json_path,"w") as file:
            json.dump(users,file)
        return users
    else:
        with open(users_json_path,"r") as file:
            return json.load(file)

users = get_users()
keys = []
for user in users:
   keys.append(user)
print(keys)
for key in keys:
   user = users[key]
   restrictions = user["restrictions"]
   for restriction in restrictions:
       if restriction == 'lower_letters':
            print("строчные буквы")
       if restriction == 'upper_letters':
           print("заглавные буквы")
       if restriction == 'digits':
           print("цифры")
       if restriction == 'special':
           print("особые символы")
"""
# открыть файл дать строк
"""
def clean_text(text):
    text = text.lower()
    text = re.sub('[^а-я]', '', text)
    return text

def determine_caesar_key(text):
    cleaned = clean_text(text)
    if not cleaned:
        return 0
    freq = Counter(cleaned)
    most_common = freq.most_common(1)[0][0]
    key = alphabet.index(most_common) % len(alphabet)
    return key

def ceaser_mode(filename,move):
    # файл с текстом

    with open(filename,"r",encoding='utf-8') as orig_file:
        fanfic = orig_file.read()
    orig_fanfic = fanfic

    ceaser_filename_enc = 'encC'+filename
    ceaser_filename_dec = 'decC'+filename
    encoded_fanfic = ceaser_encode(fanfic,move)

    # запись зашифрованного
    with open(ceaser_filename_enc,"w",encoding='utf-8') as ceaser_file:
        ceaser_file.write(encoded_fanfic)
    # чтение зашифрованного
    with open(ceaser_filename_enc,"r",encoding='utf-8') as ceaser_file:
        fanfic = ceaser_file.read()

    decoded_fanfic = ceaser_decode(fanfic,move)

    with open(ceaser_filename_dec,"w",encoding='utf-8') as ceaser_file:
        ceaser_file.write(decoded_fanfic)

    print(orig_fanfic[:90])
    print(encoded_fanfic[:90])
    print(decoded_fanfic[:90])

    if decoded_fanfic == orig_fanfic:
        print('Тексты совпадают')
    else:
        print('Тексты не совпадают')

    return

filename = 'fanfic.txt'
ceaser_filename = 'encC'+filename
visioner_filename = 'encV'+filename
with open(filename,"r",encoding='utf-8') as orig_file:
    govno = orig_file.read()
    govno.replace(".","", 34)
    ceaser_mode(filename,24)


with open(ceaser_filename,"r",encoding='utf-8') as ceaser_file:
    ponos = ceaser_file.read()
    key = determine_caesar_key(ponos)+1
    sran = ceaser_decode(ponos,key)
    print(key, sran[:90])"""
def split_block(block, bits=128):
    """Разбивает блок размером 128 бит на две части."""
    half = bits // 2
    return (block >> half) & ((1 << half) - 1), block & ((1 << half) - 1)

# key 64 bits
key = 0xA00000FF_90000100
# key_size in bits
key_size = key.bit_length()
print(key_size)
half = key_size // 2
print(half)
L,R = key >> 32 & 0xFFFFFFFF, key & 0xFFFFFFFF
print(hex(L),hex(R))
L_new, R_new = L ^ 0x0000000F, R ^ 0x00000000
print(hex(L_new), hex(R_new))
L_new, R_new = key >> half & ((1 << half)-1), key & ((1 << half)-1)
print(hex(L_new), hex(R_new))
