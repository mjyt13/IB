import json, os, itertools,time, string, re
from collections import Counter

from mpmath import mnorm

from Cryptographic_change import ceaser_encode,ceaser_decode

from Frequency_analysis import determine_caesar_key

alphabet = ['а','б','в','г','д','е','ё','ж','з','и','й',
           'к','л','м','н','о','п','р','с','т','у','ф',
           'х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я',' ']

s_box = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
         233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
         249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
         5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
         235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
         181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,  183, 93, 135,
         21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
         50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
         223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
         224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
         167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
         173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
         7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
         225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
         32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
         89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]

for i in range(0,len(s_box),16):
    for j in range(16):
        print(hex(s_box[i+j]),end=", ")
    print()


S_BOX = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9D, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
]
INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i
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

def join_blocks(L, R, bits=128):
    """Соединяет две части в один блок."""
    half = bits // 2
    return (L << half) | R

def substitute_bytes(x, s_box, size=128):
    """Применяет S-блок к каждому байту 128-битного числа."""
    result = 0
    for i in range(size // 8):
        byte = (x >> (8 * i)) & 0xFF
        substituted = s_box[byte]
        result |= (substituted << (8 * i))
    return result

# key 64 bits
key = 0xA00000FF_90000100_C0007003_80000001
# key_size in bits
key_size = key.bit_length()
print(key_size)
half = key_size // 2
print(half)
#xpehb - OHO HA 64 BITS
L,R = key >> 32 & 0xFFFFFFFF, key & 0xFFFFFFFF
print(hex(L),hex(R))
L_new, R_new = L ^ 0x0000000F, R ^ 0x00000000
print(hex(L_new), hex(R_new))

# KRYTO - HA LYBOE KOL-VO BITS
L_new, R_new = split_block(key)
print(hex(L_new), hex(R_new))
key_new = join_blocks(L_new,R_new)
print(hex(key_new))

nlock = 0x11_22_33_44_55_66_77_00_ff_ee_dd_cc_bb_aa_99_88 # 16 bytes, 128 bits, 32 digits in hex

mlock = substitute_bytes(nlock,S_BOX)

mnlock = substitute_bytes(mlock,INV_S_BOX)

print(mnlock==nlock)

# для полей галуа

gf = [1]

for i in range(1,256):
    galua_val = gf[i - 1] << 1
    if galua_val >= 256:
        galua_val ^= 0xC3 # = 195 = 451 (0x1C3)
    gf.append(galua_val % 256)


for i in range(0, len(gf), 16):
    for j in range(16):
        print((gf[i + j]), end=", ")
    print()

def gf_mult(a, b):
    """Умножение в поле GF(2^8)
    Берутся 2 числа, находятся соответствующие им степени двойки, степени складываются,
    после чего находится остаток от деления на 255(вернуться в поле), и находится число по показателю степени"""
    log_a = gf.index(a%256)
    log_b = gf.index(b%256)
    log_c = (log_a + log_b)%255
    return gf[log_c]

def gf_div(a,b):
    log_a = gf.index(a % 256)
    log_b = gf.index(b % 256)
    log_c = (log_a - log_b) % 255
    return gf[log_c]


xori = [0xff,0xab,0x77]
s = xori[0] ^ xori[1]
print(hex(s))
s = s ^ xori[2]
print(hex(s))
s = s ^ xori[0] ^ xori[2]
print(hex(s))