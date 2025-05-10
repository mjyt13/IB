from GOST_R_34_12_2015 import (encrypt_text, decrypt_text,
                               encrypt_file, decrypt_file,
                               text_to_blocks,blocks_to_text,
                               kuznechik_encrypt, kuznechik_decrypt,
                               generate_round_keys, S_BOX, INV_S_BOX)
import time
from collections import Counter
songtext = (
"(ドラゴンボール おれはたいよう\n"
"Doragonbooru (Ore wa taiyou)\n"

"ドラゴンボール (おまえはつき)\n"
"Doragonbooru (Omae wa tsuki)\n"

"とけあえばきせきのぱわー\n"
"Tokeaeba kiseki no pawaa\n"

"ドラゴンボール (ゆびをあわせ)\n"
"Doragonbooru (Yubi wo awase)\n"

"ドラゴンボール (こころかさね)\n"
"Doragonbooru (Kokoro kasane)\n"

"たたかいのれきしをかえろ...さいきょうのふゆうじょん\n"
"Tatakai no rekishi wo kaero... Saikyou no fyuujon\n"
)  # Пример открытого текста

def sum_bytes(c_bytes: list[int], byte_pos: int, key_guess: int) -> (int, int, dict,int):
    xor_sum = 0
    plain_sum = 0
    found_bytes = []
    for ct in c_bytes:
        # Извлекаем нужный байт (после S-боксов, но до L-слоя 4-го раунда)
        ct_byte = (ct >> (8 * (15 - byte_pos))) & 0xFF
        xor_sum ^= (ct_byte ^ key_guess)
        plain_sum ^= ct_byte
        found_bytes.append(hex(ct_byte))
    fill = Counter(found_bytes).items()
    quan = len(fill)
    return xor_sum, plain_sum, fill, quan

taken_rounds = 10
# key = 0x2456899AFEDABBA12456899AFEDABBA1B5F3A1077915EFC0B5F3A1077915EFC0
key = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
keys = generate_round_keys(key,rounds=taken_rounds)
filename = "sobache_serdce.txt"
opened = 0x1122334455667700ffeeddccbbaa9988

# частотные характеристики для блоков - ничего особенного
"""
with open(filename,"r",encoding="utf-8") as textfile:
    text = textfile.read()
blocks_ = Counter(hex(block) for block in (text_to_blocks(text))).items()
comparasion = []
opened = []
for block in blocks_:
    opened.append(block)
enc_blocks = Counter(hex(block) for block in (encrypt_text(text,key,rounds=taken_rounds))).items()
ciphered = []
for block in enc_blocks:
    ciphered.append(block)
comparasion.append(opened); comparasion.append(ciphered)
for i in range(len(comparasion[0])):
    if comparasion[0][i][1] > 4:
        print(f"{comparasion[0][i][0]} - {comparasion[1][i][0]} : {comparasion[0][i][1]}")
print()"""
# попытка в интегральный анализ
# bytes([i]+[0]*15) ->
first_bytes = []
# генерация данных
plaintexts = [(i << 15*8) for i in range(256)]
# for p in plaintexts: print(hex(p),end=" ")
print()
# print(sum_bytes(plaintexts,0,keys[0]))
# шифрование
ciphertexts = [kuznechik_encrypt(block,keys,rounds=taken_rounds,mass=first_bytes) for block in plaintexts]
cips = []
for ct in ciphertexts:
    print(f"{ct:032x}"[:2+taken_rounds+4],end=", ")
    cips.append(f"{ct:032x}"[2+taken_rounds*2:])
ciphers=Counter(cips).items()
print()
print(ciphers)

found_key = bytearray(16)
for byte_pos in range(16):
    print(f"Анализ байта {byte_pos}")
    for k_guess in range(256):
        xor_sum, _, found_bytes, quan = sum_bytes(ciphertexts, byte_pos, k_guess)
        if xor_sum == 0:
            found_key[byte_pos] = k_guess
            print(f"Найден ключевой байт k[{byte_pos}]: {hex(k_guess)}")
            print(f"Значения байта {byte_pos} ({quan} штук): {found_bytes}")
            break
    else:
        print(f"Не удалось найти ключ для байта {byte_pos}: сумма равна {xor_sum}")
        print(f"Значения байта {byte_pos} ({quan} штук): {found_bytes}")
print("Найденный ключ:", found_key)
# шифрование и дешифрование текста из файла
"""enc_filename = "GOST_encrypted_"+filename
start = time.time()
encrypt_file(filename,key,rounds=taken_rounds)
decrypt_file(enc_filename,key,rounds=taken_rounds)
finish = time.time()
print(f"шифрование и дешифрование сработано за {finish-start} секунд")"""

print(hex(kuznechik_encrypt(opened,keys,taken_rounds)))