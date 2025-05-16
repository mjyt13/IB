from GOST_R_34_12_2015 import (encrypt_text, decrypt_text,
                               kuznechik_encrypt, generate_round_keys)
import time
import numpy as np
from collections import Counter

taken_rounds = 3
# key = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
key = 0
keys = generate_round_keys(key,rounds=taken_rounds)
opened = 0x1122334455667700ffeeddccbbaa9988

def differential_cryptoanalisys(delta_P):
    t_start = time.time()
    # генерация данных
    delta = delta_P  # Разница
    signs = 1 << 9
    print(f"рассматривается разница {hex(delta)}")
    plaintexts = [i.to_bytes(16, 'big') for i in range(signs)]  # Базовые тексты
    # пары вида (P, P ⊕ ΔP)
    print(plaintexts[1<<7])
    pairs = [(p, bytes([a ^ b for a, b in zip(p, delta.to_bytes(16, 'big'))])) for p in plaintexts]
    # шифрование блоков
    ciphertexts = []
    for p1, p2 in pairs:
        c1 = kuznechik_encrypt(int.from_bytes(p1, 'big'), keys, rounds=taken_rounds)
        c2 = kuznechik_encrypt(int.from_bytes(p2, 'big'), keys, rounds=taken_rounds)
        ciphertexts.append((c1, c2))
    delta_ciphers = [c1 ^ c2 for c1, c2 in ciphertexts]  # Разности шифротекстов

    byte_positions = range(16)  # Байты 0, 1, 2, 3
    all_delta_bytes = {pos: [] for pos in byte_positions}

    for pos in byte_positions:
        all_delta_bytes[pos] = [(dc >> (8 * (15 - pos))) & 0xFF for dc in delta_ciphers]

    # 1. Вывод топ-5 разностей для каждого байта
    for pos in byte_positions:
        freq = Counter(all_delta_bytes[pos])
        top10 = freq.most_common(10)
        # Расчет среднего числа повторений
        avg = np.mean(list(freq.values()))

        print(f"Байт {pos}:")
        print(f"Топ-10 разностей: {top10}")
        print(f"Среднее число повторений: {avg:.2f}")
        print(f"Максимальное число повторений: {top10[0][1]}")
        print(f"Отношение макс/среднее: {top10[0][1] / avg:.2f}x\n")

    t_finish = time.time()
    print(f"Построено за {t_finish - t_start} секунд ({(t_finish - t_start) / 60} минут)")

    return None
t_start = time.time()
d = 0xFF
i = 0
while i < 16:
    differential_cryptoanalisys(d << 4*i)
    i += 1
t_finish = time.time()
print(f"анализ проведен за {t_finish-t_start} секунд ({(t_finish-t_start)/60} минут)")
"""
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
print("Найденный ключ:", found_key)"""