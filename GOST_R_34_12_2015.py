# Предопределенные константы (S-блоки)
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
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
]

INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i

# Итерационные константы (8 штук для 10 итерационных ключей)
C = [
    0x6ea276726c487ab85d27bd10dd849401,
    0xdc87ece4d890f4b3ba4eb92079cbeb02,
    0xb2259a96b4d88e0be7690430a44f7f03,
    0x7bcd1b0b73e32ba5b79cb140f2551504,
    0x156f6d791fab511deabb0c502fd18105,
    0xa74af7efab73df160dd208608b9efe06,
    0xc9e8819dc73ba5ae50f5b570561a6a07,
    0xf6593616e6055689adfba18027aa2a08,
    0x98fb40648a4d2c31f0dc1c90fa2ebe09,
    0x2adedaf23e95a23a17b518a05e61c10a,
    0x447cac8052ddd8824a92a5b083e5550b,
    0x8d942d1d95e67d2c1a6710c0d5ff3f0c,
    0xe3365b6ff9ae07944740add0087bab0d,
    0x5113c1f94d76899fa029a9e0ac34d40e,
    0x3fb1b78b213ef327fd0e14f071b0400f,
    0x2fb26c2c0f0aacd1993581c34e975410,
    0x41101a5e6342d669c4123cd39313c011,
    0xf33580c8d79a5862237b38e3375cbf12,
    0x9d97f6babbd222da7e5c85f3ead82b13,
    0x547f77277ce987742ea93083bcc24114,
    0x3add015510a1fdcc738e8d936146d515,
    0x88f89bc3a47973c794e789a3c509aa16,
    0xe65aedb1c831097fc9c034b3188d3e17,
    0xd9eb5a3ae90ffa5834ce2043693d7e18,
    0xb7492c48854780e069e99d53b4b9ea19,
    0x56cb6de319f0eeb8e80996310f6951a,
    0x6bcec0ac5dd77453d3a72473cd72011b,
    0xa22641319aecd1fd835291039b686b1c,
    0xcc843743f6a4ab45de752c1346ecff1d,
    0x7ea1add5427c254e391c2823e2a3801e,
    0x1003dba72e345ff6643b95333f27141f,
    0x5ea7d8581e149b61f16ac1459ceda820
]

# степени двойки для поля Галуа
gf = [1]
for i in range(1,256):
    galua_val = gf[i - 1] << 1
    if galua_val >= 256:
        galua_val ^= 0xC3 # = 195 = 451 (0x1C3)
    gf.append(galua_val % 256)

# Константы для линейного преобразования
L_const = [1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148]

def split_block(block, bits=128):
    """Разбивает блок размером 128 бит на две части. Произвольное количество бит у блока указывается явно."""
    half = bits // 2
    return (block >> half) & ((1 << half) - 1), block & ((1 << half) - 1)

def join_blocks(L, R, bits=128):
    """Соединяет две части в один блок размером 128 бит. Произвольное количество бит всего блока указывается явно."""
    half = bits // 2
    return (L << half) | R

def substitute_bytes(x, s_box=None, size=128):
    """Применяет S-блок к каждому байту 128-битного числа."""

    if s_box is None:
        s_box = S_BOX
    result = 0
    for i in reversed(range(size // 8)):
        byte = (x >> (8 * i)) & 0xFF
        substituted = s_box[byte]
        result = (result << 8) | substituted
    return result

def generate_round_keys(key,rounds=10):
    """Генерирует 10 раундовых ключей из 256-битного ключа."""
    K = [0] * rounds
    K[0], K[1] = key >> 128, key & ((1 << 128) - 1)
    for i in range(2, rounds,2):
        pair_1, pair_2 = K[i-2], K[i-1]
        for j in range(8):
            temp_pair = pair_1
            pair_1 = linear_transform(substitute_bytes(pair_1 ^ C[4*(i-2) + j])) ^ pair_2
            pair_2 = temp_pair
        K[i] = pair_1; K[i+1] = pair_2
    return K


def gf_mult(a, b):
    """Умножение в поле GF(2^8)
    Берутся 2 числа, находятся соответствующие им степени двойки, показатели складываются,
    после чего находится остаток от деления на 255(вернуться в поле), и находится число по показателю степени
    пример: 319 = 63 (mod 256) * 77. 63=2**204, 77=2**109; 204+109=313 = 58 (mod 255); 2**58 = 227"""
    if a==0 or b==0: return 0
    log_a = gf.index(a%256)
    log_b = gf.index(b%256)
    log_c = (log_a + log_b)%255
    return gf[log_c]

def gf_div(a,b):
    """Деление в поле GF(2^8)
    Берутся 2 числа, находятся соответствующие им степени двойки, показатель второго вычитается из оного первого,
    после чего находится остаток от деления на 255(вернуться в поле), и находится число по показателю степени"""
    if a==0 or b==0: return 0
    log_a = gf.index(a % 256)
    log_b = gf.index(b % 256)
    log_c = (log_a - log_b) % 255
    return gf[log_c]

def linear_transform_single(x,size=128):
    """линейное преобразование L(x) для 128-битного блока. Разбивается блок 128 бит на 16 байт,
    и к каждому из них применяется умножение строго определенных констант ГОСТ"""
    x_bytes = [(x >> (8 * i)) & 0xFF for i in range(size//8)]
    result = 0
    l = 0
    for i in range(size // 8):
        val = gf_mult(x_bytes[i],L_const[i])
        l ^= val
    result |= l
    for i in range(size//8 - 1,0,-1):
        result <<= 8
        result |= x_bytes[i]
    return result

def inv_linear_transform_single(x,size=128):
    """ Обратное линейное преобразование L(x) для 128-битного блока. Разбивается блок 128 бит на 16 байт,
    и к каждому из них применяется умножение строго определенных констант ГОСТ.
    После этого находится сумма в поле с первым байтом(он результат прямого преобразования),
    что становится недостающим первым(нулевым) байтом."""
    x_bytes = [(x >> (8 * i)) & 0xFF for i in range(size//8)]
    result = 0
    l = x_bytes[-1]
    for i in range((size // 8) - 1):
        val = gf_mult(x_bytes[i],L_const[i+1])
        l ^= val
    for i in range(size//8 - 2,-1,-1):
        result |= x_bytes[i]
        result <<= 8
    result |= l
    return result

def linear_transform(x,size=128):
    """Линейное преобразование. 16 раз единичного линейного преобразования"""
    x_iter = x
    for i in range(16):
        x_iter = linear_transform_single(x_iter,size=size)
    return x_iter

def inv_linear_transform(x, size=128):
    """Обратное линейное преобразование. 16 раз единичного преобразования"""
    x_iter = x
    for i in range(16):
        x_iter = inv_linear_transform_single(x_iter, size=size)
    return x_iter

def kuznechik_encrypt(block, round_keys, rounds=10, mass=None):
    if mass is None:
        mass = []
    R = block
    for i in range(rounds):
        R ^= round_keys[i]
        # print(hex(R))
        R = substitute_bytes(R,S_BOX, 128)
        # print(hex(R))
        R = linear_transform(R, 128)
        # print(hex(R))
        if i == 4:
            mass.append(R)
    return R

def kuznechik_decrypt(block, round_keys, rounds=10):
    L = block
    for i in reversed(range(rounds)):
        L = inv_linear_transform(L, 128)
        L = substitute_bytes(L, INV_S_BOX,128)
        L ^= round_keys[i]
    return L


def text_to_blocks(text: str) -> list[int]:
    """Разбивает текст на блоки по 16 байт (128 бит) и преобразует в числа."""
    byte_data = text.encode('utf-8')
    blocks = []
    for i in range(0, len(byte_data), 16):
        chunk = byte_data[i:i+16]
        # Дополняем последний блок нулями, если нужно
        if len(chunk) < 16:
            chunk += bytes([0] * (16 - len(chunk)))
        blocks.append(int.from_bytes(chunk, byteorder='big'))
    return blocks

def blocks_to_text(blocks: list[int]) -> str:
    """Собирает текст из блоков, удаляя дополняющие нули."""
    byte_data = bytearray()
    for block in blocks:
        byte_data.extend(block.to_bytes(16, byteorder='big'))
    # Удаляем нули в конце
    padding_len = 0
    for i in range(len(byte_data) - 1, -1, -1):
        if byte_data[i] != 0:
            padding_len = i + 1
            break
    return byte_data[:padding_len].decode('utf-8')


def encrypt_text(text: str, key: int,rounds=10) -> list[int]:
    """Шифрует текст (строку) введенным ключом с помощью разбиения на байты в процессе.
    Результат - список зашфированных чисел"""
    blocks = text_to_blocks(text)
    round_keys = generate_round_keys(key,rounds=rounds)
    return [kuznechik_encrypt(b, round_keys,rounds=rounds) for b in blocks]

def decrypt_text(encrypted_blocks: list[int], key: int,rounds=10) -> str:
    """Дешифрует текст (набор чисел) с помощью введенного ключа, собирает байты, переводит в
    строку, понятную человеку"""
    round_keys = generate_round_keys(key,rounds=rounds)
    decrypted = [kuznechik_decrypt(b, round_keys,rounds=rounds) for b in encrypted_blocks]
    return blocks_to_text(decrypted)


def encrypt_file(filename: str, key: int,rounds=10) -> None:
    with open (filename,"r",encoding="utf-8") as orig_file:
        firsttext = orig_file.read()

    encrypted_text = encrypt_text(firsttext,key,rounds=rounds)
    out_text = ""
    for block in encrypted_text:
        out_text+=str(block)
        out_text+=" "

    out_filename = "GOST_encrypted_"+filename
    with open(out_filename,"w",encoding="utf-8") as out_file:
        out_file.write(out_text)
    return

def decrypt_file(filename: str, key: int,rounds=10)-> None:
    with open (filename,"r",encoding="utf-8") as orig_file:
        firsttext = orig_file.read()
        encrypted = firsttext.split()

    enc_numbers = [int(num) for num in encrypted]
    out_text = decrypt_text(enc_numbers,key,rounds=rounds)

    out_filename = "GOST_decrypted_"+filename
    with open(out_filename,"w",encoding="utf-8") as out_file:
        out_file.write(out_text)
    return

# Пример использования
if __name__ == "__main__":
    key = 0x8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF  # Пример ключа
    # key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # key = 0x1000
    keys = generate_round_keys(key)

    num = 0x0e93691a0cfc60408b7b68f66b513c13
    lin_num = linear_transform(num)
    inv_lin = inv_linear_transform(lin_num)

    num_text =173887671632706779947018813715747275054
    enc = kuznechik_encrypt(num_text,keys)
    decr = kuznechik_decrypt(enc,keys)
    print("zaeboka") if decr == num_text else print("biobroli poportil")