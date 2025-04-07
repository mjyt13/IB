import sys, os, random

alphabet = ['А','Б','В','Г','Д','Е','Ё','Ж','З','И','Й',
           'К','Л','М','Н','О','П','Р','С','Т','У','Ф',
           'Х','Ц','Ч','Ш','Щ','Ъ','Ы','Ь','Э','Ю','Я']

alphabet_low = ['а','б','в','г','д','е','ё','ж','з','и','й',
           'к','л','м','н','о','п','р','с','т','у','ф',
           'х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я']

# создание квадрата виженера (фиксированный случайный алфавит)
def create_visioner_random():
    visioner = {}

    alphabet_vis_big = []
    banned_pos = []
    for i in range(len(alphabet)):
        letter_pos = random.randint(0,len(alphabet)-1)
        while letter_pos in banned_pos:
            letter_pos = random.randint(0, len(alphabet) - 1)
        banned_pos.append(letter_pos)
        alphabet_vis_big.append(alphabet[letter_pos])

    alphabet_vis_low = []
    banned_pos.clear()
    for i in range(len(alphabet_low)):
        letter_pos = random.randint(0,len(alphabet_low)-1)
        while letter_pos in banned_pos:
            letter_pos = random.randint(0, len(alphabet_low) - 1)
        banned_pos.append(letter_pos)
        alphabet_vis_low.append(alphabet_low[letter_pos])

    # квадрат виженера: словарик, где ключ - буква, а значение - алфавит
    for i in range(len(alphabet)):
        temp_alphabet= alphabet_vis_big[-i+1:]+alphabet_vis_big[:-i+1]
        visioner[alphabet[i]] = temp_alphabet

    for i in range(len(alphabet_low)):
        temp_alphabet = alphabet_vis_low[-i+1:] + alphabet_vis_low[:-i+1]
        visioner[alphabet_low[i]] = temp_alphabet

    return visioner

def create_visioner_order(move):
    visioner = {}
    alphabet_vis_big = alphabet[-move-1:]+alphabet[:-move-1]
    alphabet_vis_low = alphabet_low[-move-1:]+alphabet_low[:-move-1]

    for i in range(len(alphabet)):
        temp_alphabet= alphabet_vis_big[-i+1:]+alphabet_vis_big[:-i+1]
        visioner[alphabet[i]] = temp_alphabet

    for i in range(len(alphabet_low)):
        temp_alphabet = alphabet_vis_low[-i+1:] + alphabet_vis_low[:-i+1]
        visioner[alphabet_low[i]] = temp_alphabet

    return visioner


# процесс кодирования, ебать его рот (ЦЕЗАРЬ)
def ceaser_encode(message,move):
    ceaser_move = move
    encoded_message = ''
    for i in range(len(message)):
        letter = message[i]
        if letter.islower():
            start_index = alphabet_low.index(letter)
            encoded_message += alphabet_low[(start_index+ceaser_move)%len(alphabet_low)]
        if letter.isupper():
            start_index = alphabet.index(letter)
            encoded_message += alphabet[(start_index+ceaser_move)%len(alphabet)]
        if not(letter.isupper()) and not(letter.islower()):
            encoded_message += letter
    return encoded_message

def ceaser_decode(encoded_message,move):
    ceaser_move = move
    decoded_message = ''
    for i in range(len(encoded_message)):
        letter = encoded_message[i]
        if letter.islower():
            start_index = alphabet_low.index(letter)
            decoded_message += alphabet_low[(start_index-ceaser_move)%len(alphabet_low)]
        if letter.isupper():
            start_index = alphabet.index(letter)
            decoded_message += alphabet[(start_index-ceaser_move)%len(alphabet)]
        if not(letter.isupper()) and not(letter.islower()):
            decoded_message += letter
    return decoded_message

# работа с файлом в режиме шифр Цезаря
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

# вижиненр

# процесс кодирования (ВИЖЕНЕР)
def encode_visioner(message,vis_dict,keyU,keyL):
    encoded_message = ''
    for i in range(len(message)):
        letter = message[i]
        if letter.islower():
            key_index = keyL[i % len(keyL)]
            start_index = alphabet_low.index(letter)
            encoded_message += vis_dict[key_index][start_index]
        if letter.isupper():
            key_index = keyU[i % len(keyU)]
            start_index = alphabet.index(letter)
            dicti = vis_dict[key_index]
            encoded_message += vis_dict[key_index][start_index]
        if not(letter.isupper()) and not(letter.islower()):
            encoded_message += letter
    return encoded_message

def decode_visioner(encoded_message,vis_dict,keyU,keyL):
    decoded_message = ''
    for i in range(len(encoded_message)):
        letter = encoded_message[i]
        if letter.islower():
            key_index = keyL[i % len(keyL)]
            decode_index = vis_dict[key_index].index(letter)
            decoded_message += alphabet_low[decode_index]
        if letter.isupper():
            key_index = keyU[i % len(keyU)]
            decode_index = vis_dict[key_index].index(letter)
            decoded_message += alphabet[decode_index]
        if not(letter.isupper()) and not(letter.islower()):
            decoded_message += letter
    return decoded_message

def visioner_mode(filename,mode,move,key_word):

    with open(filename,"r",encoding='utf-8') as orig_file:
        fanfic = orig_file.read()
    orig_fanfic = fanfic

    key_upper = key_word.upper()
    key_lower = key_word.lower()

    if mode == 'random':
        visioner_dict = create_visioner_random()
    else:
        visioner_dict = create_visioner_order(move)

    # вывод квадрата виженера
    for key in visioner_dict:
        print(key,visioner_dict[key])

    visioner_filename_enc = 'encV'+filename
    visioner_filename_dec = 'decV'+filename

    encoded_fanfic = encode_visioner(fanfic,visioner_dict,key_upper,key_lower)

    with open(visioner_filename_enc,"w",encoding='utf-8') as visioner_file:
        visioner_file.write(encoded_fanfic)

    # дать другие ключи можно здесь
    key_upper = key_word.upper()
    key_lower = key_word.lower()

    with open(visioner_filename_enc,"r",encoding='utf-8') as visioner_file:
        fanfic = visioner_file.read()

    decoded_fanfic = decode_visioner(fanfic,visioner_dict,key_upper,key_lower)

    with open(visioner_filename_dec,"w",encoding='utf-8') as visioner_file:
        visioner_file.write(decoded_fanfic)

    print(orig_fanfic[:90])
    print(encoded_fanfic[:90])
    print(decoded_fanfic[:90])

    if decoded_fanfic == orig_fanfic:
        print('Тексты совпадают')
    else:
        print('Тексты не совпадают')

    return

file_name = 'fanfic.txt'
