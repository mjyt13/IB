def password_power(password,speed,attempts,pause):
    ascii_exist = False
    digits_exist = False
    low_letters_exist = False
    big_letters_exist = False

    alphabet = 0

    # проверить каждый символ на принадлежность к какому-либо алфавиту
    for letter in password:
        if str(letter).isdigit():
            digits_exist = True
        if str(letter).islower():
            low_letters_exist = True
        if str(letter).isupper():
            big_letters_exist = True
        if (str(letter).isascii() and not (str(letter).isupper()) and
                not (str(letter).islower()) and not (str(letter).isdigit())):
            ascii_exist = True
    # и в зависимости от принадлежности добавить к объявленному алфавиту мощность присутствующего
    if digits_exist: alphabet += 10
    if big_letters_exist: alphabet += 26
    if low_letters_exist: alphabet += 26
    if ascii_exist: alphabet = 95

    # print(f"Алфавит равен {alphabet}")

    power = alphabet ** (len(password))  # количество всевозможных комбинаций

    # print(f"Мощность пространства равна {power}")

    s = speed  # скорость перебора паролей в секунду
    m = attempts  # количество неправильных попыток, после которых идёт пауза в v секунд
    v = pause  # пауза в секундах при неверном вводе пароля

    if power % m == 0:
        times_to_pause = power // m - 1  # сколько раз будет спровоцирована пауза
    else:
        times_to_pause = power // m
    t = (power // s + 1) + times_to_pause * v

    # обнаружен косяк - если мощность делится нацело на количество неверных попыток
    # то будет лишняя пауза

    return t,power,alphabet


def reformat_time(time):
    seconds = time % 60
    all_minutes = time // 60
    minutes = all_minutes % 60
    all_hours = all_minutes // 60
    hours = all_hours % 24
    all_days = all_hours // 24
    days = all_days % 30
    all_months = all_days // 30
    months = all_months % 12
    years = all_days // 365
    return f"{years} лет, {months} месяцев, {days} дней, {hours} часов, {minutes} минут, {seconds} секунд"
