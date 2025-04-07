import time
import itertools

# Словарь для преобразования русских букв в латинскую (QWERTY) раскладку
RUS_TO_LAT = {
    'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y',
    'г': 'u', 'ш': 'i', 'щ': 'o', 'з': 'p', 'х': '[', 'ъ': ']',
    'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f', 'п': 'g', 'р': 'h',
    'о': 'j', 'л': 'k', 'д': 'l', 'ж': ';', 'э': "'",
    'я': 'z', 'ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n',
    'ь': 'm', 'б': ',', 'ю': '.'
}

def rus_to_qwerty(word):
    """Преобразует русское слово в QWERTY-раскладку."""
    result = ""
    for char in word.lower():
        result += RUS_TO_LAT.get(char, char)
    return result


def dictionary_attack(target_password, dictionary) :

    attempts = 0
    desired_attempt_time = 1.0 / 100  # 0.01 сек на попытку
    start_time = time.perf_counter()

    for word in dictionary:
        attempt_start = time.perf_counter()
        attempts += 1

        # Преобразуем слово в QWERTY-раскладку и сравниваем с целевым паролем
        if rus_to_qwerty(word) == target_password:
            elapsed = time.perf_counter() - start_time
            return {
                "method": "dictionary",
                "found_word": word,
                "attempts": attempts,
                "time": elapsed,
                "speed": attempts / elapsed if elapsed > 0 else 0
            }
        attempt_end = time.perf_counter()
        elapsed_attempt = attempt_end - attempt_start

        # Если попытка заняла меньше 0.01 сек, делаем паузу
        if elapsed_attempt < desired_attempt_time:
            time.sleep(desired_attempt_time - elapsed_attempt)

    elapsed = time.perf_counter() - start_time
    return {
        "method": "dictionary",
        "found_word": None,
        "attempts": attempts,
        "time": elapsed,
        "speed": attempts / elapsed if elapsed > 0 else 0
    }


def brute_force_attack(target_password, max_length, alphabet):

    attempts = 0
    desired_attempt_time = 1.0 / 1000  # 0.001 секунды на попытку
    start_time = time.perf_counter()

    for length in range(1, max_length + 1):
        for candidate in itertools.product(alphabet, repeat=length):
            iteration_start = time.perf_counter()
            attempts += 1
            attempt = "".join(candidate)
            if attempt == target_password:
                elapsed = time.perf_counter() - start_time
                return {
                    "method": "brute_force",
                    "found_password": attempt,
                    "attempts": attempts,
                    "time": elapsed,
                    "speed": attempts / elapsed if elapsed > 0 else 0
                }
            iteration_end = time.perf_counter()
            elapsed_iteration = iteration_end - iteration_start
            # Если попытка заняла меньше 0.001 сек, делаем паузу, чтобы не превышать 1000 попыток/сек.
            if elapsed_iteration < desired_attempt_time:
                time.sleep(desired_attempt_time - elapsed_iteration)

            print(f"doesn't seem right {attempt}")

    elapsed = time.perf_counter() - start_time
    return {
        "method": "brute_force",
        "found_password": None,
        "attempts": attempts,
        "time": elapsed,
        "speed": attempts / elapsed if elapsed > 0 else 0
    }

