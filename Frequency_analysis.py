# https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf
import sys
import re
import math
from math import gcd
from collections import Counter
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QTabWidget, QPushButton, QLabel, QTextEdit, QFileDialog)
from PySide6.QtCore import Qt

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from Cryptographic_change import ceaser_decode

# Определяем русский алфавит (без буквы "ё" — все 'ё' заменяются на 'е')
ALPHABET = ['а','б','в','г','д','е','ё','ж','з','и','й',
           'к','л','м','н','о','п','р','с','т','у','ф',
           'х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я']
ALPHABET_SIZE = len(ALPHABET)


def clean_text(text):
    # Приведение текста к нижнему регистру, замена 'ё' на 'е' и удаление всего, кроме русских букв.
    text = text.lower()
    text = re.sub('[^а-я]', '', text) 
    return text


# ---------- Функции для шифра Цезаря ----------

def determine_caesar_key(text):
    """
    Определяет ключ шифрования по методу Цезаря.
    Предполагается наибольшая частота буквы "о"
    """
    cleaned = clean_text(text)
    if not cleaned:
        return 0
    freq = Counter(cleaned)
    most_common = freq.most_common(1)[0][0]
    key = (ALPHABET.index(most_common) - ALPHABET.index("о")) % ALPHABET_SIZE
    return key



# ========= Функции для шифра Виженера =========

def index_of_coincidence(text, alphabet=ALPHABET):
    # Вычисляет индекс совпадений для заданного текста
    text = [c for c in text.lower() if c in alphabet]
    n = len(text)
    if n <= 1:
        return 0
    freq = Counter(text)
    ic = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))
    return ic


def split_text_by_key_length(text, key_length, alphabet=ALPHABET):
    """
    Разбивает текст на группы по символам, соответствующим позиции символа ключа.
    """
    groups = ['' for _ in range(key_length)]
    for i, char in enumerate(text):
        if char.lower() in alphabet:
            groups[i % key_length] += char
    return groups


def guess_vigenere_key_length(cipher_text, max_key_length=19, alphabet=ALPHABET):
    """
    Определяет возможную длину ключа, вычисляя средний индекс совпадений для разных разбиений.
    """
    candidates = {}
    for key_length in range(1, max_key_length + 1):
        groups = split_text_by_key_length(cipher_text, key_length, alphabet)
        ic_values = [index_of_coincidence(group, alphabet) for group in groups if group]
        avg_ic = sum(ic_values) / len(ic_values) if ic_values else 0
        candidates[key_length] = avg_ic
    # Выбираем длину ключа с максимальным средним индексом совпадений
    best_length = max(candidates, key=candidates.get)
    return best_length


STANDARD_RUS_FREQ = {
    'а': 0.062, 'б': 0.014, 'в': 0.038, 'г': 0.013, 'д': 0.025, 'е': 0.072,
    'ж': 0.007, 'з': 0.012, 'и': 0.046, 'й': 0.010, 'к': 0.028, 'л': 0.035,
    'м': 0.026, 'н': 0.053, 'о': 0.090, 'п': 0.023, 'р': 0.040, 'с': 0.045,
    'т': 0.053, 'у': 0.021, 'ф': 0.002, 'х': 0.009, 'ц': 0.004, 'ч': 0.010,
    'ш': 0.006, 'щ': 0.003, 'ъ': 0.014, 'ы': 0.016, 'ь': 0.014, 'э': 0.003,
    'ю': 0.006, 'я': 0.018
}


def determine_vigenere_key(cipher_text, key_length, alphabet=ALPHABET):
    """
    Улучшенный вариант: для каждой группы символов перебираем все сдвиги 0...len(alphabet)-1
    и выбираем тот, при котором распределение максимально похоже на эталонное.
    """
    groups = split_text_by_key_length(cipher_text, key_length, alphabet)
    key_shifts = []

    for group in groups:
        # Если группа пуста, пусть сдвиг = 0
        if not group:
            key_shifts.append(0)
            continue

        # Считаем частоту каждой буквы в группе
        group = group.lower()
        group_count = Counter(group)
        group_len = sum(group_count.values())

        # функция для оценки "схожести" через корреляцию - сумму долей нахождения букв в тексте
        def correlation(shift):
            # Построим распределение "расшифрованного" текста при данном shift
            # cipher_letter -> plain_letter = (index(cipher_letter) - shift) mod len(alphabet)
            shifted_freq = {letter: 0 for letter in alphabet}
            for cletter, cnt in group_count.items():
                p_index = (alphabet.index(cletter) - shift) % len(alphabet)
                pletter = alphabet[p_index]
                shifted_freq[pletter] += cnt

            # найти долю буквы в "расшифрованном" тексте
            for l in alphabet:
                shifted_freq[l] /= group_len

            # суммировать произведения: sum( частота в "расшифрованном" * частота в стандартном )
            corr_val = 0
            for l in alphabet:
                corr_val += shifted_freq[l] * STANDARD_RUS_FREQ.get(l, 0)
            return corr_val

        # Перебираем все сдвиги и выбираем с наибольшей корреляцией
        best_shift = 0
        best_corr = float('-inf')
        for s in range(len(alphabet)):
            c = correlation(s)
            if c > best_corr:
                best_corr = c
                best_shift = s

        key_shifts.append(best_shift)

    return key_shifts


def decrypt_vigenere(cipher_text, key_shifts, alphabet=ALPHABET):
    result = []
    key_length = len(key_shifts)
    letter_index = 0  # Отслеживаем позицию в ключе

    for char in cipher_text:
        if char.lower() in alphabet:
            shift = key_shifts[letter_index % key_length]  # Берем соответствующий сдвиг
            idx = alphabet.index(char.lower())  # Индекс символа в алфавите
            new_idx = (idx - shift) % len(alphabet)  # Вычисляем расшифрованный индекс
            new_char = alphabet[new_idx]
            result.append(new_char.upper() if char.isupper() else new_char)  # Сохраняем регистр
        else:
            result.append(char)  # Не изменяем пробелы, знаки, цифры

        letter_index += 1  # Увеличиваем индекс

    return "".join(result)


# ---------- Функции для построения диаграмм частот ----------

def get_bigrams(text):
    """
    Формирует список биграмм (двухсимвольных комбинаций) из очищенного текста.
    """
    text = clean_text(text)
    return [text[i:i + 2] for i in range(len(text) - 1)]


def plot_top_letters(text, ax):
    """
    Строит столбчатую диаграмму для 10 наиболее встречаемых букв.
    """
    cleaned = clean_text(text)
    freq = Counter(cleaned)
    top10 = freq.most_common(10)
    if top10:
        letters, counts = zip(*top10)
    else:
        letters, counts = [], []
    ax.clear()
    ax.bar(letters, counts, color='skyblue')
    ax.set_title("Топ 10 букв")
    ax.set_ylabel("Количество")
    ax.figure.canvas.draw()


def plot_top_bigrams(text, ax):
    """
    Строит столбчатую диаграмму для 10 наиболее встречаемых биграмм.
    """
    bigrams = get_bigrams(text)
    freq = Counter(bigrams)
    top10 = freq.most_common(10)
    if top10:
        bigram_list, counts = zip(*top10)
    else:
        bigram_list, counts = [], []
    ax.clear()
    ax.bar(bigram_list, counts, color='lightgreen')
    ax.set_title("Топ 10 биграмм")
    ax.set_ylabel("Количество")
    ax.figure.canvas.draw()


# ---------- Виджеты для интерфейса ----------

class CaesarTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        btn_load = QPushButton("Загрузить файл (encC<...>.txt)")
        btn_load.clicked.connect(self.load_file)
        layout.addWidget(btn_load)

        self.text_cipher = QTextEdit()
        self.text_cipher.setPlaceholderText("Здесь отображается зашифрованный текст...")
        layout.addWidget(self.text_cipher)

        btn_analyze = QPushButton("Анализировать (Цезарь)")
        btn_analyze.clicked.connect(self.analyze)
        layout.addWidget(btn_analyze)

        self.label_key = QLabel("Найденный ключ: ")
        layout.addWidget(self.label_key)

        self.text_decrypted = QTextEdit()
        self.text_decrypted.setPlaceholderText("Здесь будет отображён расшифрованный текст...")
        layout.addWidget(self.text_decrypted)

        self.setLayout(layout)

    def load_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "r", encoding="utf-8") as f:
                content = f.read()
                self.text_cipher.setPlainText(content)

    def analyze(self):
        cipher_text = self.text_cipher.toPlainText()
        if not cipher_text.strip():
            return
        key = determine_caesar_key(cipher_text)
        decrypted = ceaser_decode(cipher_text, key)
        self.label_key.setText(f"Найденный ключ: {key}")
        self.text_decrypted.setPlainText(decrypted)


class VigenereTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Кнопка для загрузки зашифрованного текста
        btn_load = QPushButton("Загрузить файл (encV<...>.txt)")
        btn_load.clicked.connect(self.load_file)
        layout.addWidget(btn_load)

        # Текстовое поле для отображения зашифрованного текста
        self.text_cipher = QTextEdit()
        self.text_cipher.setPlaceholderText("Зашифрованный текст...")
        layout.addWidget(self.text_cipher)

        # Кнопка для анализа шифра Виженера
        btn_analyze = QPushButton("Анализировать и расшифровать (Виженер)")
        btn_analyze.clicked.connect(self.analyze)
        layout.addWidget(btn_analyze)

        # Метка для отображения длины ключа
        self.label_key = QLabel("Длина ключа и сдвиги: ")
        layout.addWidget(self.label_key)

        # Текстовое поле для отображения расшифрованного текста
        self.text_decrypted = QTextEdit()
        self.text_decrypted.setPlaceholderText("Расшифрованный текст...")
        layout.addWidget(self.text_decrypted)

        self.setLayout(layout)

    def load_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "r", encoding="utf-8") as f:
                content = f.read()
                self.text_cipher.setPlainText(content)

    def analyze(self):
        cipher_text = self.text_cipher.toPlainText()
        if not cipher_text.strip():
            return
        # Вычисляем длину ключа и сдвиги для шифра Виженера
        key_length = guess_vigenere_key_length(cipher_text)
        key_shifts = determine_vigenere_key(cipher_text, key_length)
        self.label_key.setText(f"Длина ключа: {key_length}, сдвиги: {key_shifts}")

        # Расшифровываем текст с использованием полученных сдвигов
        decrypted = decrypt_vigenere(cipher_text, key_shifts)
        self.text_decrypted.setPlainText(decrypted)


class FrequencyAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        btn_load = QPushButton("Загрузить большой текст")
        btn_load.clicked.connect(self.load_file)
        layout.addWidget(btn_load)

        self.text_area = QTextEdit()
        self.text_area.setPlaceholderText("Здесь отображается текст для частотного анализа...")
        layout.addWidget(self.text_area, stretch=1)

        charts_layout = QHBoxLayout()
        self.fig1, self.ax1 = plt.subplots(figsize=(4, 3))
        self.canvas1 = FigureCanvas(self.fig1)
        charts_layout.addWidget(self.canvas1)

        self.fig2, self.ax2 = plt.subplots(figsize=(4, 3))
        self.canvas2 = FigureCanvas(self.fig2)
        charts_layout.addWidget(self.canvas2)

        layout.addLayout(charts_layout)

        btn_plot = QPushButton("Построить диаграммы")
        btn_plot.clicked.connect(self.plot_charts)
        layout.addWidget(btn_plot)

        self.setLayout(layout)

    def load_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "r", encoding="utf-8") as f:
                content = f.read()
                self.text_area.setPlainText(content)

    def plot_charts(self):
        text = self.text_area.toPlainText()
        if not text.strip():
            return
        plot_top_letters(text, self.ax1)
        plot_top_bigrams(text, self.ax2)
        self.canvas1.draw()
        self.canvas2.draw()


# ---------- Основное окно приложения ----------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Программа криптоанализа")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        tabs = QTabWidget()
        tabs.addTab(CaesarTab(), "Цезарь")
        tabs.addTab(VigenereTab(), "Виженер")
        tabs.addTab(FrequencyAnalysisTab(), "Частотный анализ")
        self.setCentralWidget(tabs)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
