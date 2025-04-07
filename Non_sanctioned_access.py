from users import save_users,get_users
import sys
import string,itertools, time
from Passwords_Power import password_power, reformat_time
from password_crack import RUS_TO_LAT,rus_to_qwerty
from PySide6.QtWidgets import (
    QApplication, QDialog, QMainWindow, QWidget, QMessageBox,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
)
from PySide6.QtCore import QTimer



# Вот это окно используется при Первой регистрации и Смене пароля
class ConfirmPasswordDialog(QDialog):
    def __init__(self,password):
        super().__init__()
        self.setWindowTitle("Подтверждение")

        layout = QVBoxLayout()

        self.password = password
        layout_password = QHBoxLayout()
        self.label_password = QLabel("Пароль")
        self.lineedit_password = QLineEdit()
        self.lineedit_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout_password.addWidget(self.label_password)
        layout_password.addWidget(self.lineedit_password)

        self.btn_login = QPushButton("Подтвердить")
        self.btn_login.clicked.connect(self.check_input)

        layout.addLayout(layout_password)
        layout.addWidget(self.btn_login)

        self.setLayout(layout)

    def check_input(self):
        correct_password = self.password
        possible_password = self.lineedit_password.text()
        if possible_password != correct_password:
            QMessageBox.warning(self,"Ошибка","Введённые пароли не совпадают")
            return
        else:
            QMessageBox.information(self,"Успех","Пароль подтверждён")
            self.accept()
            return
# Начальное окно входа (3 попытки, проверка на существование)
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход")
        # Словарь из JSON файла
        self.users = get_users()

        layout = QVBoxLayout()

        self.username = None
        layout_username = QHBoxLayout()
        self.label_username = QLabel("Имя")
        self.lineedit_username = QLineEdit()
        layout_username.addWidget(self.label_username)
        layout_username.addWidget(self.lineedit_username)

        self.password = None
        layout_password = QHBoxLayout()
        self.label_password = QLabel("Пароль")
        self.lineedit_password = QLineEdit()
        self.lineedit_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout_password.addWidget(self.label_password)
        layout_password.addWidget(self.lineedit_password)

        self.btn_login = QPushButton("Вход")
        self.btn_login.clicked.connect(self.check_input)

        self.btn_bruteforce = QPushButton("Полный перебор (поиск пароля ADMIN)")
        self.btn_bruteforce.clicked.connect(self.bruteforce_attack)

        self.btn_dictattack = QPushButton("Подбор по словарь(поиск пароля ADMIN)")
        self.btn_dictattack.clicked.connect(self.dictionary_attack)

        layout.addLayout(layout_username)
        layout.addLayout(layout_password)
        layout.addWidget(self.btn_login)
        layout.addWidget(self.btn_bruteforce)
        layout.addWidget(self.btn_dictattack)

        self.setLayout(layout)
        self.attempt = 0

    def check_input(self):
        username = self.lineedit_username.text()
        password = self.lineedit_password.text()

        if username not in self.users:
            QMessageBox.warning(self,"Ошибка","Такого пользователя не существует")
            return
        # Обратиться к элементу словаря (индексация то бижь)
        user = self.users[username]
        if user.get("banned",True):
            QMessageBox.critical(self,"Ошибка","Пользователь заблокирован")
            self.reject()
            return
        if user["password"] != "":
            if password != user["password"]:
                self.attempt += 1
                if self.attempt < 3:
                    msg_box = QMessageBox()
                    msg_box.setIcon(QMessageBox.Warning)
                    msg_box.setText("Неправильный пароль")
                    msg_box.setWindowTitle("Ошибка")
                    msg_box.setStandardButtons(QMessageBox.Ok)

                    QTimer.singleShot(00, msg_box.close)
                    msg_box.exec()
                    return "wrong"
                else:
                    msg_box = QMessageBox()
                    msg_box.setIcon(QMessageBox.Critical)
                    msg_box.setText("Превышено число попыток входа")
                    msg_box.setWindowTitle("Ошибка")
                    msg_box.setStandardButtons(QMessageBox.Ok)

                    QTimer.singleShot(00, msg_box.close)
                    msg_box.exec()
                    # QMessageBox.critical(self,"Ошибка", "Превышено число попыток входа")
                    self.attempt = 0
                    return "pause"
        else:
            if password.strip() == "":
                QMessageBox.warning(self,"Внимание","Пароль не может быть пустым")
                return
            """Пусть здесь тоже будет проверка пароля"""
            restrictions = user["restrictions"]
            #  Поля, обозначающие присутствие символа из группы
            digits = False
            lower_letters = False
            upper_letters = False
            special = False
            for symbol in password:
                if symbol.isdigit():
                    digits = True
                if symbol.isupper():
                    upper_letters = True
                if symbol.islower():
                    lower_letters = True
                if not (symbol.islower()) and not (symbol.isupper()) and not (symbol.isdigit()):
                    special = True
            if restrictions["digits"] and not digits:
                QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать цифры")
                return
            if restrictions["upper_letters"] and not upper_letters:
                QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать буквы верхнего регистра")
                return
            if restrictions["lower_letters"] and not lower_letters:
                QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать буквы нижнего регистра")
                return
            if restrictions["special"] and not special:
                QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать особые символы")
                return

            if len(password.strip()) < 6:
                QMessageBox.warning(self,"Внимание","Пароль слишком короткий")
                return
            QMessageBox.information(self,"Внимание",
                                    "Необходимо подтвердить пароль для завершения регистрации")
            confirming = ConfirmPasswordDialog(password)
            if confirming.exec() == QDialog.DialogCode.Accepted:
                print(f"удалось авторизовать {username}")
                # сохранить пароль того, кто зарегался
                self.users[username]["password"] = password
                save_users(self.users)
            else:
                print(confirming.exec())
                print(f"чёто {username} не логиниться")
                return

        # Удалось войти
        self.username = username
        self.password = password
        self.accept()
        return "right"

    def bruteforce_attack(self):

        self.lineedit_username.setText("ADMIN")
        alphabet = string.ascii_lowercase + string.digits
        start_time = time.perf_counter()
        attempts = 0
        max_length = 6
        for length in range(1, max_length + 1):
            for candidate in itertools.product(alphabet, repeat=length):
                iteration_start = time.perf_counter()
                attempts += 1
                attempt = "".join(candidate)
                print(attempt, end=" ")
                self.lineedit_password.setText(attempt)
                # QMessageBox.information(self,"tech","started")
                result = self.check_input()

                if result == "wrong":
                    print(f"doesn't seem right {attempt}")
                if result == "wrong pause":
                    # time.sleep(0.2)
                    print(f"doesn't seem right {attempt}, also need pause")
                if result == "right":
                    elapsed = time.perf_counter() - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    QMessageBox.information(self, "Результат",
                                            f"[Полный перебор]\nПароль найден: {attempt}\n"
                                            f"Попыток: {attempts}\n"
                                            f"Время: {elapsed:.2f} сек\n"
                                            f"Средняя скорость: {speed:.2f} попыток/сек")
                    return

        elapsed = time.perf_counter() - start_time
        QMessageBox.information(self, "Результат", "Пароль не найден в заданном диапазоне длин.")
        return

    def load_dictionary(self):
        try:
            with open("Dictionary2.txt", "r", encoding="utf-8") as f:
                content = f.read().strip()
                if "," in content:
                    words = content.split(",")
                else:
                    words = content.split()
                return words
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить словарь: {e}")
            return []

    def dictionary_attack(self):
        attempts = 0
        self.lineedit_username.setText("ADMIN")
        start_time = time.perf_counter()
        dictionary = self.load_dictionary()

        for word in dictionary:
            attempt_start = time.perf_counter()
            attempts += 1

            attempt = rus_to_qwerty(word)
            self.lineedit_password.setText(attempt)

            result = self.check_input()
            # Преобразуем слово в QWERTY-раскладку и сравниваем с целевым паролем
            if result == "wrong":
                print(f"doesn't seem right {attempt}")
            if result == "wrong pause":
                # time.sleep(0.2)
                print(f"doesn't seem right {attempt}, also need pause")
            if result == "right":
                elapsed = time.perf_counter() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                QMessageBox.information(self, "Результат",
                                        f"[Полный перебор]\nПароль найден: {attempt}\n"
                                        f"Попыток: {attempts}\n"
                                        f"Время: {elapsed:.2f} сек\n"
                                        f"Средняя скорость: {speed:.2f} попыток/сек")
                return

        elapsed = time.perf_counter() - start_time
        QMessageBox.information(self, "Результат", "Пароль не найден методом словаря.")
        return


# А что юзер может сделать? (сменить пароль или выйти)
class UserMain(QMainWindow):
    def __init__(self,username):
        super().__init__()
        self.users = get_users()
        self.username = username
        self.setWindowTitle(f"Работа пользователя {self.username}")

        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout()

        btn_password_change = QPushButton("Сменить пароль")
        btn_password_change.clicked.connect(self.password_change)

        btn_close = QPushButton("Закончить работу")
        btn_close.clicked.connect(self.close)

        layout.addWidget(btn_password_change)
        layout.addWidget(btn_close)

        widget.setLayout(layout)

    def password_change(self):

        changing = ChangePasswordDialog(self.username)
        if changing.exec() == QDialog.DialogCode.Accepted:
            return

# А вот админ пусть ебенит
class AdminMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.users = get_users()
        self.setWindowTitle(f"Работа администратора")

        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout()

        btn_password_change = QPushButton("Сменить пароль")
        btn_password_change.clicked.connect(self.password_change)

        btn_users_check = QPushButton("Просмотреть список пользователей")
        btn_users_check.clicked.connect(self.check_users)

        btn_user_create = QPushButton("Создать пользователя")
        btn_user_create.clicked.connect(self.user_create)

        btn_user_ban = QPushButton("Заблокировать пользователя")
        btn_user_ban.clicked.connect(self.user_ban)

        btn_user_restrict = QPushButton("Ограничить пароль пользователя")
        btn_user_restrict.clicked.connect(self.user_restrict)

        btn_check_password = QPushButton("Проверить надёжность пароля")
        btn_check_password.clicked.connect(self.check_password_strenght)

        btn_close = QPushButton("Закончить работу")
        btn_close.clicked.connect(self.close)

        layout.addWidget(btn_password_change)
        layout.addWidget(btn_users_check)
        layout.addWidget(btn_user_create)
        layout.addWidget(btn_user_ban)
        layout.addWidget(btn_user_restrict)
        layout.addWidget(btn_check_password)
        layout.addWidget(btn_close)

        widget.setLayout(layout)

    def password_change(self):
        changing = ChangePasswordDialog("ADMIN")
        if changing.exec() == QDialog.DialogCode.Accepted:
            return

    def check_users(self):
        checking = CheckUsersDialog()
        if checking.exec() == QDialog.DialogCode.Accepted:
            return
        return

    def user_create(self):
        creating = CreateUserDialog()
        if creating.exec() == QDialog.DialogCode.Accepted:
            return

    def user_ban(self):
        banning = BanUserDialog()
        if banning.exec() == QDialog.DialogCode.Accepted:
            return

    def user_restrict(self):
        restricting = RestrictUserDialog()
        if restricting.exec() == QDialog.DialogCode.Accepted:
            return

    def check_password_strenght(self):
        checking_password = CheckPasswordDialog()
        checking_password.exec()
        return

# Смена пароля (доступна всем)
class ChangePasswordDialog(QDialog):
    def __init__(self,username):
        super().__init__()

        self.username = username
        self.setWindowTitle(f"Смена пароля для пользователя {username}")
        self.new_password = None

        layout = QVBoxLayout()

        layout_old_password = QHBoxLayout()
        self.old_password_label = QLabel("Прежний пароль")
        self.old_password_lineedit = QLineEdit()
        self.old_password_lineedit.setEchoMode(QLineEdit.EchoMode.Password)
        layout_old_password.addWidget(self.old_password_label)
        layout_old_password.addWidget(self.old_password_lineedit)

        layout_new_password = QHBoxLayout()
        self.new_password_label = QLabel("Новый пароль")
        self.new_password_lineedit = QLineEdit()
        self.new_password_lineedit.setEchoMode(QLineEdit.EchoMode.Password)
        layout_new_password.addWidget(self.new_password_label)
        layout_new_password.addWidget(self.new_password_lineedit)

        self.change_password = QPushButton("Сменить пароль")
        self.change_password.clicked.connect(self.validate_data)

        layout.addLayout(layout_old_password)
        layout.addLayout(layout_new_password)
        layout.addWidget(self.change_password)

        self.setLayout(layout)

        self.users = get_users()

    def validate_data(self):
        old_password = self.old_password_lineedit.text()
        """
        Сделать проверку пароля
        """
        user = self.users[self.username]
        if old_password != user["password"]:
            QMessageBox.critical(self,"Ошибка","Введён неверный пароль, смена невозможна")
            return

        new_password = self.new_password_lineedit.text()

        # Отвергнуть пароль
        restrictions = user["restrictions"]
        #  Поля, обозначающие присутствие символа из группы
        digits = False; lower_letters = False; upper_letters = False; special = False
        for symbol in new_password:
            if symbol.isdigit():
                digits = True
            if symbol.isupper() :
                upper_letters = True
            if symbol.islower():
                lower_letters = True
            if not(symbol.islower()) and not(symbol.isupper()) and not(symbol.isdigit()):
                special = True
        if restrictions["digits"] and not digits:
            QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать цифры")
            return
        if restrictions["upper_letters"] and not upper_letters:
            QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать буквы верхнего регистра")
            return
        if restrictions["lower_letters"] and not lower_letters:
            QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать буквы нижнего регистра")
            return
        if restrictions["special"] and not special:
            QMessageBox.warning(self, "Внимание", "В пароле необходимо использовать особые символы")
            return


        # Не отвергнулся пароль, придётся подтверждать
        if new_password.strip() == "":
            QMessageBox.warning(self, "Внимание", "Пароль не может быть пустым")
            return
        if len(new_password.strip()) < 2:
            QMessageBox.warning(self, "Внимание", "Пароль слишком короткий")
            return
        QMessageBox.information(self,"Внимание","Необходимо подтвердить пароль")
        confirming = ConfirmPasswordDialog(new_password)
        if confirming.exec() == QDialog.DialogCode.Accepted:
            self.users[self.username]["password"] = new_password
            save_users(self.users)
            self.accept()

# Дальше только админские функции
# Первая - проверить список существующих пользователей
class CheckUsersDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.users = get_users()
        self.setWindowTitle("Просмотр списка пользователей")

        layout = QVBoxLayout()

        # тут обозначения
        point_layout = QHBoxLayout()
        username = QLabel("Имя пользователя")
        banned = QLabel("Заблокирован")
        password_digits = QLabel("Цифры в пароле")
        password_lower_letters = QLabel("Строчные буквы в пароле")
        password_upper_letters = QLabel("Заглавные буквы в пароле")
        password_special = QLabel("Остальные символы в пароле")
        point_layout.addWidget(username)
        point_layout.addWidget(banned)
        point_layout.addWidget(password_digits)
        point_layout.addWidget(password_lower_letters)
        point_layout.addWidget(password_upper_letters)
        point_layout.addWidget(password_special)

        layout.addLayout(point_layout)

        # а тут уже наполнение
        keys = []
        for user in self.users:
            keys.append(user)
        # сначала были ключи, а вот теперь наполнение
        for key in keys:
            user_layout = QHBoxLayout()
            user = self.users[key]
            username = QLabel(user["username"])
            if user["banned"]:
                banned = QLabel("Да")
            else:
                banned = QLabel("Нет")
            restrictions = user["restrictions"]
            if not restrictions["digits"]:
                password_digits = QLabel("Опциональны")
            else:
                password_digits = QLabel("Обязательны")

            if not restrictions["lower_letters"]:
                password_lower_letters = QLabel("Опциональны")
            else:
                password_lower_letters = QLabel("Обязательны")

            if not restrictions["upper_letters"]:
                password_upper_letters = QLabel("Опциональны")
            else:
                password_upper_letters = QLabel("Обязательны")

            if not restrictions["special"]:
                password_special = QLabel("Опциональны")
            else:
                password_special = QLabel("Обязательны")

            user_layout.addWidget(username)
            user_layout.addWidget(banned)
            user_layout.addWidget(password_digits)
            user_layout.addWidget(password_lower_letters)
            user_layout.addWidget(password_upper_letters)
            user_layout.addWidget(password_special)
            layout.addLayout(user_layout)

        self.btn_accept = QPushButton("ОК")
        self.btn_accept.clicked.connect(self.close)

        layout.addWidget(self.btn_accept)

        self.setLayout(layout)
# Вторая - создать пользоваателя
class CreateUserDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.users = get_users()
        self.setWindowTitle(f"Создание пользователя")

        layout = QVBoxLayout()

        layout_new_user = QHBoxLayout()
        self.new_user_label = QLabel("Имя пользователя")
        self.new_user_lineedit = QLineEdit()
        layout_new_user.addWidget(self.new_user_label)
        layout_new_user.addWidget(self.new_user_lineedit)

        self.btn_confirm = QPushButton("Добавить пользователя")
        self.btn_confirm.clicked.connect(self.create_user)

        self.btn_reject = QPushButton("Отмена")
        self.btn_reject.clicked.connect(self.reject)

        layout.addLayout(layout_new_user)
        layout.addWidget(self.btn_confirm)
        layout.addWidget(self.btn_reject)
        self.setLayout(layout)

    def create_user(self):
        new_user = self.new_user_lineedit.text()
        if new_user == "":
            QMessageBox.warning(self, "Ошибка", "Недопустимое имя пользователя (пустое имя)")
            return
        if new_user in self.users:
            QMessageBox.warning(self,"Ошибка","Такой пользователь уже существует")
            return

        QMessageBox.information(self,"Успех",f"Пользователь {new_user} создан")
        restrictions = {
            "lower_letters": True,
            "upper_letters": True,
            "digits": True,
            "special": True
        }
        self.users[new_user] = {
            "username": new_user,
            "password": "",
            "banned": False,
            "restrictions": restrictions
        }

        save_users(self.users)
        print(f"created user {new_user}")

        self.accept()
# Третья - заблокировать пользователя
class BanUserDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.users = get_users()
        self.setWindowTitle(f"Блокирование пользователя")
        layout = QVBoxLayout()

        layout_ban_user = QHBoxLayout()
        self.ban_user_label = QLabel("Имя пользователя")
        self.ban_user_lineedit = QLineEdit()
        layout_ban_user.addWidget(self.ban_user_label)
        layout_ban_user.addWidget(self.ban_user_label)

        self.btn_confirm = QPushButton("Заблокировать пользователя")
        self.btn_confirm.clicked.connect(self.ban_user)

        self.btn_reject = QPushButton("Отмена")
        self.btn_reject.clicked.connect(self.close)

        layout.addWidget(self.ban_user_label)
        layout.addWidget(self.ban_user_lineedit)
        layout.addWidget(self.btn_confirm)
        layout.addWidget(self.btn_reject)

        self.setLayout(layout)

    def ban_user(self):
        ban_username = self.ban_user_lineedit.text()
        if ban_username not in self.users:
            QMessageBox.warning(self,"Ошибка","Такого пользователя не существует")
            return
        if ban_username == "ADMIN":
            QMessageBox.warning(self,"Ошибка","Администратор не может быть заблокирован")
            return

        ban_user = self.users[ban_username]
        ban_user["banned"] = True
        save_users(self.users)
        self.accept()
        return
# Четвертая - ограничить пароль пользователя
class RestrictUserDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.users = get_users()
        self.setWindowTitle(f"Ограничение пароля пользователя")

        layout = QVBoxLayout()

        layout_new_user = QHBoxLayout()
        self.new_user_label = QLabel("Введите имя пользователя")
        self.new_user_lineedit = QLineEdit()
        layout_new_user.addWidget(self.new_user_label)
        layout_new_user.addWidget(self.new_user_lineedit)

        self.btn_confirm = QPushButton("Выбрать пользователя")
        self.btn_confirm.clicked.connect(self.restrict_user)

        layout.addLayout(layout_new_user)
        layout.addWidget(self.btn_confirm)

        self.setLayout(layout)

    def restrict_user(self):
        restrict_user = self.new_user_lineedit.text()
        if restrict_user not in self.users:
            QMessageBox.warning(self,"Ошибка","Такого пользователя не существует")
            return
        # пошёл пароль
        restrict_password = None
        while restrict_password is None or restrict_password.exec() != QDialog.DialogCode.Rejected:
            restrict_password = RestrictPasswordDialog(restrict_user)
        if restrict_password.exec()== QDialog.DialogCode.Rejected:
            QMessageBox.information(self,"Успех","Ограничение завершено")
        return
   # Вспомогательное окно  для ограничения
class RestrictPasswordDialog(QDialog):
    def __init__(self,key_username):
        super().__init__()
        self.users = get_users()
        self.setWindowTitle(f"Ограничение пароля пользователя {key_username}")

        layout = QVBoxLayout()

        self.username = key_username
        self.user = self.users[key_username]
        username = QLabel(self.user["username"])
        restrictions_label = QLabel("Ограничения")
        point_layout = QHBoxLayout()
        point_layout.addWidget(username)
        point_layout.addWidget(restrictions_label)

        layout.addLayout(point_layout)

        restrictions = self.user["restrictions"]

        digits_layout = QHBoxLayout()
        digits_label = QLabel("Цифры")
        if restrictions["digits"]:
            self.digits_allowed = QLabel("Разрешены")
            self.digits_change_button = QPushButton("Запретить")
        else:
            self.digits_allowed = QLabel("Запрещены")
            self.digits_change_button = QPushButton("Разрешить")
        self.digits_change_button.clicked.connect(self.change_digits)
        digits_layout.addWidget(digits_label)
        digits_layout.addWidget(self.digits_allowed)
        digits_layout.addWidget(self.digits_change_button)

        lower_letters_layout = QHBoxLayout()
        lower_letters_label = QLabel("Заглавные буквы")
        if restrictions["lower_letters"]:
            self.lower_letters_allowed = QLabel("Разрешены")
            self.lower_letters_change_button = QPushButton("Запретить")
        else:
            self.lower_letters_allowed = QLabel("Запрещены")
            self.lower_letters_change_button = QPushButton("Разрешить")
        self.lower_letters_change_button.clicked.connect(self.change_lower)
        lower_letters_layout.addWidget(lower_letters_label)
        lower_letters_layout.addWidget(self.lower_letters_allowed)
        lower_letters_layout.addWidget(self.lower_letters_change_button)

        upper_letters_layout = QHBoxLayout()
        upper_letters_label = QLabel("Строчные буквы")
        if restrictions["upper_letters"]:
            self.upper_letters_allowed = QLabel("Разрешены")
            self.upper_letters_change_button = QPushButton("Запретить")
        else:
            self.upper_letters_allowed = QLabel("Запрещены")
            self.upper_letters_change_button = QPushButton("Разрешить")
        self.upper_letters_change_button.clicked.connect(self.change_upper)
        upper_letters_layout.addWidget(upper_letters_label)
        upper_letters_layout.addWidget(self.upper_letters_allowed)
        upper_letters_layout.addWidget(self.upper_letters_change_button)

        special_layout = QHBoxLayout()
        special_label = QLabel("Особые символы")
        if restrictions["special"]:
            self.special_allowed = QLabel("Разрешены")
            self.special_change_button = QPushButton("Запретить")
        else:
            self.special_allowed = QLabel("Запрещены")
            self.special_change_button = QPushButton("Разрешить")
        self.special_change_button.clicked.connect(self.change_special)
        special_layout.addWidget(special_label)
        special_layout.addWidget(self.special_allowed)
        special_layout.addWidget(self.special_change_button)

        self.btn_close = QPushButton("Завершить процесс ограничения")
        self.btn_close.clicked.connect(self.close_dialog)

        layout.addLayout(digits_layout)
        layout.addLayout(lower_letters_layout)
        layout.addLayout(upper_letters_layout)
        layout.addLayout(special_layout)
        layout.addWidget(self.btn_close)

        self.setLayout(layout)

    def change_digits(self):
        restrictions = self.user["restrictions"]
        if restrictions["digits"]:
            restrictions["digits"] = False
        else:
            restrictions["digits"] = True
        save_users(self.users)
        self.accept()
        self.close()
        return

    def change_lower(self):
        restrictions = self.user["restrictions"]
        if restrictions["lower_letters"]:
            restrictions["lower_letters"] = False
        else:
            restrictions["lower_letters"] = True
        save_users(self.users)
        self.accept()
        self.close()
        return

    def change_upper(self):
        restrictions = self.user["restrictions"]
        if restrictions["upper_letters"]:
            restrictions["upper_letters"] = False
        else:
            restrictions["upper_letters"] = True
        save_users(self.users)
        self.accept()
        self.close()
        return

    def change_special(self):
        restrictions = self.user["restrictions"]
        if restrictions["special"]:
            restrictions["special"] = False
        else:
            restrictions["special"] = True
        save_users(self.users)
        self.accept()
        self.close()
        return

    def close_dialog(self):
        self.reject()
        self.close()
        return

# Дополнительная функция, слабо относимая к функционалу - подбор пароля по словарю

# Дополнительная функция 2, слабо относимая к функционалу - анализ сложности пароля
class CheckPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Проверка надёжности пароля")
        layout = QVBoxLayout()
        password_label = QLabel("Введите пароль для оценки")
        self.password_lineedit = QLineEdit()
        btn_analyze_password = QPushButton("Проверить")
        btn_analyze_password.clicked.connect(self.analyze_password)

        layout.addWidget(password_label)
        layout.addWidget(self.password_lineedit)
        layout.addWidget(btn_analyze_password)

        self.setLayout(layout)

    def analyze_password(self):
        password = self.password_lineedit.text()
        if not password:
            QMessageBox.warning(self,"Ошибка","Пароль пуст")
            return
        pswrd_power = password_power(password,587,10,0)
        power = pswrd_power[1]
        time = pswrd_power[0]
        alphabet = pswrd_power[2]
        needed_time = reformat_time(time)
        QMessageBox.information(self,"Результат",
                                f"Величина алфавита равна {alphabet}\n"
                                f"Мощность пространства равна {power}\n"
                                f"Время перебора равно {needed_time}")
        return

# запуск программы

app = QApplication(sys.argv)
login = LoginDialog()
if login.exec() == QDialog.DialogCode.Accepted:
    used_username = login.username

    used_password = login.password

    if used_username == "ADMIN":
        window = AdminMain()
    else:
        window = UserMain(used_username)
    window.show()
    sys.exit(app.exec())
else:
    sys.exit(0)
