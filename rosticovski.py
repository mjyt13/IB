import sys
import string
import itertools
import time
from PySide6.QtWidgets import (
    QApplication, QDialog, QMainWindow, QWidget, QMessageBox,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QFormLayout
)
from users import load_users, save_users
from password_analysis import get_alphabet_power, calculate_combinations, brute_force_time, format_time
from password_cracking import dictionary_attack, brute_force_attack


# ------------------- Login Dialog --------------------
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход в систему")
        self.users = load_users()
        self.attempts = 0
        layout = QVBoxLayout()

        self.label_user = QLabel("Имя пользователя:")
        self.edit_user = QLineEdit()
        layout.addWidget(self.label_user)
        layout.addWidget(self.edit_user)

        self.label_pass = QLabel("Пароль:")
        self.edit_pass = QLineEdit()
        self.edit_pass.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.label_pass)
        layout.addWidget(self.edit_pass)

        # Кнопка для ручного ввода пароля
        self.btn_login = QPushButton("Войти")
        self.btn_login.clicked.connect(self.check_credentials)
        layout.addWidget(self.btn_login)

        # Новая кнопка для анализа устойчивости (брутфорс)
        self.btn_analysis = QPushButton("Анализ устойчивости (брутфорс)")
        self.btn_analysis.clicked.connect(self.run_stability_analysis)
        layout.addWidget(self.btn_analysis)

        self.setLayout(layout)

    def check_credentials(self):
        username = self.edit_user.text().strip()
        password = self.edit_pass.text()
        if username not in self.users:
            QMessageBox.warning(self, "Ошибка", "Пользователь не найден!")
            return
        user = self.users[username]
        if user.get("blocked", False):
            QMessageBox.critical(self, "Ошибка", "Учетная запись заблокирована!")
            self.reject()
            return
        if password != user["password"]:
            self.attempts += 1
            QMessageBox.warning(self, "Ошибка", f"Неверный пароль! Попыток: {self.attempts}")
            if self.attempts >= 3:
                QMessageBox.critical(self, "Ошибка", "Превышено число попыток. Программа завершает работу.")
                self.reject()
            return
        self.accept()

    def run_stability_analysis(self):
        username = self.edit_user.text().strip()
        # Анализ доступен только для пользователя ADMIN
        if username != "ADMIN":
            QMessageBox.warning(self, "Ошибка", "Анализ устойчивости доступен только для ADMIN!")
            return

        # Если пользователь не вводит пароль вручную, берём сохранённый пароль из файла пользователей
        target_password = self.users["ADMIN"]["password"]
        if not target_password:
            QMessageBox.warning(self, "Ошибка", "Пароль ADMIN не установлен!")
            return

        dlg = PasswordCrackDialog(target_password)
        result = dlg.exec()
        # Если диалог завершился успешно (пароль подобран)
        if result == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Успех", "Пароль подобран! Вход выполнен.")
            self.accept()

    def get_username(self):
        return self.edit_user.text().strip()


# ------------------- Admin Window --------------------
class AdminWindow(QMainWindow):
    def __init__(self, users):
        super().__init__()
        self.users = users
        self.setWindowTitle("Режим администратора")
        self.setMinimumSize(500, 400)
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()

        btn_change_pass = QPushButton("Сменить пароль администратора")
        btn_change_pass.clicked.connect(self.change_admin_password)

        btn_view_users = QPushButton("Просмотр списка пользователей")
        btn_view_users.clicked.connect(self.view_users)

        btn_add_user = QPushButton("Добавить нового пользователя")
        btn_add_user.clicked.connect(self.add_user)

        btn_block_user = QPushButton("Заблокировать пользователя")
        btn_block_user.clicked.connect(self.block_user)

        btn_restrict_user = QPushButton("Ограничить пользователя")
        btn_restrict_user.clicked.connect(self.restrict_user)

        btn_password_strength = QPushButton("Проверка надежности пароля")
        btn_password_strength.clicked.connect(self.check_password_strength)

        # Анализ устойчивости через брутфорс уже реализован в LoginDialog
        btn_exit = QPushButton("Завершить работу")
        btn_exit.clicked.connect(self.close)

        layout.addWidget(btn_change_pass)
        layout.addWidget(btn_view_users)
        layout.addWidget(btn_add_user)
        layout.addWidget(btn_block_user)
        layout.addWidget(btn_restrict_user)
        layout.addWidget(btn_password_strength)
        layout.addWidget(btn_exit)

        central.setLayout(layout)

    def change_admin_password(self):
        dlg = ChangePasswordDialog("ADMIN", self.users["ADMIN"])
        if dlg.exec():
            new_pass = dlg.new_password
            self.users["ADMIN"]["password"] = new_pass
            save_users(self.users)
            QMessageBox.information(self, "Успех", "Пароль администратора изменён.")

    def view_users(self):
        dlg = UsersListDialog(self.users)
        dlg.exec()

    def add_user(self):
        dlg = AddUserDialog(self.users)
        if dlg.exec():
            new_user = dlg.new_username
            if new_user in self.users:
                QMessageBox.warning(self, "Ошибка", "Такой пользователь уже существует!")
            else:
                self.users[new_user] = {
                    "username": new_user,
                    "password": "",
                    "blocked": False,
                    "password_restrictions": False
                }
                save_users(self.users)
                QMessageBox.information(self, "Успех", f"Пользователь {new_user} успешно добавлен.")

    def block_user(self):
        dlg = BlockUserDialog(self.users)
        if dlg.exec():
            target = dlg.username_to_block
            if target in self.users:
                self.users[target]["blocked"] = True
                save_users(self.users)
                QMessageBox.information(self, "Успех", f"Пользователь {target} заблокирован.")
            else:
                QMessageBox.warning(self, "Ошибка", "Пользователь не найден!")

    def restrict_user(self):
        dlg = RestrictUserDialog(self.users)
        if dlg.exec():
            target = dlg.username_to_block
            if target in self.users:
                self.users[target]["password_restrictions"] = True
                self.users[target]["password_power"] = dlg.username_power
                save_users(self.users)
                QMessageBox.information(self, "Успех", f"Пользователь {target} ограничен.")
            else:
                QMessageBox.warning(self, "Ошибка", "Пользователь не найден!")

    def check_password_strength(self):
        dlg = PasswordStrengthDialog()
        dlg.exec()


# ------------------- User Window --------------------
class UserWindow(QMainWindow):
    def __init__(self, username, users):
        super().__init__()
        self.username = username
        self.users = users
        self.setWindowTitle(f"Пользователь: {username}")
        self.setMinimumSize(400, 200)
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()

        btn_change_pass = QPushButton("Сменить пароль")
        btn_change_pass.clicked.connect(self.change_password)

        btn_exit = QPushButton("Завершить работу")
        btn_exit.clicked.connect(self.close)

        layout.addWidget(btn_change_pass)
        layout.addWidget(btn_exit)

        central.setLayout(layout)

    def change_password(self):
        dlg = ChangePasswordDialog(self.username, self.users[self.username])
        if dlg.exec():
            new_pass = dlg.new_password
            self.users[self.username]["password"] = new_pass
            save_users(self.users)
            QMessageBox.information(self, "Успех", "Пароль изменён.")


# ------------------- Change Password Dialog --------------------
class ChangePasswordDialog(QDialog):
    def __init__(self, username, user_data):
        super().__init__()
        self.setWindowTitle(f"Смена пароля для {username}")
        self.user_data = user_data
        self.new_password = None
        self.init_ui()

    def init_ui(self):
        layout = QFormLayout()
        if self.user_data["password"]:
            self.old_pass = QLineEdit()
            self.old_pass.setEchoMode(QLineEdit.EchoMode.Password)
            layout.addRow("Старый пароль:", self.old_pass)
        else:
            self.old_pass = None

        self.new_pass = QLineEdit()
        self.new_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pass = QLineEdit()
        self.confirm_pass.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addRow("Новый пароль:", self.new_pass)
        layout.addRow("Подтверждение:", self.confirm_pass)

        btn_ok = QPushButton("ОК")
        btn_ok.clicked.connect(self.accept_dialog)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addRow(btn_layout)
        self.setLayout(layout)

    def accept_dialog(self):
        if self.old_pass:
            if self.old_pass.text() != self.user_data["password"]:
                QMessageBox.warning(self, "Ошибка", "Неверный старый пароль!")
                return
        new_pwd = self.new_pass.text()
        confirm = self.confirm_pass.text()
        if new_pwd != confirm:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают!")
            return
        power = get_alphabet_power(new_pwd)
        if self.user_data.get("password_restrictions", False):
            required_power = self.user_data.get("password_power", 0)
            if power < required_power or len(new_pwd) < 8:
                QMessageBox.warning(self, "Ошибка",
                                    f"Пароль не удовлетворяет ограничениям! (Не менее мощности: {required_power} и длина не менее 8 символов)")
                return
        self.new_password = new_pwd
        self.accept()


# ------------------- Users List Dialog --------------------
class UsersListDialog(QDialog):
    def __init__(self, users):
        super().__init__()
        self.setWindowTitle("Список пользователей")
        self.users = users
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        for username, data in self.users.items():
            status = "Заблокирован" if data.get("blocked", False) else "Активен"
            restrictions = "ограничения включены" if data.get("password_restrictions",
                                                              False) else "ограничения отключены"
            item_text = f"{username} | {status} | {restrictions}"
            item = QListWidgetItem(item_text)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)
        btn_close = QPushButton("Закрыть")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)
        self.setLayout(layout)


# ------------------- Block User Dialog --------------------
class BlockUserDialog(QDialog):
    def __init__(self, users):
        super().__init__()
        self.setWindowTitle("Блокировка пользователя")
        self.users = users
        self.username_to_block = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.edit_username = QLineEdit()
        layout.addWidget(QLabel("Введите имя пользователя для блокировки:"))
        layout.addWidget(self.edit_username)
        btn_ok = QPushButton("ОК")
        btn_ok.clicked.connect(self.accept_dialog)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def accept_dialog(self):
        username = self.edit_username.text().strip()
        if not username:
            QMessageBox.warning(self, "Ошибка", "Имя не может быть пустым!")
            return
        self.username_to_block = username
        self.accept()


# ------------------- Restrict User Dialog --------------------
class RestrictUserDialog(QDialog):
    def __init__(self, users):
        super().__init__()
        self.setWindowTitle("Ограничение пользователя")
        self.users = users
        self.username_to_block = None
        self.username_power = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.edit_username = QLineEdit()
        layout.addWidget(QLabel("Введите имя пользователя для ограничения:"))
        layout.addWidget(self.edit_username)
        self.edit_example = QLineEdit()
        layout.addWidget(QLabel("Введите эталон пароля:"))
        layout.addWidget(self.edit_example)
        btn_ok = QPushButton("ОК")
        btn_ok.clicked.connect(self.accept_dialog)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def accept_dialog(self):
        username = self.edit_username.text().strip()
        if not username:
            QMessageBox.warning(self, "Ошибка", "Имя не может быть пустым!")
            return
        self.username_to_block = username
        example = self.edit_example.text().strip()
        if not example:
            QMessageBox.warning(self, "Ошибка", "Эталонный пароль не может быть пустым!")
            return
        self.username_power = get_alphabet_power(example)
        self.accept()


# ------------------- Add User Dialog --------------------
class AddUserDialog(QDialog):
    def __init__(self, users):
        super().__init__()
        self.setWindowTitle("Добавление пользователя")
        self.users = users
        self.new_username = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.edit_username = QLineEdit()
        layout.addWidget(QLabel("Введите имя нового пользователя:"))
        layout.addWidget(self.edit_username)
        btn_ok = QPushButton("Добавить")
        btn_ok.clicked.connect(self.accept_dialog)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def accept_dialog(self):
        username = self.edit_username.text().strip()
        if not username:
            QMessageBox.warning(self, "Ошибка", "Имя пользователя не может быть пустым!")
            return
        if username in self.users:
            QMessageBox.warning(self, "Ошибка", "Такой пользователь уже существует!")
            return
        self.new_username = username
        self.accept()


# ------------------- Password Strength Dialog --------------------
class PasswordStrengthDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Проверка надежности пароля")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.edit_password = QLineEdit()
        layout.addWidget(QLabel("Введите пароль для оценки:"))
        layout.addWidget(self.edit_password)
        btn_check = QPushButton("Проверить")
        btn_check.clicked.connect(self.check_strength)
        layout.addWidget(btn_check)
        self.setLayout(layout)

    def check_strength(self):
        password = self.edit_password.text()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Пароль не может быть пустым!")
            return
        power = get_alphabet_power(password)
        combinations = calculate_combinations(len(password), power)
        s, m, v = 1000, 5, 1
        time_needed = brute_force_time(combinations, s, m, v)
        formatted = format_time(time_needed)
        QMessageBox.information(self, "Результат",
                                f"Мощность алфавита: {power}\n"
                                f"Количество комбинаций: {combinations:,}\n"
                                f"Время полного перебора: {formatted}")


# ------------------- Password Crack Dialog --------------------
class PasswordCrackDialog(QDialog):
    def __init__(self, target_password):
        super().__init__()
        self.setWindowTitle("Анализ устойчивости пароля")
        self.target_password = target_password
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Брутфорс пароля"))
        self.btn_dictionary = QPushButton("Подбор по словарю")
        self.btn_dictionary.clicked.connect(self.run_dictionary_attack)
        self.btn_bruteforce = QPushButton("Полный перебор")
        self.btn_bruteforce.clicked.connect(self.run_bruteforce_attack)
        self.edit_max_length = QLineEdit()
        self.edit_max_length.setPlaceholderText("Максимальная длина перебора (например, 6)")
        layout.addWidget(self.btn_dictionary)
        layout.addWidget(self.btn_bruteforce)
        layout.addWidget(self.edit_max_length)
        self.setLayout(layout)

    def load_dictionary(self):
        try:
            with open("resources/Dictionary.txt", "r", encoding="utf-8") as f:
                content = f.read().strip()
                if "," in content:
                    words = content.split(",")
                else:
                    words = content.split()
                return words
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить словарь: {e}")
            return []

    def run_dictionary_attack(self):
        dictionary = self.load_dictionary()
        result = dictionary_attack(self.target_password, dictionary)
        if result["found_word"]:
            QMessageBox.information(self, "Результат",
                                    f"[Словарный перебор]\nНайдено слово: {result['found_word']}\n"
                                    f"Попыток: {result['attempts']}\n"
                                    f"Время: {result['time']:.2f} сек\n"
                                    f"Средняя скорость: {result['speed']:.2f} попыток/сек")
            self.accept()
        else:
            QMessageBox.information(self, "Результат", "Пароль не найден методом словаря.")

    def run_bruteforce_attack(self):
        try:
            max_length = int(self.edit_max_length.text())
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректное число для максимальной длины!")
            return
        alphabet = string.ascii_lowercase + string.digits
        result = brute_force_attack(self.target_password, max_length, alphabet)
        if result["found_password"]:
            QMessageBox.information(self, "Результат",
                                    f"[Полный перебор]\nПароль найден: {result['found_password']}\n"
                                    f"Попыток: {result['attempts']}\n"
                                    f"Время: {result['time']:.2f} сек\n"
                                    f"Средняя скорость: {result['speed']:.2f} попыток/сек")
            self.accept()
        else:
            QMessageBox.information(self, "Результат", "Пароль не найден в заданном диапазоне длин.")


# ------------------- Start Application --------------------
def start_app():
    login = LoginDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        username = login.get_username()
        users = load_users()
        if username == "ADMIN":
            window = AdminWindow(users)
        else:
            window = UserWindow(username, users)
        window.show()
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        sys.exit(app.exec())


if __name__ == "__main__":
    start_app()
