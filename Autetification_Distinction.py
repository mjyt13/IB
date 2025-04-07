import sys, os, json
from PySide6.QtWidgets import (
    QApplication, QDialog, QMainWindow, QWidget, QMessageBox,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QFormLayout
)



USER_FILE = "users.json"
MAX_ATTEMPTS = 3

def get_alphabet_power(password):
    """ Определение мощности алфавита на основе введенного пароля """
    lower = upper = digits = special = 0
    for char in password:
        if char.isdigit():
            digits = 10
        elif char.islower():
            lower = 26
        elif char.isupper():
            upper = 26
        else:
            special = 33

    return lower + upper + digits + special


def load_users():
    """Загружает пользователей из файла или создаёт файл с администратором по умолчанию."""
    if not os.path.exists(USER_FILE):
        admin = {
            "username": "ADMIN",
            "password": "",
            "blocked": False,
            "password_restrictions": False
        }
        users = {"ADMIN": admin}
        with open(USER_FILE, "w") as f:
            json.dump(users, f, indent=4)
        return users
    with open(USER_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    """Сохраняет данные пользователей в файл."""
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)


# вход
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

        self.btn_login = QPushButton("Войти")
        self.btn_login.clicked.connect(self.check_credentials)
        layout.addWidget(self.btn_login)

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
            if self.attempts >= MAX_ATTEMPTS:
                QMessageBox.critical(self, "Ошибка", "Превышено число попыток. Программа завершает работу.")
                self.reject()
            return

        self.accept()

    def get_username(self):
        return self.edit_user.text().strip()


# ---------------------- Окно администратора -------------------------
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

        # Кнопки верхнего меню
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

        btn_exit = QPushButton("Завершить работу")
        btn_exit.clicked.connect(self.close)

        layout.addWidget(btn_change_pass)
        layout.addWidget(btn_view_users)
        layout.addWidget(btn_add_user)
        layout.addWidget(btn_block_user)
        layout.addWidget(btn_restrict_user)
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
                    "password": "",  # пустой пароль
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


# ---------------------- Окно обычного пользователя -------------------------
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


# ---------------------- Диалог смены пароля -------------------------
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
        if self.user_data.get("password_restrictions", False) and power < self.user_data.get("password_power") and len(new_pwd) < 8:
            QMessageBox.warning(self, "Ошибка",
                                f"Пароль не удовлетворяет ограничениям"
                                f" (мощность должна быть не меньше {self.user_data.get("password_power")})")
            return
        if self.user_data.get("password_restrictions", False) and len(new_pwd) < 8:
            QMessageBox.warning(self, "Ошибка",
                                f"Пароль не удовлетворяет ограничениям (длина пароля не меньше 8!)")
            return
        self.new_password = new_pwd
        self.accept()


# ---------------------- Диалог просмотра списка пользователей -------------------------
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


# ---------------------- Диалог блокирования пользователя -------------------------
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
        if username == "":
            QMessageBox.warning(self, "Ошибка", "Имя не может быть пустым!")
            return
        self.username_to_block = username
        self.accept()


# ---------------------- Диалог ограничения пользователя -------------------------
class RestrictUserDialog(QDialog):

    def __init__(self, users):
        super().__init__()
        self.edit_username = None
        self.edit_example = None
        self.setWindowTitle("Ограничение пользователя")
        self.users = users
        self.username_to_block = None
        self.username_to_example = None
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
        if username == "":
            QMessageBox.warning(self, "Ошибка", "Имя не может быть пустым!")
            return
        self.username_to_block = username

        example = self.edit_example.text().strip()
        if example == "":
            QMessageBox.warning(self, "Ошибка", "Пример не может быть пустым!")
            return
        power = get_alphabet_power(example)
        self.username_power = power
        self.accept()


# ---------------------- Диалог добавления пользователя -------------------------
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
        if username == "":
            QMessageBox.warning(self, "Ошибка", "Имя пользователя не может быть пустым!")
            return
        if username in self.users:
            QMessageBox.warning(self, "Ошибка", "Такой пользователь уже существует!")
            return
        self.new_username = username
        self.accept()


# ---------------------- Главная функция -------------------------
def main():
    app = QApplication(sys.argv)
    login = LoginDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        username = login.get_username()
        users = load_users()
        # Если пользователь не найден или заблокирован — уже обработано в диалоге.
        if username == "ADMIN":
            window = AdminWindow(users)
        else:
            window = UserWindow(username, users)
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
