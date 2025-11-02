import os
import subprocess
import getpass
import crypt
from multiprocessing import shared_memory

SHM_NAME = "my_memory"
SHM_SIZE = 100  # Размер сегмента памяти

class Password:
    def __init__(self):
        self.user_info = self.read_shadow_file()
        self.setup_users_and_groups()

    def setup_users_and_groups(self):
        try:
            group_exists_rw = subprocess.run(['getent', 'group', 'rw_group'], capture_output=True, text=True)
            if group_exists_rw.returncode != 0:
                subprocess.run(['sudo', 'groupadd', 'rw_group'], check=True)
                print("Группа rw_group успешно создана.")
            else:
                print("Группа rw_group уже существует.")
            
            group_exists_read = subprocess.run(['getent', 'group', 'read_group'], capture_output=True, text=True)
            if group_exists_read.returncode != 0:
                subprocess.run(['sudo', 'groupadd', 'read_group'], check=True)
                print("Группа read_group успешно создана.")
            else:
                print("Группа read_group уже существует.")

            # создаем пользователя user3
            user3_exists = subprocess.run(['id', '-u', 'user3'], capture_output=True, text=True)
            if user3_exists.returncode != 0:
                subprocess.run(['sudo', 'useradd', 'user3', '-d', '/home/user3', '-m', '-G', 'rw_group', '-s', '/bin/bash'], check=True)
                print("Пользователь user3 успешно создан.")
            else:
                print("Пользователь user3 уже существует.")

            # создаем пользователя user2
            user2_exists = subprocess.run(['id', '-u', 'user2'], capture_output=True, text=True)
            if user2_exists.returncode != 0:
                subprocess.run(['sudo', 'useradd', 'user2', '-d', '/home/user2', '-m', '-G', 'read_group', '-s', '/bin/bash'], check=True)
                print("Пользователь user2 успешно создан.")
            else:
                print("Пользователь user2 уже существует.")
        except subprocess.CalledProcessError as e:
            print(f"Ошибка при создании пользователей: {e}. Возможно, они уже существуют.")

    def read_shadow_file(self):
        """Читает содержимое файла /etc/shadow"""
        try:
            shadow_content = subprocess.check_output(['sudo', 'cat', '/etc/shadow'], universal_newlines=True)
            return self.parse_shadow_content(shadow_content)
        except subprocess.CalledProcessError as e:
            print(f"Ошибка при чтении файла /etc/shadow: {e}")
            return {}

    def parse_shadow_content(self, content):
        """Разбирает содержимое файла shadow на пары логин-хэш."""
        user_info = {}
        for line in content.splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 2:
                username = parts[0]
                password_hash = parts[1]
                user_info[username] = {'hash': password_hash}
        return user_info

    def authenticate_user(self, username, password):
        """Проверяет корректность введенного пароля."""
        if username in self.user_info:
            stored_hash = self.user_info[username]['hash']
            entered_hash = crypt.crypt(password, stored_hash)
            return entered_hash == stored_hash
        return False

    def setup_shared_memory(self, create):
        """Создает или открывает сегмент памяти с настройкой прав."""
        if create:
            shm = shared_memory.SharedMemory(name=SHM_NAME, create=True, size=SHM_SIZE)
            print("Сегмент памяти был создан.")
            # Устанавливаем корректные права доступа
            shm_fd_path = f"/dev/shm/{SHM_NAME}"
            os.chmod(shm_fd_path, 0o660)  # Доступ для чтения и записи для группы
        else:
            shm = shared_memory.SharedMemory(name=SHM_NAME, create=False)
            print("Сегмент памяти уже существует.")
        return shm

    def process_authentication(self):
        """Обрабатывает аутентификацию и доступ к сегменту памяти."""
        login = input("Логин: ")
        password = getpass.getpass("Пароль: ")
        if self.authenticate_user(login, password):
            groups = subprocess.check_output(['groups', login], universal_newlines=True).strip()
            if 'rw_group' in groups:
                print(f"Пользователь {login} имеет доступ на чтение и запись.")
                try:
                    # Попытка открыть существующий сегмент памяти
                    shm = self.setup_shared_memory(create=False)
                except FileNotFoundError:
                    # Создаем новый сегмент памяти, если он не найден
                    shm = self.setup_shared_memory(create=True)

                # Читаем существующие данные
                existing_data = bytes(shm.buf[:]).rstrip(b'\x00').decode('utf-8')
                print(f"Текущие данные в общем сегменте памяти: {existing_data}")

                # Запись новых данных
                user_input = input("Введите данные для записи в общий сегмент памяти: ")
                new_data = (existing_data + '\n' + user_input).strip()
                shm.buf[:len(new_data)] = new_data.encode('utf-8')
                print("Данные добавлены в общий сегмент памяти.")
            elif 'read_group' in groups:
                print(f"Пользователь {login} имеет доступ только на чтение.")
                try:
                    shm = shared_memory.SharedMemory(name=SHM_NAME, create=False)
                    print(f"Данные из общего сегмента памяти: {shm.buf[:].tobytes().decode('utf-8')}")
                except FileNotFoundError:
                    print("Общий сегмент памяти еще не создан.")
            else:
                print(f"Пользователь {login} не имеет доступа к общему сегменту памяти.")
        else:
            print("Неправильный логин или пароль.")

if __name__ == "__main__":
    password_manager = Password()
    password_manager.process_authentication()
    input()
