import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


sys.path.append(str(Path(__file__).resolve().parents[2]))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

DATA_DIR = Path(__file__).parent / "data"
CSV_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"


class ValidationError(Exception):
    pass


def log_event(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")
        result_status = "failure"
        try:
            res = func(*args, **kwargs)
            result_status = "success" if res else "failure"
            return res
        except (ValueError, ValidationError, OSError):
            result_status = "failure"
            raise
        finally:
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                log_data = []
                if LOG_FILE.exists() and os.path.getsize(LOG_FILE) > 0:
                    try:
                        with open(LOG_FILE, "r", encoding="utf-8") as f:
                            log_data = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        log_data = []

                entry = {
                    "event": "login",
                    "user": username,
                    "result": result_status,
                    "timestamp": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
                log_data.append(entry)
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump(log_data, f, indent=4, ensure_ascii=False)
            except (OSError, PermissionError) as e:
                print(f"[ПОМИЛКА ЛОГУВАННЯ]: {e}")

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:

    try:
        if not password or not salt:
            raise ValueError("Пароль або сіль не можуть бути порожніми.")
        if len(password) < 10:
            raise ValidationError("Пароль коротший за мінімальну довжину (10).")

        salted_input = (password + salt).encode("utf-8")
        return hashlib.sha3_384(salted_input).hexdigest()
    except (ValueError, ValidationError) as e:
        print(f"[ПОМИЛКА ХЕШУВАННЯ]: {e}")
        return ""


def get_personal_salt() -> str:
    try:
        return str(VARIANT_NUMBER).zfill(5)
    except (TypeError, ValueError) as e:
        print(f"[ПОМИЛКА СОЛІ]: {e}")
        return "00000"


def create_user(username: str, password: str) -> tuple[str, str]:
    try:
        salt = get_personal_salt()
        pwd_hash = generate_hash(password, salt)
        return username, pwd_hash
    except (ValueError, ValidationError) as e:
        print(f"[ПОМИЛКА СТВОРЕННЯ КОРИСТУВАЧА {username}]: {e}")
        return username, ""


def create_users(users_list: list[tuple[str, str]]) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for u, p in users_list:
                user_data = create_user(u, p)
                writer.writerow(user_data)
    except (OSError, PermissionError, FileNotFoundError) as e:
        print(f"[ПОМИЛКА ЗАПИСУ CSV]: {e}")


def read_users_db() -> list[tuple[str, str]]:
    db = []
    try:
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row:
                    db.append((row[0], row[1]))
    except (OSError, PermissionError, FileNotFoundError) as e:
        print(f"[ПОМИЛКА ЧИТАННЯ CSV]: {e}")
    return db


@log_event
def login(username: str, password: str) -> bool:
    try:
        if not username or not password:
            raise ValueError("Логін та пароль є обов'язковими.")

        db = read_users_db()
        salt = get_personal_salt()
        input_hash = generate_hash(password, salt)

        if not input_hash:
            return False

        for stored_user, stored_hash in db:
            if stored_user == username and stored_hash == input_hash:
                return True
        return False
    except (ValueError, ValidationError) as e:
        print(f"[ПОМИЛКА АВТОРИЗАЦІЇ]: {e}")
        return False


def run_task3() -> None:
        print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}\n")

        users_to_register = [
            ("user1", "Phishing@D3tect"),
            ("user2", "Ransomwar3@Protect"),
            ("user3", "Social@Engineer"),
            ("user4", "Zero@D4yPass1"),
            ("user5", "Bug@Bounty#2023"),
            ("user6", "Secure@Pass10"),
            ("user7", "Complex!Pass10"),
            ("user8", "Crypto#Pass10"),
            ("user9", "Stronger!Pass10"),
            ("user10", "Ultimate#Pass10"),
        ]

        create_users(users_to_register)
        db = read_users_db()

        print("=== БАЗА КОРИСТУВАЧІВ (CSV) ===")
        print(f"{'Логін':<10} | {'Хеш (sha3_384)':<90}")
        print("-" * 105)
        for u, h in db:
            print(f"{u:<10} | {h:<90}")

        print("\n=== ПЕРЕВІРКА АВТЕНТИФІКАЦІЇ ТА ЛОГУВАННЯ ===")
        print("1. Успішна авторизація (user1):", login("user1", "Phishing@D3tect"))
        print("2. Невдала авторизація (user1):", login("user1", "WrongPass123"))


if __name__ == "__main__":
    run_task3()