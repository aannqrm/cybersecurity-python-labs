import random
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "Social@Engineer",
    "basic",
    "Phishing@D3tect",
    "client",
    "Ransomwar3@Protect",
    "general",
    "Zero@D4y",
    "generic",
    "Bug@Bounty",
    "standard123",
]

criteria = {
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "basic",
    "client",
    "general",
    "generic",
    "standard123",
    "guest",
}


def analyze_passwords() -> None:

    working_passwords = passwords.copy()

    indices = random.sample(range(len(working_passwords)), 3)
    for idx in indices:
        working_passwords.append(working_passwords[idx])

    min_len = criteria["min_length"]

    print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}\n")
    print(f"{'Пароль':<25} | {'Категорія':<15}")
    print("-" * 43)

    for pwd in working_passwords:
        is_forbidden = pwd in forbidden_passwords or len(pwd) < min_len
        has_digit = any(c.isdigit() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)

        all_criteria = has_digit and has_upper and has_special and has_lower
        any_criteria = has_digit or has_upper or has_special or has_lower

        if is_forbidden:
            category = "Заборонений"
        elif (
            all_criteria
            and len(pwd) >= min_len + 4
            and working_passwords.count(pwd) == 1
        ):
            category = "Дуже сильний"
        elif all_criteria and len(pwd) < min_len + 4:
            category = "Сильний"
        elif any_criteria and not all_criteria:
            category = "Середній"
        else:
            category = "Слабкий"

        print(f"{pwd:<25} | {category:<15}")


if __name__ == "__main__":
    analyze_passwords()
