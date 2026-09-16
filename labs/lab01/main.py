import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from labs.lab01.task1 import analyze_passwords
from labs.lab01.task2 import check_access
from labs.lab01.task3 import run_task3


def main():
    print("=" * 50)
    print("ЗАВДАННЯ 1: Аналізатор надійності паролів")
    print("=" * 50)
    analyze_passwords()

    print("\n" + "=" * 50)
    print("ЗАВДАННЯ 2: Система контролю доступу")
    print("=" * 50)
    check_access()

    print("\n" + "=" * 50)
    print("ЗАВДАННЯ 3: Хешування, CSV та JSON-логування")
    print("=" * 50)
    run_task3()


if __name__ == "__main__":
    main()
