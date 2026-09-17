import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

users = {
    "iot_specialist": {
        "role": "iot_security",
        "clearance": 3,
        "department": "IoT",
        "active": True,
    },
    "mobile_analyst": {
        "role": "mobile_security",
        "clearance": 3,
        "department": "Mobile",
        "active": True,
    },
    "web_developer": {
        "role": "web_developer",
        "clearance": 2,
        "department": "Web",
        "active": True,
    },
    "api_consumer": {
        "role": "api_user",
        "clearance": 2,
        "department": "Integration",
        "active": True,
    },
    "demo_account": {
        "role": "demonstration",
        "clearance": 1,
        "department": "Demo",
        "active": False,
    },
}

resources = [
    ("iot_firmware", 3),
    ("mobile_policies", 3),
    ("web_applications", 2),
    ("api_gateway", 2),
    ("device_certificates", 3),
    ("app_store", 1),
    ("vulnerability_database", 3),
    ("device_management", 3),
    ("integration_docs", 2),
    ("demo_content", 1),
]

security_levels = ("Consumer", "Business", "Enterprise", "Critical Systems")
blocked_users = {"demo_account", "compromised_device", "malicious_app"}


def check_access() -> None:

    print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}\n")
    print("=== СПИСОК РЕСУРСІВ СИСТЕМИ ===")
    for res_name, lvl_num in resources:
        lvl_text = security_levels[lvl_num-1]
        print(f" - {res_name}: {lvl_text}")

    print("\n=== РЕЗУЛЬТАТИ ПЕРЕВІРКИ ДОСТУПУ ===")
    all_test_users = list(users.keys()) + ["unknown_user"]

    for username in all_test_users:
        for res_name, req_level in resources:
            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username]["active"]:
                status = "DENY (Account inactive)"
            elif users[username]["clearance"] >= req_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            print(f"user=[{username}] resource=[{res_name}] -> {status}")


if __name__ == "__main__":
    check_access()
