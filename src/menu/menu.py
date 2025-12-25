#!/opt/network_ids/venv/bin/python

import os
from typing import Optional
from time import sleep

from src.menu.utils import get_field_info, ret_str_type
from src.config import Settings, load_settings, save_settings
from src.cmd_utils import run_cmd


def clear_screen():
    os.system("clear")


def enable_service(service_name="network_ids.service") -> Optional[str]:
    _, _, err = run_cmd(f"sudo systemctl enable {service_name}")
    return err if len(err) > 0 else None


def disable_service(service_name="network_ids.service") -> Optional[str]:
    _, _, err = run_cmd(f"sudo systemctl disable {service_name}")
    return err if len(err) > 0 else None


def start_service(service_name="network_ids.service") -> Optional[str]:
    _, _, err = run_cmd(f"sudo systemctl start {service_name}")
    return err if len(err) > 0 else None


def stop_service(service_name="network_ids.service") -> Optional[str]:
    _, _, err = run_cmd(f"sudo systemctl stop {service_name}")
    return err if len(err) > 0 else None

def delete_service() -> Optional[str]:
    run_cmd("bash /opt/network_ids/uninstall.sh")


def edit_settings_menu(settings: Settings):
    print("Редактирование настроек:")
    for i, _ in enumerate(Settings.model_fields.items()):
        field_info = get_field_info(settings, i)
        if field_info.description:
            print(f"{i + 1}) {field_info.name} ({field_info.description}) = {field_info.value}")
        else:
            print(f"{i + 1}) {field_info.name} = {field_info.value}")
    print()
    last_ind = len(Settings.model_fields.items()) + 1
    print(f"{last_ind}) Вернуться\n")

    ind = input("Выберите номер поля: ")
    while not ind.isdigit() or not 1 <= int(ind) <= len(Settings.model_fields.items()) + 1:
        ind = input("Введите число - номер поля: ")
    ind = int(ind) - 1

    if ind + 1 == last_ind:
        return

    field_info = get_field_info(settings, ind)
    obj = input(f"Введите новое значение поля ({field_info.annotation.__name__}): ")
    while (type_obj := ret_str_type(obj, field_info.annotation)) is None:
        obj = input(f"Введите значение указанного типа ({field_info.annotation.__name__}): ")

    setattr(settings, field_info.name, type_obj)
    save_settings(settings)


def main_menu():
    settings = load_settings()

    while True:
        clear_screen()

        print("Меню ids:")
        print("1) Редактирование настроек")
        print()
        print("2) Запустить сервис")
        print("3) Остановить сервис")
        print()
        print("4) Добавить в автозапуск")
        print("5) Удалить из автозапуска")
        print()
        print("6) Удалить")
        print()
        print("7) Выход")

        choice = input("\nВыберите номер действия: ")
        while not choice.isdigit() or not 1 <= int(choice) <= 7:
            choice = input("Введите число - номер действия: ")

        match choice:
            case "1":
                clear_screen()
                edit_settings_menu(settings)
            case "2": start_service()
            case "3": stop_service()
            case "4": enable_service()
            case "5": disable_service()
            case "6": delete_service()
            case _: break
    
    clear_screen()


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print()
        exit(-1)
