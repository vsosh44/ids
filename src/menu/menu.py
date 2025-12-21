#!/usr/bin/env python3

import sys
sys.path.insert(0, '/opt/network_ids')

import os

from src.menu.utils import get_field_info, ret_str_type
from src.config import Settings, load_settings, save_settings


def clear_screen():
    os.system("clear")


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
        print("\n2) Выход")

        choice = input("\nВыберите номер действия: ")
        while not choice.isdigit() or not 1 <= int(choice) <= 2:
            choice = input("Введите число - номер действия: ")

        clear_screen()

        if choice == "1":
            edit_settings_menu(settings)
        if choice == "2":
            break
    
    clear_screen()


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print()
        exit(-1)
