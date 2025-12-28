# Network IDS

Программа анализирует сетевой трафик в реальном времени, обраруживает аномалии и блокирует атакующий IP.


## Установка

Для установки программы введите следующие команды в терминал.
```bash
sudo apt update
sudo apt install curl

curl -sSL https://raw.githubusercontent.com/nikita463/ids/refs/heads/main/install.sh | bash
```


## Меню

Программа установлена, но не запущена. Чтобы её запустить и настроить, нужно зайти в её меню.

```bash
network_ids
```

<p align="center">
<img style="" src="https://github.com/nikita463/ids/blob/main/images/menu.png?raw=true" width=250>
</p>


Для каждого поля есть его описание и его текущее значение.
Для изменения настройки надо ввести номер поля и его новое значение указанного типа.

<p align="center">
<img style="" src="https://github.com/nikita463/ids/blob/main/images/settings.png?raw=true" width=500>
</p>

<p align="center">
<img style="" src="https://github.com/nikita463/ids/blob/main/images/set_settings.png?raw=true" width=500>
</p>


В меню можно запускать и останавливать сервис, а так же добавлять и удалять его из автозапуска после загрузки системы.


Выбрав шестое действие, можно удалить полностью программу, сохранив логи.


## Логи

Программа сохраняет все аномалии в сети в файл `/var/log/network_ids/network_ids.log`

Прочитать его можно используя следующую команду

```bash
less /var/log/network_ids/network_ids.log
```