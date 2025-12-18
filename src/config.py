import os
import asyncio
from pydantic import BaseModel, Field, ValidationError
from logging import getLogger
import yaml

logger = getLogger(__name__)
CONFIG_FILE = "config.yaml"


class Settings(BaseModel):
    interface: str = Field(description="Имя сетевого интерейса", default="ens33")

    window: float = Field(description="Окно подсчёта пакетов", default=0.5)
    m_syn: float = Field(description="Порог SYN, 1/сек", default=3.0)
    m_icmp: float = Field(description="Порог ICMP, 1/сек", default=5.0)
    m_udp: float = Field(description="Порог UDP, 1/сек", default=10.0)

    block_output: bool = Field(description="Блокировка исходящих пакетов", default=False)


def save_settings(settings: Settings):
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(settings.model_dump(), f)


def load_settings() -> Settings:
    try:
        with open(CONFIG_FILE, "r") as f:
            data = yaml.safe_load(f) or {}
        return Settings(**data)
    except FileNotFoundError:
        save_settings(Settings())
    except ValidationError as exc:
        logger.error(f"config file validation error:\n{str(exc)}")
        exit(-1)


settings: Settings = load_settings()


async def check_config():
    global settings
    last_mtime = os.path.getmtime(CONFIG_FILE)
    while True:
        mtime = os.path.getmtime(CONFIG_FILE)
        if mtime != last_mtime:
            last_mtime = mtime
            settings = load_settings()
            print("Конфиг загружен")
        await asyncio.sleep(1)
