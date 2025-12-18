import os
import asyncio
from pydantic import BaseModel, Field, ValidationError
from logging import getLogger
import yaml

logger = getLogger(__name__)
CONFIG_FILE = "config.yaml"


class Settings(BaseModel):
    interface: str = Field(description="Имя сетевого интерейса")

    window: float = Field(description="Окно подсчёта пакетов")
    m_syn: float = Field(description="Порог SYN, 1/сек")
    m_icmp: float = Field(description="Порог ICMP, 1/сек")
    m_udp: float = Field(description="Порог UDP, 1/сек")

    block_output: bool = Field(description="Блокировка исходящих пакетов")


def save_settings(settings: Settings):
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(settings.model_dump(), f)


def load_settings() -> Settings:
    try:
        with open(CONFIG_FILE, "r") as f:
            data = yaml.safe_load(f) or {}
        return Settings(**data)
    except FileNotFoundError:
        logger.error("config file not found")
        exit(-1)
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
