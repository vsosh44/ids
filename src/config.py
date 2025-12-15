import os
import asyncio
from pydantic import BaseModel, Field, ValidationError
from logging import getLogger
import yaml

logger = getLogger(__name__)
CONFIG_FILE = "config.yaml"


class Settings(BaseModel):
    interface: str = Field(description="Имя сетевого интерейса")

    window: float
    m_syn: float
    m_icmp: float
    m_udp: float

    block_output: bool


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
