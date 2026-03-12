import os
import asyncio
from pydantic import BaseModel, Field, ValidationError
import yaml
from src.logs import logger

CONFIG_FILE = "config.yaml"


class Settings(BaseModel):
    window: float = Field(description="Окно подсчёта пакетов", default=2.0)

    tcp_min_m: float = Field(description="Минимальный порог TCP, 1/сек", default=30.0)
    tcp_max_m: float = Field(description="Максимальный порог TCP, 1/сек", default=2500.0)
    tcp_k: float = Field(description="Коэффициент адаптации порога TCP (PSH+ACK), 1/сек", default=10.0)

    syn_min_m: float = Field(description="Минимальный порог SYN, 1/сек", default=5.0)
    syn_max_m: float = Field(description="Максимальный порог SYN, 1/сек", default=200.0)
    syn_k: float = Field(description="Коэффициент адаптации порога SYN, 1/сек", default=10.0)

    udp_min_m: float = Field(description="Минимальный порог UDP, 1/сек", default=10.0)
    udp_max_m: float = Field(description="Максимальный порог UDP, 1/сек", default=2000.0)
    udp_k: float = Field(description="Коэффициент адаптации порога UDP, 1/сек", default=50.0)

    icmp_min_m: float = Field(description="Минимальный порог ICMP, 1/сек", default=5.0)
    icmp_max_m: float = Field(description="Максимальный порог ICMP, 1/сек", default=500.0)
    icmp_k: float = Field(description="Коэффициент адаптации порога ICMP, 1/сек", default=20.0)


def save_settings(setts: Settings):
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(setts.model_dump(), f)


def load_settings() -> Settings | None:
    try:
        with open(CONFIG_FILE, "r") as f:
            data = yaml.safe_load(f) or {}
        return Settings(**data)
    except FileNotFoundError:
        save_settings(Settings())
    except ValidationError as exc:
        logger.error(f"[ERROR] config file validation error:\n{str(exc)}")
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
            logger.info("Config updated")
        await asyncio.sleep(1)
