from dataclasses import dataclass, field
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[2]

@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv('SENTINEL_DATA_DIR', str(ROOT / 'data'))))
    decoy_port: int = field(default_factory=lambda: int(os.getenv('SENTINEL_DECOY_PORT', '9090')))
    decoy_enabled: bool = True
    seed_replay: bool = field(default_factory=lambda: os.getenv('SENTINEL_SEED_REPLAY', '1') == '1')
    train_model: bool = True
    session_hours: int = 8
    origins: tuple = ('http://127.0.0.1:8000', 'http://localhost:8000', 'http://127.0.0.1:5173', 'http://localhost:5173')
    frontend_dir: Path = ROOT / 'frontend' / 'dist'
