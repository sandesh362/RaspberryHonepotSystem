from datetime import datetime, timezone
from typing import Literal, Any
from ipaddress import ip_address
from pydantic import BaseModel, Field, field_validator
import json

Mode = Literal['LIVE', 'REPLAY']
Kind = Literal['connection', 'tcp_probe', 'auth_failure', 'auth_success', 'command', 'http_request']

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')

class EventInput(BaseModel):
    event_id: str = Field(min_length=1, max_length=160, pattern=r'^[a-zA-Z0-9_.:-]+$')
    sensor_id: str = Field(default='software-lab', pattern=r'^[a-zA-Z0-9_-]{1,64}$')
    source: Literal['http-decoy', 'cowrie', 'suricata', 'lab-replay']
    timestamp: datetime
    kind: Kind
    protocol: Literal['SSH', 'TELNET', 'HTTP', 'TCP']
    source_ip: str
    source_port: int = Field(default=0, ge=0, le=65535)
    destination_port: int = Field(default=0, ge=0, le=65535)
    session_id: str = Field(min_length=1, max_length=160, pattern=r'^[a-zA-Z0-9_.:-]+$')
    detail: str = Field(default='', max_length=4096)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator('timestamp')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None: raise ValueError('timestamp must include a UTC offset')
        return value.astimezone(timezone.utc)

    @field_validator('source_ip')
    @classmethod
    def address(cls, value):
        return str(ip_address(value))

    @field_validator('metadata')
    @classmethod
    def bounded(cls, value):
        if len(json.dumps(value, allow_nan=False)) > 8192: raise ValueError('metadata exceeds 8 KiB')
        return value

class BatchInput(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=100)

class LoginInput(BaseModel):
    username: str = Field(max_length=80)
    password: str = Field(max_length=256)

class RunInput(BaseModel):
    scenario: Literal['mixed', 'scan', 'auth', 'shell', 'http', 'control'] = 'mixed'

class CaseInput(BaseModel):
    title: str = Field(min_length=3, max_length=140)
    mode: Mode
    finding_id: str | None = Field(default=None, max_length=80)
    session_id: str | None = Field(default=None, max_length=160)
    notes: str = Field(default='', max_length=4000)

class CaseUpdate(BaseModel):
    notes: str = Field(max_length=4000)
    status: Literal['open', 'reviewed', 'closed']

class FindingUpdate(BaseModel):
    status: Literal['open', 'reviewed', 'dismissed']

class CowrieImport(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=100)
