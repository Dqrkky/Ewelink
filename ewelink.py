import asyncio
import hashlib
import hmac
import base64
import json
import time
from typing import Literal
import uuid
import random
import string
import requests
import datetime
import websockets
import shared

class WebsocketOnBeforeStart:
    def __init__(self, getaway :str=None, url :str=None):
        
        self.type = "WebsocketOnBeforeStart"
        self.getaway = getaway
        self.url :str = url

class WebsocketOnStart:
    def __init__(self, websocket=None, time :datetime.datetime=datetime.datetime.now()):
        self.type = "WebsocketOnStart"
        self.websocket = websocket
        self.time :datetime.datetime = time

REGIONS = Literal["cn", "as", "us", "eu"]

class EWeLink:
    def __init__(self, client_id :str=None, client_secret :str=None, region :REGIONS="eu"):
        self.event_handlers = {}
        self.config = {
            "client_id": client_id if client_id != None and isinstance(client_id, str) else None,  # noqa: E711
            "client_secret": client_secret if client_secret != None and isinstance(client_secret, str) else None,  # noqa: E711
            "regions": {
                "cn": {
                    "apia": "https://cn-apia.coolkit.cn",
                    "dispa": "https://cn-dispa.coolkit.cn"
                },
                "as": {
                    "apia": "https://as-apia.coolkit.cc",
                    "dispa": "https://as-dispa.coolkit.cc"
                },
                "us": {
                    "apia": "https://us-apia.coolkit.cc",
                    "dispa": "https://us-dispa.coolkit.cc"
                },
                "eu": {
                    "apia": "https://eu-apia.coolkit.cc",
                    "dispa": "https://eu-dispa.coolkit.cc"
                }
            },
            "headers": {
                "content-type": "application/json; charset=utf-8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.42"
            },
            "ping_interval": 5,
            "access_token": None,
            "api_key": None
        }
        with requests.Session() as rss:
            self.rss = rss
        self.shared = shared.Shared(
            rss=self.rss
        )
        if hasattr(self, "rss") and self.rss != None and isinstance(self.rss, requests.Session) and \
        hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and \
        "headers" in self.config and self.config["headers"] != None and isinstance(self.config["headers"], str):  # noqa: E711
            self.rss.headers.update(self.config["headers"])
        self.config["getaway"] = self.config["regions"].get(region if region != None and isinstance(region, str) else "eu", None)  # noqa: E711
        getaway = self.dispach()
        self.config["getaway"]["websocket"] = f'{"wss" if getaway["port"] == 443 else "ws"}://{getaway["domain"]}'
    def event(self, event_type=None):
        return self._register_event(event_type=event_type)
    def _register_event(self, event_type=None):
        return self.decorator(event_type) if event_type and isinstance(event_type, object) else self.decorator
    def decorator(self, event_type=None):
        if event_type and isinstance(event_type, object):  # Ensure it's a class type
            if event_type.__name__ not in self.event_handlers:
                self.event_handlers[event_type.__name__] = event_type
            return event_type
    async def trigger_event(self, event_name :str=None, event_data=None):
        if event_name != None and isinstance(event_name, str) and \
        event_data != None and isinstance(event_data, object):  # noqa: E711
            if event_name in self.event_handlers:
                handler = self.event_handlers[event_name]
                if isinstance(handler, object):  # noqa: F821
                    await handler(event_data)
    def request(self, config :dict=None):
        if config != None and isinstance(config, dict):  # noqa: E711
            return self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            )
    def generate_nonce(self=None, length :int=8):
      if length != None and isinstance(length, int):  # noqa: E711
          return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    def make_sign(self, key :str=None, message :str=None):
        if key != None and isinstance(key, str) and message != None and isinstance(message, str):  # noqa: E711
            return base64.b64encode(hmac.new(key.encode(), message.encode(), digestmod=hashlib.sha256).digest()).decode()
    def oauth(self, redirect_url :str=None, state :str=str(uuid.uuid4()), nonce :str=generate_nonce(), domain :str='c2ccdn.coolkit.cc'):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and \
        "client_id" in self.config and self.config["client_id"] != None and \
        "client_secret" in self.config and self.config["client_secret"] != None:  # noqa: E711
            if redirect_url != None and isinstance(redirect_url, str) and \
            state != None and isinstance(state, str) and \
            nonce != None and isinstance(nonce, str) and \
            domain != None and isinstance(domain, str):  # noqa: E711
                seq :int = time.time() * 1000
                config = {
                    "url": f"https://{domain}/oauth/index.html",
                    "params": {
                        "clientId": self.config["client_id"],
                        "seq": seq,
                        "authorization": self.make_sign(
                            self.config["client_secret"],
                            f"{self.config['client_id']}_{seq}"
                        ),
                        "redirectUrl": redirect_url,
                        "grantType": "authorization_code",
                        "state": state,
                        "nonce": nonce
                    }
                }
                return self.shared.construct(
                    url=config["url"],
                    params=config["params"]
                )
    def ng_oauth(self, email :str=None, password :str=None, redirect_url: str=None):
        """Performs the OAuth request and returns the response."""
        if email != None and isinstance(email, str) and \
        password != None and isinstance(password, str) and \
        redirect_url != None and isinstance(redirect_url, str):  # noqa: E711
            seq = int(time.time() * 1000)
            nonce = self.generate_nonce()
            state = str(uuid.uuid4())
            authorization = self.make_sign(self.config["client_secret"], f"{self.config['client_id']}_{seq}")
            config = {
                "method": "post",
                "url": f'{self.config["getaway"]["apia"]}/v2/user/oauth/code',
                "headers": {
                    "authorization": f"Sign {authorization}",
                    "x-ck-appid": self.config["client_id"],
                    "x-ck-nonce": nonce,
                    "x-ck-seq": str(seq)
                },
                "json": {
                    "clientId": self.config["client_id"],
                    "authorization": F"Sign {authorization}",
                    "grantType": "authorization_code",
                    "redirectUrl": redirect_url,
                    "password": password,
                    "email": email,
                    "state": state,
                    "nonce": nonce,
                    "seq": str(seq),
                }
            }
            return self.request(
                config=config
            ).json()
    def token(self, code :str=None, redirect_url :str=None):
        if code != None and isinstance(code, str) and \
        redirect_url != None and isinstance(redirect_url, str):  # noqa: E711
            data = {
                "code": code,
                "redirectUrl": redirect_url,
                "grantType": "authorization_code",
            }
            authorization = self.make_sign(self.config["client_secret"], json.dumps(data))
            config = {
                "method": "post",
                "url": f'{self.config["getaway"]["apia"]}/v2/user/oauth/token',
                "headers": {
                    "authorization": f"Sign {authorization}",
                    "x-ck-appid": self.config["client_id"],
                    "x-ck-nonce": self.generate_nonce(),
                },
                "json": data
            }
            data = self.request(
                config=config
            ).json()
            self.config["access_token"] = data.get("data", {}).get("accessToken", None)
            return data
    def get_devices(self):
        config = {
            "method": "get",
            "url": f'{self.config["getaway"]["apia"]}/v2/device/thing',
            "headers": {
                "Authorization": f'Bearer {self.config["access_token"]}',
                "x-ck-nonce": self.generate_nonce(),
            }
        }
        data = self.request(
            config=config
        ).json()
        self.config["api_key"] = data.get("data", {}).get("thingList", {})[0].get("itemData", {}).get("apikey", None)
        return data
    def dispach(self):
        config = {
            "method": "get",
            "url": f'{self.config["getaway"]["dispa"]}/dispatch/app',
            "headers": {
                **({"Authorization": f'Bearer {self.config["access_token"]}'} if self.config["access_token"] else {})
            }
        }
        return self.request(
            config=config
        ).json()
    async def receive_data(self, websocket=None):
        if websocket:
            # Handshake message
            await self.trigger_event(
                event_name="on_websocket",
                event_data=WebsocketOnStart(
                    websocket=websocket
                )
            )
    async def send_handshake(self):
        if hasattr(self, "websocket") and self.websocket != None:  # noqa: E711
            handshake_msg = {
                'action': 'userOnline',
                'version': 8,
                'ts': int(time.time()),
                'at': self.config["access_token"],
                'userAgent': 'app',
                'apikey': self.config["api_key"],
                'appid': self.config["client_id"],
                'nonce': self.generate_nonce(),
                'sequence': str(int(time.time() * 1000))
            }
            await self.websocket.send(json.dumps(handshake_msg))
            return json.loads(s=await self.websocket.recv())
    async def get_query_device(self, deviceid :str=None):
        if hasattr(self, "websocket") and self.websocket != None:  # noqa: E711
            if deviceid != None and isinstance(deviceid, str):  # noqa: E711
                check_status_msg = {
                    'action': 'query',
                    'apikey': self.config["api_key"],
                    'deviceid': deviceid,
                    'params': [],
                    'userAgent': "app",
                    'sequence': str(int(time.time() * 1000))
                }
                await self.websocket.send(json.dumps(check_status_msg))
                return json.loads(s=await self.websocket.recv())
    async def set_query_device(self, deviceid :str=None, params :dict=None):
        if hasattr(self, "websocket") and self.websocket != None:  # noqa: E711
            if deviceid != None and isinstance(deviceid, str) and \
            params != None and isinstance(params, dict):  # noqa: E711
                check_status_msg = {
                    'action': 'update',
                    'apikey': self.config["api_key"],
                    'deviceid': deviceid,
                    'params': params,
                    'userAgent': "app",
                    'sequence': str(int(time.time() * 1000))
                }
                await self.websocket.send(json.dumps(check_status_msg))
                return json.loads(s=await self.websocket.recv())
    async def start(self):
        if hasattr(self, "config") and self.config and isinstance(self.config, dict) and \
        "ping_interval" in self.config and self.config["ping_interval"] and isinstance(self.config["ping_interval"], int) and \
        "access_token" in self.config and self.config["access_token"] and isinstance(self.config["access_token"], str) and \
        "getaway" in self.config and self.config["getaway"] and isinstance(self.config["getaway"], dict):
            url = f'{self.config["getaway"]["websocket"]}/api/ws'
            await self.trigger_event(
                event_name="on_before_start",
                event_data=WebsocketOnBeforeStart(
                    getaway=self.config["getaway"]["websocket"],
                    url=url
                )
            )
            async with websockets.connect(
                uri=url
            ) as websocket:
                self.websocket = websocket
                await self.receive_data(
                    websocket=websocket
                )
    def run(self):
        asyncio.run(self.start())