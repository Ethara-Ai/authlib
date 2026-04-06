import json
import time
from collections.abc import Hashable
from typing import Any

from ..base_client import FrameworkIntegration


class StarletteIntegration(FrameworkIntegration):
    async def _get_cache_data(self, key: Hashable):
        pass

    async def get_state_data(
        self, session: dict[str, Any] | None, state: str
    ) -> dict[str, Any]:
        pass

    async def set_state_data(
        self, session: dict[str, Any] | None, state: str, data: Any
    ):
        pass

    async def clear_state_data(self, session: dict[str, Any] | None, state: str):
        pass

    def update_token(self, token, refresh_token=None, access_token=None):
        pass

    @staticmethod
    def load_config(oauth, name, params):
        if not oauth.config:
            return {}

        rv = {}
        for k in params:
            conf_key = f"{name}_{k}".upper()
            v = oauth.config.get(conf_key, default=None)
            if v is not None:
                rv[k] = v
        return rv
