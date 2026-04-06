import json
import time


class FrameworkIntegration:
    expires_in = 3600

    def __init__(self, name, cache=None):
        self.name = name
        self.cache = cache

    def _get_cache_data(self, key):
        pass

    def _clear_session_state(self, session):
        pass

    def get_state_data(self, session, state):
        pass

    def set_state_data(self, session, state, data):
        pass

    def clear_state_data(self, session, state):
        pass

    def update_token(self, token, refresh_token=None, access_token=None):
        raise NotImplementedError()

    @staticmethod
    def load_config(oauth, name, params):
        raise NotImplementedError()
