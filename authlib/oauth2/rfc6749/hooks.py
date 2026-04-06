from collections import defaultdict


class Hookable:
    _hooks = None

    def __init__(self):
        self._hooks = defaultdict(set)

    def register_hook(self, hook_type, hook):
        pass

    def execute_hook(self, hook_type, *args, **kwargs):
        pass


def hooked(func=None, before=None, after=None):
    """Execute hooks before and after the decorated method."""
    pass
