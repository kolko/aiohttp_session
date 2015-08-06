import asyncio
import hashlib
import time
import random
from . import AbstractStorage, Session


try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    import warnings
    warnings.warn('A secure pseudo-random number generator is not available '
                  'on your system. Falling back to Mersenne Twister.')
    using_sysrandom = False



class InmemoryStorage(AbstractStorage):
    """Inmemory storage.
    """


    def __init__(self, cookie_id_length, cookie_id_secret, *, cookie_name="AIOHTTP_SESSION",
                 domain=None, max_age=None, path='/',
                 secure=None, httponly=True):
        super().__init__(cookie_name=cookie_name, domain=domain,
                         max_age=max_age, path=path, secure=secure,
                         httponly=httponly)
        self.cookie_id_length = cookie_id_length
        self.cookie_id_secret = cookie_id_secret
        self._storage = {}

    @asyncio.coroutine
    def load_session(self, request):
        cookie = self.load_cookie(request)
        if cookie is None:
            return Session(None, new=True)
        else:
            session = self._storage.get(cookie)
            if session is None:
                return Session(None, new=True)
            return session

    @asyncio.coroutine
    def save_session(self, request, response, session):
        if not session._mapping:
            return self.save_cookie(response, session._mapping)

        if session.new:
            while True:
                uid = get_random_string(length=self.cookie_id_length, secret_key=self.cookie_id_secret)
                if uid not in self._storage:
                    break
            self._storage[uid] = session
            self.save_cookie(response, uid)


# From django.utils.crypto
def get_random_string(length=12,
                      allowed_chars='abcdefghijklmnopqrstuvwxyz'
                                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                      secret_key=None):
    """
    Returns a securely generated random string.
    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit value. log_2((26+26+10)^12) =~ 71 bits
    """
    assert secret_key is not None, "Need secret_key"
    if not using_sysrandom:
        # This is ugly, and a hack, but it makes things better than
        # the alternative of predictability. This re-seeds the PRNG
        # using a value that is hard for an attacker to predict, every
        # time a random string is required. This may change the
        # properties of the chosen random sequence slightly, but this
        # is better than absolute predictability.
        random.seed(
            hashlib.sha256(
                ("%s%s%s" % (
                    random.getstate(),
                    time.time(),
                    secret_key)).encode('utf-8')
            ).digest())
    return ''.join(random.choice(allowed_chars) for i in range(length))