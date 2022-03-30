from base64 import b32encode
from os import urandom

from django.conf import settings
from django.contrib.auth.hashers import get_hasher, make_password
from django.db import models

from django_otp.models import Device, ThrottlingMixin


class StaticDevice(ThrottlingMixin, Device):
    """
    A static :class:`~django_otp.models.Device` simply consists of random
    tokens shared by the database and the user.

    These are frequently used as emergency tokens in case a user's normal
    device is lost or unavailable. They can be consumed in any order; each
    token will be removed from the database as soon as it is used.

    This model has shared salt and algorithm fields, used to hash contained
    :class:`StaticToken` objects.

    .. attribute:: token_set

        The RelatedManager for our tokens.

    """

    salt = models.CharField(max_length=128, null=True)
    hash_algorithm = models.CharField(max_length=64, null=True)

    def save(self, *args, **kwargs):
        """Create a salt on save, using the default password hasher."""
        if self._state.adding:
            hasher = get_hasher()
            self.hash_algorithm = hasher.algorithm
            self.salt = hasher.salt()
        super().save(*args, **kwargs)

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_STATIC_THROTTLE_FACTOR', 1)

    def verify_token(self, token):
        verify_allowed, _ = self.verify_is_allowed()
        if verify_allowed:
            if self.salt is not None:
                token = make_password(token, self.salt, self.hash_algorithm)
            match = self.token_set.filter(token=token).first()
            if match is not None:
                match.delete()
                self.throttle_reset()
            else:
                self.throttle_increment()
        else:
            match = None

        return (match is not None)


class StaticToken(models.Model):
    """
    A single token belonging to a :class:`StaticDevice`.

    .. attribute:: device

        *ForeignKey*: A foreign key to :class:`StaticDevice`.

    .. attribute:: token

        *CharField*: A random string up to 16 characters.
    """

    device = models.ForeignKey(StaticDevice, related_name='token_set', on_delete=models.CASCADE)
    token = models.CharField(max_length=128, db_index=True)

    @staticmethod
    def random_token():
        """
        Returns a new random string that can be used as a static token.

        :rtype: bytes

        """
        return b32encode(urandom(5)).decode('utf-8').lower()

    def save(self, *args, **kwargs):
        """Hash the token on save, if the device has a salt."""
        if self._state.adding and (self.device.salt is not None):
            self.token = make_password(
                self.token, salt=self.device.salt, hasher=self.device.hash_algorithm
            )
        super().save(*args, **kwargs)
