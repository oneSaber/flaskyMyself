import unittest
from app.models import User,Role,Permission,AnonymousUser
class UserModelTestCase(unittest.TestCase):
    def test_password_setter(self):
        u = User(password = 'saber')
        self.assertTrue(u.password_hash is not None)
    def test_no_password_getter(self):
        u = User(password = 'saber')
        with self.assertRaises(AttributeError):
            u.password
    def test_password_verificattion(self):
        u = User(password = 'saber')
        self.assertTrue(u.verify_password('saber'))
        self.assertFalse(u.verify_password('acher'))
    def test_password_salts_are_random(self):
        u = User(password = 'saber')
        u2= User(password = 'acher')
        self.assertTrue(u.password_hash,u2.password_hash)
    def test_roles_and_permissions(self):
        Role.insert_roles()
        u = User(email = 'faker@example.com',password = 'dog',username = 'faker')
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))
    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))