import joat

from .helper import JOATTestCase

def some_salt_generator(claims):
  return "abcdefg"

class TestSaltGenerator(JOATTestCase):

  def setUp(self):
    reload(joat)

  def test_create_token_generator_without_setting_salter(self):
    with self.assertRaises(NotImplementedError):
      generator = joat.TokenGenerator("Some Provider")

  def test_create_token_generator_after_setting_salter(self):
    joat.salt_generator = some_salt_generator
    generator = joat.TokenGenerator("Some Provider")

  def test_validate_token_without_setting_salter(self):
    with self.assertRaises(NotImplementedError):
      joat.parse_token(self.jwt_token)

  def test_validate_token_after_setting_salter(self):
    joat.salt_generator = self.salt_generator
    token = joat.parse_token(self.jwt_token)
