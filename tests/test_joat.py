import datetime
import jwt

from .helper import JOATTestCase
from joat import JOAT

class TestTokenGeneration(JOATTestCase):

  def test_generate_token(self):
    joat = JOAT('My OAuth2 Provider', client_id='abc123DEF')
    joat.salt_generator = self.generate_salt

    token = joat.issue_token(user_id='12345',
        scope=['email', 'profile'],
        issued_at=self.test_iat_datetime,
        lifetime=self.test_exp_timedelta)

    try:
      decoded = jwt.decode(token, self.generate_salt(None))
    except:
      self.fail("Token was not decodable after generation")

    reference = jwt.decode(self.jwt_token, self.generate_salt(None))

    # this borders on tautological, but the token should be a JWT that's decodable, with the same claims as the test data
    self.assertDictEqual(decoded, reference)

  def test_generate_without_salt(self):
    joat = JOAT('My OAuth2 Provider', client_id='abc123DEF')
    with self.assertRaises(NotImplementedError):
      token = joat.issue_token(user_id='12345', scope=['email', 'profile'])

  def test_generate_token_missing_params(self):
    joat = JOAT('My OAuth2 Provider')
    joat.salt_generator = self.generate_salt

    token = joat.issue_token()
    self.assertIsNone(token)

    joat.client_id="abc123DEF"
    token = joat.issue_token()
    self.assertIsNone(token)

    joat.user_id = "12345"
    token = joat.issue_token()
    self.assertIsNone(token)

    # this one actually should succeed, since it'll use datetime.now and the default lifetime
    joat.scope = ['email', 'profile']
    token = joat.issue_token()
    self.assertIsNotNone(token)
