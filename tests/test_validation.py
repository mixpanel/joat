import datetime
import jwt
import time

from .helper import JOATTestCase, random_bytes
import joat

class TestTokenValidation(JOATTestCase):

  def setUp(self):
    super(TestTokenValidation, self).setUp()
    joat.salt_generator = self.generate_salt

  def test_validate_token(self):
    valid_token = jwt.encode(self.jwt_claims, self.generate_salt(self.jwt_claims))

    cred = joat.parse_token(valid_token)
    self.assertEqual(cred.user_id, jwt_claims['sub'])
    self.assertEqual(cred.client_id, jwt_claims['aud'])
    self.assertEqual(cred.scope, jwt_claims['scp'])

  def test_validate_with_incorrect_salt(self):
    invalid_token = jwt.encode(self.jwt_claims, self.generate_wrong_salt(None))

    credential = joat.parse_token(invalid_token)
    self.assertIsNone(credential)

  def test_validate_expired_token(self):
    lifetime = datetime.timedelta(seconds=2)

    generator = joat.TokenGenerator("My Provider")
    generator.client_id = 'abc123DEF'
    token = generator.issue_token(user_id='12345',
                                  scope=['email', 'profile'],
                                  lifetime=lifetime)

    time.sleep(3)

    with self.assertRaises(jwt.ExpiredSignature):
      joat.parse_token(token)
