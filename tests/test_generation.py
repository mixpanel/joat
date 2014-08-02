import datetime
import jwt

from .helper import JOATTestCase, random_bytes
from joat import JOAT

class TestTokenGeneration(JOATTestCase):

  def setUp(self):
    super(TestTokenGeneration, self).setUp()
    self.joat = JOAT("My OAuth2 Provider")
    self.joat.salt_generator = self.generate_salt

  def test_generate_token(self):
    self.joat.client_id = 'abc123DEF'
    token = self.joat.issue_token(user_id='12345',
        scope=['email', 'profile'],
        issued_at=self.test_iat_datetime,
        lifetime=self.test_exp_timedelta)

    try:
      decoded = jwt.decode(token, self.generate_salt(token))
    except Exception as e:
      print(e)
      self.fail("Token was not decodable after generation")

    reference = jwt.decode(self.jwt_token, self.generate_salt(token))

    # this borders on tautological, but the token should be a JWT that's decodable, with the same claims as the test data
    self.assertDictEqual(decoded, reference)

  def test_generate_without_salt(self):
    joat = JOAT('My OAuth2 Provider', client_id='abc123DEF')
    with self.assertRaises(NotImplementedError):
      token = joat.issue_token(user_id='12345', scope=['email', 'profile'])

  def test_generate_token_missing_params(self):

    token = self.joat.issue_token()
    self.assertIsNone(token)

    self.joat.client_id="abc123DEF"
    token = self.joat.issue_token()
    self.assertIsNone(token)

    self.joat.user_id = "12345"
    token = self.joat.issue_token()
    self.assertIsNone(token)

    # this one actually should succeed, since it'll use datetime.now and the default lifetime
    self.joat.scope = ['email', 'profile']
    token = self.joat.issue_token()
    self.assertIsNotNone(token)

  def test_using_claim_data_in_salt(self):
    jti = random_bytes()
    claims = self.jwt_claims
    claims['jti'] = jti

    def generate_custom_salt(cls, claims):
      if claims is None:
        return "foobar"

      # Obviously you'd never do _literally_ this, but you might want
      # To use some of this data to generate the salt, or to look it
      # up in a db somewhere based on some of this info.
      return "%s%d%s" % (claims['aud'], claims['iat'], claims['jti'])

    issued_at = datetime.datetime.utcnow()

    token = self.joat.issue_token(user_id='12345',
                                  scope=['email', 'profile'],
                                  jti=jti,
                                  issued_at=issued_at)

    # change the salt generator
    self.joat.salt_generator = generate_custom_salt
    salted_token = self.joat.issue_token(user_id='12345',
                                         scope=['email', 'profile'],
                                         jti=jti,
                                         issued_at=issued_at)
    self.assertNotEqual(token, salted_token)

    # token with original salt shouldn't parse
    self.assertIsNone(self.joat.parse_token(token))

    # but this one should
    salted_token_data = self.joat.parse_token(salted_token)
    self.assertIsNotNone(salted_token_data)
    self.assertDictEqual(salted_token_data, self.joat_payload)

    # restore the original salt generator
    self.joat.salt_generator = self.generate_salt

    # custom salted token shouldnt parse anymore
    self.assertIsNone(self.joat.parse_token(salted_token))

    # but this one should
    token_data = self.joat.parse_token(token)
    self.assertIsNotNone(token_data)
    self.assertDictEqual(token_data, self.joat_payload)
