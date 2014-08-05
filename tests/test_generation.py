import base64
import datetime
import jwt

import joat

from .helper import JOATTestCase, random_bytes


class TestTokenGeneration(JOATTestCase):

  def setUp(self):
    super(TestTokenGeneration, self).setUp()
    joat.salt_generator = self.generate_salt
    self.token_generator = joat.TokenGenerator("My OAuth2 Provider")
    self.token_generator.client_id = 'abc123DEF'


  def test_generate_token(self):
    token = self.token_generator.issue_token(user_id='12345',
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


  def test_generate_token_missing_client_id(self):
    token_gen = joat.TokenGenerator("My Provider")

    with self.assertRaises(ArgumentError):
      token = self.token_generator.issue_token()


  def test_generate_token_missing_user(self):
    token_gen = joat.TokenGenerator("My Provider")

    with self.assertRaises(ArgumentError):
      token = self.token_generator.issue_token(client_id="abc123DEF")


  def test_generate_token_missing_scope(self):
    token_gen = joat.TokenGenerator("My Provider")
    token_gen.client_id = "abc123DEF"

    token = token_gen.issue_token(user_id="12345")
    self.assertIsNone(token)

    token_gen.user_id = "12345"
    token = token_gen.issue_token()
    self.assertIsNone(token)


  def test_generate_token_default_iat_lifetime(self):
    token_gen = joat.TokenGenerator("My Provider")

    token = token_gen.issue_token(client_id="abc123DEF",
                                  user_id="12345",
                                  scope=['email', 'profile'])

    self.assertIsNotNone(token)
    # should probably also assert that token issued at is approx equal to now
    # and that expiry is approx equal to 90 mins from now


  def test_using_claim_data_in_salt(self):
    jti = base64.urlsafe_b64encode(random_bytes())
    claims = self.jwt_claims
    claims['jti'] = jti

    def generate_custom_salt(claims):
      if claims is None:
        return "foobar"

      # Obviously you'd never do _literally_ this, but you might want
      # To use some of this data to generate the salt, or to look it
      # up in a db somewhere based on some of this info.
      return "%s%d%s" % (claims['aud'], claims['iat'], claims['jti'])

    issued_at = datetime.datetime.utcnow()

    token_gen = self.token_generator

    token = token_gen.issue_token(user_id='12345',
                                  scope=['email', 'profile'],
                                  jti=jti,
                                  issued_at=issued_at)

    # change the salt generator
    joat.salt_generator = generate_custom_salt
    salted_token = token_gen.issue_token(user_id='12345',
                                         scope=['email', 'profile'],
                                         jti=jti,
                                         issued_at=issued_at)
    self.assertNotEqual(token, salted_token)

    # token with original salt shouldn't parse
    self.assertIsNone(joat.parse_token(token))

    # but this one should
    salted_token_data = joat.parse_token(salted_token)
    self.assertIsNotNone(salted_token_data)
    self.assertDictEqual(salted_token_data, self.joat_payload)

    # restore the original salt generator
    joat.salt_generator = self.generate_salt

    # custom salted token shouldnt parse anymore
    self.assertIsNone(joat.parse_token(salted_token))

    # but this one should
    token_data = joat.parse_token(token)
    self.assertIsNotNone(token_data)
    self.assertDictEqual(token_data, self.joat_payload)
