from calendar import timegm
import datetime
import hashlib
import jwt
import os
import unittest

from joat import JOAT


class TestJOAT(unittest.TestCase):

  test_iat_datetime = datetime.datetime(2014, 8, 2, 0, 59, 10)
  test_iat_timestamp = 1406941150
  test_exp_timedelta = datetime.timedelta(0, 5400)
  test_exp_timestamp = 1406946550

  wrong_salt = '\xbb4;\xc7\xb2Vn\xa5\xb7\xb0^\xc6J%\x1d\x90\xb8Ik:'


  def generate_salt(cls, claims):
    """Use a constant salt for testing"""
    return '\xdaFw\xfb8\x9f\x9a\xb0\x87\xd3X2J!\x90\x1f\x05\xd6\xa5W'

  def setUp(self):
    self.jwt_header = {
      'typ': 'JWT',
      'alg': 'HS256'
    }
    self.jwt_claims = {
      'iss': 'My OAuth2 Provider',
      'aud': 'abc123DEF', # The application's client_id
      'sub': '12345', # The resource owner's user_id
      'scope': ['email', 'profile'],
      'iat': self.test_iat_timestamp,
      'exp': self.test_exp_timestamp
    }

    self.jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImlzcyI6Ik15IE9BdXRoMiBQcm92aWRlciIsImV4cCI6MTQwNjk0NjU1MCwic2NvcGUiOlsiZW1haWwiLCJwcm9maWxlIl0sImlhdCI6MTQwNjk0MTE1MCwiYXVkIjoiYWJjMTIzREVGIn0.2jWIf62vSDWPWdjv45JxtApXDjAhzjuCM3tuqOfZVIM"

    self.joat_payload = {
      'client': {
        'id': 'abc123DEF',
        'name': 'My OAuth2 Provider'
      },
      'user_id': '12345',
      'authorized_scope': ['email', 'profile']
    }

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
