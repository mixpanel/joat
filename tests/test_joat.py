from calendar import timegm
import datetime
import hashlib
import jwt
import os
import unittest

import joat


class TestJOAT(unittest.TestCase):

  test_iat = 1406935214
  test_exp = 1406940614 # 90 minutes later

  wrong_salt = '\xbb4;\xc7\xb2Vn\xa5\xb7\xb0^\xc6J%\x1d\x90\xb8Ik:'


  def generate_salt(cls, token):
    """Use a constant salt for testing"""
    return '\xdaFw\xfb8\x9f\x9a\xb0\x87\xd3X2J!\x90\x1f\x05\xd6\xa5W'

  def setUp(self):
    self.jwt_header = {
      'typ': 'JWT',
      'alg': 'HS256'
    }
    self.jwt_claim = {
      'iss': 'My OAuth2 Provider',
      'sub': '12345', # The resource owner's user_id
      'aud': 'abc123DEF', # The application's client_id
      'iat': self.test_iat,
      'exp': self.test_exp,
      'scope': ['email', 'profile']
    }

    self.jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImlzcyI6Ik15IE9BdXRoMiBQcm92aWRlciIsImV4cCI6MTQwNjk0MDYxNCwic2NvcGUiOlsiZW1haWwiLCJwcm9maWxlIl0sImlhdCI6MTQwNjkzNTIxNCwiYXVkIjoiYWJjMTIzREVGIn0.jUEOEjbfVaKCM4rL9I1ghh_cES_9AHRdnNgL1iALuvg"

    self.joat_payload = {
      'client': {
        'id': 'abc123DEF',
        'name': 'My OAuth2 Provider'
      },
      'user_id': '12345',
      'scope': ['email', 'profile']
    }


  def test_generate_token(self):
    joat = JOAT('My OAuth2 Provider', client_id='abc123DEF')
    joat.salt_generator = self.generate_salt
    joat.default_lifetime = datetime.timedelta(minutes=90)

    token = joat.issue_token(user_id='12345', scope=['email', 'profile'])
    self.assertEqual(token, self.jwt_token)

