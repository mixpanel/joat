from calendar import timegm
import datetime
import jwt
import logging


class JOAT(object):
  """A class that generates and parses JWT OAuth 2.0 Access Tokens.

  Each instance of the class is tied to a particular OAuth 2.0 client
  for token generation convenience.  The fields of the client and user
  are populated during token parsing if the token is valid.
  """

  provider_name = None
  client_id = None

  user_id = None

  scope = None

  default_lifetime = datetime.timedelta(hours=1)

  def salt_generator(self, claims):
    """Generate a secret for the token.

    The JWT claims are passed in, in case you'd like to use (like iat)
    some of the fields for generating an HMAC salt.

    You need to implement this method in order to use the generator.
    """
    logging.debug("JOAT salt_generator was not implemented!")
    raise NotImplementedError

  def __init__(self, name, client_id=None):
    self.provider_name = name
    self.client_id = client_id

  def issue_token(self, **kwargs):
    """Issue an access token to the client for the user and scope provided."""

    now = datetime.datetime.utcnow()

    # Use the class properties for anything not passed in
    provider = kwargs.get('provider', self.provider_name)
    client_id = kwargs.get('client_id', self.client_id)
    user_id = kwargs.get('user_id', self.user_id)
    scope = kwargs.get('scope', self.scope)
    issued_at = kwargs.get('issued_at', now)
    lifetime = kwargs.get('lifetime', self.default_lifetime)

    if (provider is None or
        client_id is None or
        user_id is None or
        scope is None or
        issued_at is None or
        lifetime is None):
      logging.debug("JOAT.issue_token called with a None param. Returning None")
      return None

    if not isinstance(scope, list):
      logging.debug("JOAT.issue_token called with an invalid scope: %s" % scope)
      logging.debug("Scope must be a list, but instead was %s" % scope.__class__)
      return None

    if not isinstance(issued_at, datetime.datetime):
      logging.debug("JOAT.issue_token called with an invalid issued_at: %s" % issued_at)
      logging.debug("issued_at must be a datetime, but instead was %s" % datetime.__class__)
      return None

    if not isinstance(lifetime, datetime.timedelta):
      logging.debug("JOAT.issue_token called with an invalid lifetime: %s" % lifetime)
      logging.debug("lifetime must be a timedelta, but instead was %s" % datetime.__class__)
      return None

    expires = issued_at + lifetime

    claims = {
      'iss': provider,
      'aud': client_id,
      'sub': user_id,
      'scope': scope,
      'iat': timegm(issued_at.utctimetuple()),
      'exp': timegm(expires.utctimetuple())
    }

    secret = self.salt_generator(claims)

    token = jwt.encode(claims, secret)

    return token
