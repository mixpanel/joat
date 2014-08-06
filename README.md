JWT OAuth Access Token
======================

A library for generating and verifying signed JWT OAuth 2.0 access tokens.

## Installation

`pip install pyjoat`


## Usage

The JOAT library is intended to be used for issuing tokens from the OAuth 2.0
`/token` endpoint, as well as from resource servers to authenticate requests.

Here is an example of token generation:

```python
import joat

def generate_hmac_salt(jwt_claims):
  return "the most secret hmac salt ever"

joat.salt_generator = generate_hmac_salt

TokenGenerator = joat.TokenGenerator("My OAuth2 Provider")

access_token = TokenGenerator.issue_token(client_id="abcd",
                                          user_id="1234",
                                          scope=["profile", "read"])

print access_token
# [line breaks added for readability only]
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmNkIiwiaXNzIjoiTXk \
# gT0F1dGgyIFByb3ZpZGVyIiwiZXhwIjoxNDA3Mjk0NTcyLCJpYXQiOjE0MDcyOTA5NzI \
# sInNjcCI6WyJwcm9maWxlIiwicmVhZCJdLCJzdWIiOiIxMjM0In0.wgNhGiKQ0ppO0Xu \
# QhalGZmSommQROjBusCanRa_6Ydc
```

And one of parsing a token:

```python
import joat

def generate_hmac_salt(jwt_claims):
  return "the most secret hmac salt ever"

joat.salt_generator = generate_hmac_salt

credentials = joat.parse_token('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmNkIiwiaXNzIjoiTXkgT0F1dGgyIFByb3ZpZGVyIiwiZXhwIjoxNDA3Mjk0NTcyLCJpYXQiOjE0MDcyOTA5NzIsInNjcCI6WyJwcm9maWxlIiwicmVhZCJdLCJzdWIiOiIxMjM0In0.wgNhGiKQ0ppO0XuQhalGZmSommQROjBusCanRa_6Ydc')

print credentials
# [again, line break added for readability]
# {u'user_id': u'1234', u'authorized_scope': [u'profile', u'read'],
#  u'client_id': u'abcd', u'provider': u'My OAuth2 Provider'}
```


## Salt Generation

Because the payload of the JWT is easily readable by anyone with access to the
token, a secure HMAC salt (or secret, depending on your preferred terminology)
is of the utmost importance for token security, and to avoid allowing tokens
issued by a malicious third party.

To this end, PyJOAT expects you to implement salt generation on your own.  The
JWT claims are passed into the salt generation method so that you may use the
payload data to lookup or generate the salt for the client-user-scope
combination.

You may also pass a `jti` to the token generation method to augment the salt
generation or otherwise keep track of the tokens you generate.

```python
access_token = TokenGenerator.issue_token(client_id="abcd",
                                          user_id="1234",
                                          scope=["profile", "read"],
                                          jti="your_token_id")
```
