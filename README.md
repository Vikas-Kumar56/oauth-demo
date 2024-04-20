1. call to generate code from authorization server
http://localhost:8080/oauth2/authorize?
  response_type=code
  &client_id=oidc-client
  &scope=openid
  &redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client
  &code_challenge=I9dW4GigwU7JO_TOstdBWtP-RiYCFLoMWnf2VyhGNJc
  &code_challenge_method=S256

2. After getting code and client need to request for access token.
   http://localhost:8080/oauth2/token
   
   form values
   client_id:oidc-client
   redirect_uri:http://127.0.0.1:8081/login/oauth2/code/oidc-client
   grant_type:authorization_code
   code:DqSI7D-kBWtv_OFcQ9_kZqaepe2pqiYyUDh6BnBWXZyL5phl72Kwv23R9m0ChzTKVN1zeJMvwunU7DvI3vQOI1NszGPNLaanO_xkTkdV-4DDE1cPPw2bJsoR3v2dgeAD
   code_verifier:OrSRuPz6SevVbqPgaU7O-om0UommNuFoP67MA6xIPBZEYQ0SDz6no3P0xtYQdymbCPevIHF9zcsfEGUZm5M8leTSOWZ0XoUXDbqho80BjZdsrZuzJmkyvCrkBLtBm2s7