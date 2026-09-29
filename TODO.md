Add proper error messages

Login in only returns access token, should return access token and refresh token 

note that ENV has the following 
`CA_ORG="Your Organization"
CA_COUNTRY=KE
CA_OUT_DIR=./ca-out
ROOT_CA_PASSPHRASE=only-needed-for-init-ca
INTERMEDIATE_CA_PASSPHRASE=long-random-value
KEK_CURRENT=v1
KEK_V1=<openssl rand -base64 32>
DATABASE_URL=postgresql://...`


