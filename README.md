### configuration environment variables
AUTH_PK_PATH

AUTH_API_PORT

AUTH_TOKEN_EXP

### creating rsa key pairs
openssl genrsa -out private-key.pem 2048

openssl rsa -in private-key.pem -outform PEM -pubout -out public-key.pem
