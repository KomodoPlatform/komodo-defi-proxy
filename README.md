### configuration environment variables
AUTH_PRIV_KEY_PATH

AUTH_PUB_KEY_PATH

AUTH_API_PORT

AUTH_TOKEN_EXP

REDIS_CONNECTION_STRING

### creating rsa key pairs
openssl genrsa -out private-key.pem 2048

openssl rsa -in private-key.pem -outform PEM -pubout -out public-key.pem

### Architecture

![arch](https://user-images.githubusercontent.com/39852038/170087184-5e98a0a0-6d4e-46d1-9213-aa62fd885be9.png)
