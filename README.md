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

![arch](https://user-images.githubusercontent.com/39852038/170098516-81fbeb1b-7043-48a7-9185-41d148932df0.png)

![auth2](https://user-images.githubusercontent.com/39852038/170179364-8a238c6c-5d6f-4097-855f-36699725d08f.png)

