### Dev Requirements

Creating rsa key pairs

```sh
openssl genrsa -out private-key.pem 2048

openssl rsa -in private-key.pem -outform PEM -pubout -out public-key.pem
```

Create the configuration file for app runtime.

```json
{
	"port": 6150,
	"pubkey_path": "/path_to_publick_key.pem",
	"privkey_path": "/path_to_private_key.pem",
	"redis_connection_string": "redis://localhost",
	"token_expiration_time": 300,
	"proxy_routes": [
		{
			"inbound_route": "/dev",
			"outbound_route": "http://localhost:8000",
			"allowed_methods": [
				"eth_blockNumber",
				"eth_gasPrice"
			]
		}
	],
	"rate_limiter": {
		"rp_1_min": 30,
		"rp_5_min": 100,
		"rp_15_min": 200,
		"rp_30_min": 350,
		"rp_60_min": 575
	},
	"nodes": [
		{
			"name": "ETH",
			"url": "https://xyz.com/096ed97e0b1342b4b33",
			"authorized": false
		}
	]
}
```

Expose configuration file's path as an environment variable in `AUTH_APP_CONFIG_PATH`.

***Important Note:*** The environment where the application will be deployed, the timezone MUST be as UTC.

### Architecture
![2022-05-25_09-44](https://user-images.githubusercontent.com/39852038/170197519-005732b5-b8b6-44f7-99df-ab1294f8ae21.png)

**Execution flow:**
1) Instead of requesting to the Authenticated service with secure token, mm2 client sends the same request(without auth token) but to our service.

2) At the beginning, request will be handled by the middleware with:
   - Status Checker: Checks the IP address status if it's blocked, allowed, or trusted(means bypass rate-limiter and proof of funding & trading).
   - Rate Limiter: Calculates the request count with specific time interval, if the IP address sent too many request than expected, then returns `429 Too Many Requests`. Otherwise, continues the process.
   - Proof of Funding & Trading: Does validation processes(like checking coin balance) using signed message.

3) Generates secure JWT token using RS algorithm or uses existing token from Redis and adds that token into incoming request's header.

4) Find the related route by current endpoint(like if current requested endpoint is '/ethereum-node' then go to 'blabla.quiknode.pro/blabla')

5) Proxy the incoming request to the target route and returns what target route returns.
