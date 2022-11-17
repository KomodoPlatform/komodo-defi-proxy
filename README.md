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
			"coins": ["ETH"],
			"url": "https://xyz.com/096ed97e0b1342b4b33",
			"authorized": false
		}
	]
}
```

Expose configuration file's path as an environment variable in `AUTH_APP_CONFIG_PATH`.

***Important Note:*** The environment where the application will be deployed, the timezone MUST be as UTC. Also, make sure redis is version `6.*`

### Architecture
![2022-05-25_09-44](https://user-images.githubusercontent.com/39852038/170197519-005732b5-b8b6-44f7-99df-ab1294f8ae21.png)

**Execution flow:**
1) Client sends the request.

2) If the incoming request comes from the same network, step 3 will be by-passed.

3) Request will be handled in the middleware with:
   - Status Checker: Checks if the wallet address status is blocked, allowed, or trusted and does the following:
   	- Blocked: Return `403 Forbidden` immediately
	- Allowed: process continues with the rate limiter
	- Trusted: bypass rate limiter and proof of funding
   - Rate Limiter: Calculate the request count with time interval specified in the application configuration. If the wallet address sent too many request than expected, process continues with the proof of funding. Otherwise, by-passes the proof of funding. Too Many Requests`. Otherwise, continues the process.
   - Proof of Funding: Return `406 Not Acceptable` if wallet has 0 balance. Otherwise, process continues with the proxy router.

4) Find target route by requested endpoint

5) Check if requested rpc call is allowed in application configuration

6) Generate JWT token with RSA algorithm using pub-priv keys specified in the application configuration, and insert the token to the request header.

7) Drop hop headers.

8) Send request to the target route, then return the same response to the client.

### Example Request

```sh
curl -v --url "'$mm2_address'" -s --data '{
	"userpass": "'$userpass'",
	"mmrpc": "2.0",
	"method": "enable_eth_with_tokens",
	"params": {
		"ticker": "ETH",
		"nodes": [
			{"url": "'$atomicdex_gui_auth_address'", "gui_auth": true }
		],
		"swap_contract_address": "0x24ABE4c71FC658C91313b6552cd40cD808b3Ea80",
		"erc20_tokens_requests": [
			{
				"ticker": "USDC-ERC20"
			},
			{
				"ticker": "SHIB-ERC20"
			}
		]
	},
	"id": 0
}'
```
