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
			"authorized": false,
			"allowed_rpc_methods": [
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
	}
}
```

Expose configuration file's path as an environment variable in `AUTH_APP_CONFIG_PATH`.

***Important Note:*** The environment where the application will be deployed, the timezone MUST be as UTC. Also, make sure redis is version `6.*`

### Architecture

![arch2](https://github.com/KomodoPlatform/komodo-defi-proxy/assets/39852038/be7fe7ae-2f2a-4f68-afa8-ce4938c570a7)


**Execution flow:**
1) Client sends the request.

2) Redirect either to websocket or http handler.

3) If the incoming request comes from the same network, step 4 will be by-passed.

4) Request will be handled in the middleware with:
   - Status Checker: Checks if the wallet address status is blocked, allowed, or trusted and does the following:
   	- Blocked: Return `403 Forbidden` immediately
	- Allowed: process continues with the rate limiter
	- Trusted: bypass rate limiter and proof of funding
   - Rate Limiter: First, verify the signed message, and if not valid, return 401 Unauthorized immediately. If valid, then calculate the request count with time interval specified in the application configuration. If the wallet address sent too many request than the expected amount, process continues with the proof of funding. If not, by-passes the proof of funding.
   - Proof of Funding: Return `406 Not Acceptable` if wallet has 0 balance. Otherwise, we assume that request is valid and process continues as usual.

5) Find target route by requested endpoint

6) Check if requested rpc call is allowed in application configuration

7) Generate JWT token with RSA algorithm using pub-priv keys specified in the application configuration, and insert the token to the request header.

8) Drop hop headers.

9) Send request to the target route, then return the same response to the client.

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
