# Komodo Defi Proxy

Decentralized P2P applications have some limitations by their nature and one of them is the use application/API keys. If an API key is used in the application, any user could retrieve it by simply debugging the app. Some of the blockchain services we use in [komodo-defi-framework](https://github.com/KomodoPlatform/komodo-defi-framework) are paid services and we want to prevent abuse, such as users copying the API key for personal use. To address this problem, we created this project, komodo-defi-proxy. It takes the request, handles the API key, forwards the request to the actual service, and returns the result without modifying the original request. This keeps our secret application keys secure and hidden from end users.

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
  "kdf_rpc_client": "http://127.0.0.1:7783",
  "kdf_rpc_password": "testpass",
  "token_expiration_time": 300,
  "proxy_routes": [
    {
      "inbound_route": "/dev",
      "outbound_route": "http://localhost:8000",
      "proxy_type": "quicknode", # available types are: "quicknode", "moralis", "block_pi"
      "authorized": false,
      "allowed_rpc_methods": [
        "eth_blockNumber",
        "eth_gasPrice"
      ],
      "rate_limiter": null
    }
  ],
  "rate_limiter": {
    "rp_1_min": 30,
    "rp_5_min": 100,
    "rp_15_min": 200,
    "rp_30_min": 350,
    "rp_60_min": 575
  },
  "peer_healthcheck_caching_secs": 10
}
```

Expose configuration file's path as an environment variable in `AUTH_APP_CONFIG_PATH`.

***Important Note:*** Make sure redis is version `7.*`

### Architecture

![2024-09-09_14-09](https://github.com/user-attachments/assets/2775d73e-8003-4bfe-89e1-2c64da9e3004)

1) Client sends the request.

2) Redirect either to websocket or http handler.

3) If the incoming request comes from the same network, step 4 will be by-passed.

4) Request Handling in the Middleware:
  - **Status Checker**:
    - **Blocked**: Return `403 Forbidden`.
    - **Allowed**: Process continues with the rate limiter.
    - **Trusted**: Bypass rate limiter and proof of funding.

  - **Peer Status Checker**:
    - The requesting peer must be active in the KDF network. Validate this by executing the `peer_connection_healthcheck` KDF RPC. If the peer is not connected to the network, return `401 Unauthorized`.

  - **Rate Limiter**:
    - First, verify the signed message. If not valid, return `401 Unauthorized`.
    - If valid, calculate the request count with the time interval specified in the application configuration. If the wallet address has sent too many requests than the expected amount, process continues with the proof of funding. If not, bypass the proof of funding.

5) Find target route by requested endpoint.

6) Check if requested rpc call is allowed in application configuration.

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
			{"url": "'$atomicdex_gui_auth_address'", "komodo_proxy": true }
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

### How to run KomodoDefi-Proxy Service with Docker Compose

If you want to test features locally, you can run Docker containers using Docker Compose commands.

1. **Update Configuration**:
   In the `.config_test` file, update the `proxy_routes` field by adding `ProxyRoutes` with the necessary parameters.

2. **Run Containers in Detached Mode**:
   To start the containers, run the following command. This will build the images if they are not already built or if changes are detected in the Dockerfile or the build context.
   ```sh
   docker compose up -d
   ```

3. **Follow the Logs**:
   Open a new terminal window or tab and execute this command to follow the logs of all services defined in the Docker Compose file. The `-f` (or `--follow`) option ensures that new log entries are continuously displayed as they are produced, while the `-t` (or `--timestamps`) option adds timestamps to each log entry.
   ```sh
   docker compose logs -f -t
   ```

4. **Stop the Containers**:
   ```sh
   docker compose down
   ```
