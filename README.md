# How to test
Access the default OAuth2 address to get the exposed endpoints: http://localhost:8080/.well-known/openid-configuration

Use the below curl command to call the endpoint and get the token back, change the values accordingly
```shell
 curl -X POST http://localhost:8080/oauth2/token
--header "Content-Type: application/x-www-form-urlencoded"
--header "Authorization: Basic Y2xpZW50OnNlY3JldA=="
--data-urlencode "client_id=client"
--data-urlencode "redirect_uri=https://www.manning.com/authorized"
--data-urlencode "grant_type=authorization_code"
--data-urlencode "code=trtofiw3eR22G0G662PDZK3K2qmrwdqr9bb7mBxHRGDwvrzj6Jt4oz5UQdnRZi4vUqoT7zFyXe1fU4MZ5d4hYhRZsfxlC-VRQ9MxKMhLB1mhA9upiX-xGDcozqDttYB_"

```
# How to use it in your project
Make sure to implement the default configuration for `UserDetails` and such, in the default code these values are being saved directly in the application which is not ideal.
