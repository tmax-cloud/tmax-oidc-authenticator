## 테스트용 토큰 발급 방법

```shell
./get-token.sh
```

## POSTMAN으로 authentication webhook 테스트 

POST: https://oidc-authenticator.tmaxcloud.org/authenticate
header: 
body: Content-Type: application/json
{
"apiVersion": "authentication.k8s.io/v1",
"kind": "TokenReview",
"spec": {
    "token": ""
    "audiences": []
    }
}

response:
{"metadata":{"creationTimestamp":null},"spec":{},"status":{"authenticated":true,"user":{"username":"admin@tmax.co.kr","uid":"dae257a0-f1f2-4ad2-bc2c-6841b94eae91","groups":["argocd-admin","hypercloud5"]}}}