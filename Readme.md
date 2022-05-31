# JWT Decode

![GitHub tag (latest by date)](https://img.shields.io/docker/v/tmaxcloudck/jwt-decode/5.0.0.3)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/tmaxcloudck/jwt-decode/5.0.0.3)
[![Go Report Card](https://goreportcard.com/badge/github.com/tmax-cloud/jwt-decode)](https://goreportcard.com/report/github.com/tmax-cloud/jwt-decode)

jwt-decode는 HyperCloud API Gateway에서 token의 검증이나 교체가 필요한 경우에 사용되는 middleware이다.
- 어떠한 상황에 이 middleware를 사용할지는 Ingress 혹은 IngressRoute를 통해 설정한다.
- middleware가 사용되는 상황이면, API Gateway의 요청이 middleware를 거쳐 가공된 후 다시 API Gateway로 되돌아간다.
- 참고 : [Traefik Proxy Middleware Overview](https://doc.traefik.io/traefik/middlewares/overview/)
![middleware](https://doc.traefik.io/traefik/assets/img/middleware/overview.png)

jwt-decode는 그 중 ForwardAuth 기능을 수행하는 middleware로써, 원본 프로젝트는 [SimonSchneider](https://github.com/SimonSchneider)의 [traefik-jwt-decode](https://github.com/SimonSchneider/traefik-jwt-decode)이다.
원작자가 의도한 바는 아래와 같이 요약된다.
- Implementation that decodes and validates JWT (JWS) tokens and populates headers with configurable claims from the token.
- The tokens are validated using jwks, checked for expiration and cached.
- 참고 : [Traefik ForwardAuth Documentation](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
![forwardauth](https://doc.traefik.io/traefik/assets/img/middleware/authforward.png)


이 미들웨어가 토큰을 처리하는 방식은 아래와 같다.

- token의 issuer가 serviceaccount, hyperauth 인 경우가 아니라면 `UNAUTHORIZED 401`.
- token의 issuer가 serviceaccount 인 경우 (정확히는 `kubernetes/serviceaccount`)
  - prometheus, alert manager, hypercloud api server로의 요청인 경우, token을 검증한다.
    - 여기서의 token 검증은, 해당 token에 들어있는 namespace와 name 정보를 사용하여 실제로 kubernetes cluster에 해당 token이 존재하고 그 값이 일치하는지 여부를 확인하는 것이다.
    - token 검증에 실패하면 `UNAUTHORIZED 401`.
  - 그 외의 경우는 추후 kubernetes api server에서 token이 검증될 것이기 때문에, jwt-decode 에서는 검증하지 않는다.
- token의 issuer가 hyperauth인 경우 (예 : `https://hyperauth.tmaxcloud.org/auth/realms/tmax`)
  - prometheus, alert manager, hypercloud api server로의 요청이거나 remote cluster로의 요청인 경우, token을 검증한다.
    - 여기서의 token 검증은, 해당 token이 올바르고 유효한 hyperauth token이 맞는지 여부를 확인하는 것이다.
    - token 검증에 실패하면 `UNAUTHORIZED 401`.
  - remote cluster로의 요청인 경우, 아래의 규칙에 따라 secret을 조회하고, HTTP Request의 Authorization 헤더를 secret 안에 들어있는 token으로 교체한다.
    - 조회 대상 secret = {namespace} 하위의 {escaped email}-{remote cluster name}-token
      - {namespace} : remote cluster가 속한 namespace의 이름
      - {escaped email} : 요청을 보내는 사람의 email 주소에서 `@`는 `-at-`으로, 그 외 특수문자는 모두 `-`으로 교체한 문자열.
        (예 : `hc-admin@tmax.co.kr` -> `hc-admin-at-tmax-co-kr`)
      - {remote cluster name} : remote cluster의 이름
    - remote cluster에서 사용하고자 하는 service account token을 위 규칙에 따라 secret으로 생성해두면, hyperauth token 대신에 이렇게 등록된 token을 사용하여 remote cluster로 요청을 보낼 수 있다.
      - secret의 data에서 key로 `token`을, value로 `{token 문자열}`을 사용한다고 가정한다.
      - secret의 type은 `Opaque`든 `kubernetes.io/service-account-token`이든 상관이 없다.
  - 그 외의 경우는 추후 kubernetes api server에서 token이 검증될 것이기 때문에, jwt-decode 에서는 검증하지 않는다.

token 검증에 실패한 경우를 제외하면, HTTP 헤더에 `jwt-token-validated: true`가 추가된다.
(`TOKEN_VALIDATED_HEADER_KEY` 설정을 통해 `jwt-token-validated` 대신 다른 문자열을 사용할 수도 있다.)

Traefik should be configured to forward these headers via the `authResponseHeaders` which forwards them to the end destination.

## 설정 정보

필수적인 설정값 : `JWKS_URL`
- url pointing at the jwks json file (https://auth0.com/docs/tokens/concepts/jwks)
- 예시 값 = `https://hyperauth.tmaxcloud.org/auth/realms/tmax/protocol/openid-connect/certs`


기본값이 제공되는 설정값 :
```
CLAIM_MAPPING_FILE_PATH    = config.json         // 우리는 주로 "/claim-mappings/config.json"를 사용한다.
AUTH_HEADER_KEY            = Authorization
TOKEN_VALIDATED_HEADER_KEY = jwt-token-validated
PORT                       = 8080
LOG_LEVEL                  = info                = trace | debug | info | warn | crit // 우리는 주로 "debug"를 사용한다.
LOG_TYPE                   = json                = json | pretty // 우리의 설정에서는 "pretty"를 사용한다.
MAX_CACHE_KEYS             = 10000
CACHE_ENABLED              = true
FORCE_JWKS_ON_START        = true
MULTI_CLUSTER_PREFIX       = multicluster        // remote cluster로 보내는 요청의 최하위 서브도메인 문자열
```
