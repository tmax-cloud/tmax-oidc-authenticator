package decoder

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt"
	zLog "github.com/rs/zerolog/log"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	statusKey = "status"
)

// Server is a http handler that will use a decoder to decode the authHeaderKey JWT-Token
// and put the resulting claims in headers
type Server struct {
	decoder                 TokenDecoder
	authHeaderKey           string
	tokenValidatedHeaderKey string
	multiClusterPrefix      string
	jwksURL                 string
	clientset               *kubernetes.Clientset
}

// NewServer returns a new server that will decode the header with key authHeaderKey
// with the given TokenDecoder decoder.
func NewServer(decoder TokenDecoder, authHeaderKey, tokenValidatedHeaderKey string, multiClusterPrefix string, jwksURL string, clientset *kubernetes.Clientset) *Server {
	return &Server{decoder: decoder, authHeaderKey: authHeaderKey, tokenValidatedHeaderKey: tokenValidatedHeaderKey, multiClusterPrefix: multiClusterPrefix, jwksURL: jwksURL, clientset: clientset}
}

// DecodeToken http handler
func (s *Server) DecodeToken(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zLog.Ctx(ctx)
	uri := r.Header.Clone().Get("X-Forwarded-Uri")
	var authToken string
	if _, ok := r.Header[s.authHeaderKey]; !ok {
		originQuery, _ := url.ParseQuery(uri)
		queryToken := originQuery.Get("token")
		// log.Debug().Int(statusKey, http.StatusOK).Str(s.tokenValidatedHeaderKey, "false").Msgf("Check query token %s", queryToken)
		if queryToken == "" {
			log.Debug().Int(statusKey, http.StatusUnauthorized).Str(s.tokenValidatedHeaderKey, "false").Msgf("no auth header %s, early exit", s.authHeaderKey)
			rw.Header().Set(s.tokenValidatedHeaderKey, "false")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Debug().Msgf("query token %s, continue", s.authHeaderKey)
			authToken = queryToken
		}
	} else {
		authHeader := r.Header.Clone().Get(s.authHeaderKey)
		authToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	tokenByteArr, err := jwt.DecodeSegment(strings.Split(authToken, ".")[1])
	if err != nil {
		log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to decode jwt token segment.")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	var decodedTokenMap map[string]interface{}
	json.Unmarshal(tokenByteArr, &decodedTokenMap)
	issuer := decodedTokenMap["iss"].(string)

	isServiceAccountToken := issuer == "kubernetes/serviceaccount"
	isHyperAuthToken := strings.Contains(s.jwksURL, issuer)
	isPrometheus := (strings.Contains(uri, "/api/prometheus/")) || (strings.Contains(uri, "/api/prometheus-tenancy/")) || (strings.Contains(uri, "/api/alertmanager/"))
	isHyperCloudAPIServer := (strings.Contains(uri, "/api/hypercloud/")) || (strings.Contains(uri, "/api/multi-hypercloud/"))
	isMultiCluster := strings.Split(r.Header.Clone().Get("X-Forwarded-Host"), ".")[0] == s.multiClusterPrefix

	if !isServiceAccountToken && !isHyperAuthToken {
		log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("token with unknown issuer.")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	if isServiceAccountToken {
		log.Debug().Msgf("received request uri %s with service account token.", uri)
		if isPrometheus || isHyperCloudAPIServer {
			namespace := decodedTokenMap["kubernetes.io/serviceaccount/namespace"].(string)
			secretname := decodedTokenMap["kubernetes.io/serviceaccount/secret.name"].(string)
			secret, err := s.clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretname, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("secret %s not found in %s namespace.", secretname, namespace)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err != nil {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("error getting secret %s in %s namespace: %s", secretname, namespace, err.Error())
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			tokenFromSecret := string(secret.Data["token"][:])
			if tokenFromSecret != authToken {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("token from secret %s in %s namespace is not the same as the given token.", secretname, namespace)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			log.Debug().Int(statusKey, http.StatusOK).Msgf("service account token verified, secretname=%s, namespace=%s", secretname, namespace)
		}
	}

	if isHyperAuthToken {
		if isMultiCluster || isPrometheus || isHyperCloudAPIServer {
			t, err := s.decoder.Decode(ctx, authToken)
			if err != nil {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to decode token")
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err = t.Validate(); err != nil {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to validate token")
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			for k, v := range t.Claims {
				rw.Header().Set(k, v)
				log.Debug().Str(k, v)
			}
		}
		if isMultiCluster {
			log.Debug().Msgf("request to remote cluster %s.", strings.Split(uri, "/")[3])
			re, _ := regexp.Compile("[" + regexp.QuoteMeta(`!#$%&'"*+-/=?^_{|}~().,:;<>[]\`) + "`\\s" + "]")
			email := decodedTokenMap["email"].(string)
			emailEscaped := re.ReplaceAllString(strings.Replace(email, "@", "-at-", -1), "-")
			namespace := strings.Split(uri, "/")[2]
			clustername := strings.Split(uri, "/")[3]
			secretname := emailEscaped + "-" + clustername + "-token"
			secret, err := s.clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretname, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("secret %s not found in %s namespace.", secretname, namespace)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err != nil {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("error getting secret %s in %s namespace: %s", secretname, namespace, err.Error())
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			authToken = string(secret.Data["token"][:])
			log.Debug().Int(statusKey, http.StatusOK).Msgf("using token from secret %s in namespace %s.", secretname, namespace)
		}
	}

	rw.Header().Set(s.authHeaderKey, "Bearer "+authToken)
	rw.Header().Set(s.tokenValidatedHeaderKey, "true")
	log.Debug().Int(statusKey, http.StatusOK).Msg("ok")
	rw.WriteHeader(http.StatusOK)
	return
}
