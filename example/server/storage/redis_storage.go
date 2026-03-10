package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	keyPrefixAuthRequest = "auth_request:"
	keyPrefixCode        = "code:"
	keyPrefixToken       = "token:"
	keyPrefixRefresh     = "refresh_token:"
	keyPrefixClient      = "client:"
	keyPrefixServiceUser = "service_user:"
	keyPrefixDeviceCode  = "device_code:"
	keyPrefixUserCode    = "user_code:"

	authRequestTTL = 30 * time.Minute
	codeTTL        = 10 * time.Minute
	accessTokenTTL = 5 * time.Minute
	refreshTokenTTL = 5 * time.Hour
)

var (
	_ op.Storage                  = &RedisStorage{}
	_ op.ClientCredentialsStorage = &RedisStorage{}
)

type RedisStorage struct {
	rdb        redis.Cmdable
	prefix     string
	userStore  UserStore
	signingKey signingKey
	services   map[string]Service
}

func NewRedisStorage(rdb redis.Cmdable, userStore UserStore, prefix string) *RedisStorage {
	if prefix == "" {
		prefix = "oidc:"
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &RedisStorage{
		rdb:    rdb,
		prefix: prefix,
		userStore: userStore,
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.RS256,
			key:       key,
		},
		services: map[string]Service{
			userStore.ExampleClientID(): {
				keys: map[string]*rsa.PublicKey{
					ServiceUserKeyID: serviceKey1,
				},
			},
		},
	}
	s.registerClients()
	return s
}

func (s *RedisStorage) key(parts ...string) string {
	return s.prefix + strings.Join(parts, "")
}

// ----- serializable wrappers for AuthRequest (which has unexported fields) -----

type authRequestJSON struct {
	ID            string             `json:"id"`
	CreationDate  time.Time          `json:"creation_date"`
	ApplicationID string             `json:"application_id"`
	CallbackURI   string             `json:"callback_uri"`
	TransferState string             `json:"transfer_state"`
	Prompt        []string           `json:"prompt"`
	LoginHint     string             `json:"login_hint"`
	MaxAuthAge    *time.Duration     `json:"max_auth_age"`
	UserID        string             `json:"user_id"`
	Scopes        []string           `json:"scopes"`
	ResponseType  oidc.ResponseType  `json:"response_type"`
	ResponseMode  oidc.ResponseMode  `json:"response_mode"`
	Nonce         string             `json:"nonce"`
	CodeChallenge *OIDCCodeChallenge `json:"code_challenge"`
	Done          bool               `json:"done"`
	AuthTime      time.Time          `json:"auth_time"`
}

func marshalAuthRequest(a *AuthRequest) ([]byte, error) {
	return json.Marshal(authRequestJSON{
		ID:            a.ID,
		CreationDate:  a.CreationDate,
		ApplicationID: a.ApplicationID,
		CallbackURI:   a.CallbackURI,
		TransferState: a.TransferState,
		Prompt:        a.Prompt,
		LoginHint:     a.LoginHint,
		MaxAuthAge:    a.MaxAuthAge,
		UserID:        a.UserID,
		Scopes:        a.Scopes,
		ResponseType:  a.ResponseType,
		ResponseMode:  a.ResponseMode,
		Nonce:         a.Nonce,
		CodeChallenge: a.CodeChallenge,
		Done:          a.done,
		AuthTime:      a.authTime,
	})
}

func unmarshalAuthRequest(data []byte) (*AuthRequest, error) {
	var j authRequestJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &AuthRequest{
		ID:            j.ID,
		CreationDate:  j.CreationDate,
		ApplicationID: j.ApplicationID,
		CallbackURI:   j.CallbackURI,
		TransferState: j.TransferState,
		Prompt:        j.Prompt,
		LoginHint:     j.LoginHint,
		MaxAuthAge:    j.MaxAuthAge,
		UserID:        j.UserID,
		Scopes:        j.Scopes,
		ResponseType:  j.ResponseType,
		ResponseMode:  j.ResponseMode,
		Nonce:         j.Nonce,
		CodeChallenge: j.CodeChallenge,
		done:          j.Done,
		authTime:      j.AuthTime,
	}, nil
}

// ----- serializable wrapper for Client -----

type clientJSON struct {
	ID                             string             `json:"id"`
	Secret                         string             `json:"secret"`
	RedirectURIs                   []string           `json:"redirect_uris"`
	PostLogoutRedirectURIs         []string           `json:"post_logout_redirect_uris"`
	ApplicationType                op.ApplicationType `json:"application_type"`
	AuthMethod                     oidc.AuthMethod    `json:"auth_method"`
	ResponseTypes                  []oidc.ResponseType `json:"response_types"`
	GrantTypes                     []oidc.GrantType   `json:"grant_types"`
	AccessTokenType                op.AccessTokenType `json:"access_token_type"`
	DevMode                        bool               `json:"dev_mode"`
	IDTokenUserinfoClaimsAssertion bool               `json:"id_token_userinfo_claims_assertion"`
	ClockSkew                      time.Duration      `json:"clock_skew"`
	PostLogoutRedirectURIGlobs     []string           `json:"post_logout_redirect_uri_globs"`
	RedirectURIGlobs               []string           `json:"redirect_uri_globs"`
}

func marshalClient(c *Client) ([]byte, error) {
	return json.Marshal(clientJSON{
		ID:                             c.id,
		Secret:                         c.secret,
		RedirectURIs:                   c.redirectURIs,
		PostLogoutRedirectURIs:         c.postLogoutRedirectURIs,
		ApplicationType:                c.applicationType,
		AuthMethod:                     c.authMethod,
		ResponseTypes:                  c.responseTypes,
		GrantTypes:                     c.grantTypes,
		AccessTokenType:                c.accessTokenType,
		DevMode:                        c.devMode,
		IDTokenUserinfoClaimsAssertion: c.idTokenUserinfoClaimsAssertion,
		ClockSkew:                      c.clockSkew,
		PostLogoutRedirectURIGlobs:     c.postLogoutRedirectURIGlobs,
		RedirectURIGlobs:               c.redirectURIGlobs,
	})
}

func unmarshalClient(data []byte) (*Client, error) {
	var j clientJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &Client{
		id:                             j.ID,
		secret:                         j.Secret,
		redirectURIs:                   j.RedirectURIs,
		postLogoutRedirectURIs:         j.PostLogoutRedirectURIs,
		applicationType:                j.ApplicationType,
		authMethod:                     j.AuthMethod,
		loginURL:                       defaultLoginURL,
		responseTypes:                  j.ResponseTypes,
		grantTypes:                     j.GrantTypes,
		accessTokenType:                j.AccessTokenType,
		devMode:                        j.DevMode,
		idTokenUserinfoClaimsAssertion: j.IDTokenUserinfoClaimsAssertion,
		clockSkew:                      j.ClockSkew,
		postLogoutRedirectURIGlobs:     j.PostLogoutRedirectURIGlobs,
		redirectURIGlobs:               j.RedirectURIGlobs,
	}, nil
}

// ----- Client registration -----

func (s *RedisStorage) registerClients() {
	ctx := context.Background()
	for _, c := range clients {
		data, _ := marshalClient(c)
		s.rdb.Set(ctx, s.key(keyPrefixClient, c.id), data, 0)
	}
	// register default service user
	svcClient := &Client{
		id:     "sid1",
		secret: "verysecret",
		grantTypes: []oidc.GrantType{
			oidc.GrantTypeClientCredentials,
		},
		accessTokenType: op.AccessTokenTypeBearer,
	}
	data, _ := marshalClient(svcClient)
	s.rdb.Set(ctx, s.key(keyPrefixServiceUser, svcClient.id), data, 0)
}

// ===================== authenticate interface =====================

func (s *RedisStorage) CheckUsernamePassword(username, password, id string) error {
	ctx := context.Background()
	data, err := s.rdb.Get(ctx, s.key(keyPrefixAuthRequest, id)).Bytes()
	if err != nil {
		return fmt.Errorf("request not found")
	}
	request, err := unmarshalAuthRequest(data)
	if err != nil {
		return err
	}

	user := s.userStore.GetUserByUsername(username)
	if user != nil && user.Password == password {
		request.UserID = user.ID
		request.done = true
		request.authTime = time.Now()

		updated, err := marshalAuthRequest(request)
		if err != nil {
			return err
		}
		return s.rdb.Set(ctx, s.key(keyPrefixAuthRequest, id), updated, authRequestTTL).Err()
	}
	return fmt.Errorf("username or password wrong")
}

func (s *RedisStorage) CheckUsernamePasswordSimple(username, password string) error {
	user := s.userStore.GetUserByUsername(username)
	if user != nil && user.Password == password {
		return nil
	}
	return fmt.Errorf("username or password wrong")
}

// ===================== AuthStorage =====================

func (s *RedisStorage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		return nil, oidc.ErrLoginRequired()
	}
	request := authRequestToInternal(authReq, userID)
	request.ID = uuid.NewString()

	data, err := marshalAuthRequest(request)
	if err != nil {
		return nil, err
	}
	if err := s.rdb.Set(ctx, s.key(keyPrefixAuthRequest, request.ID), data, authRequestTTL).Err(); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *RedisStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixAuthRequest, id)).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("request not found")
	} else if err != nil {
		return nil, err
	}
	return unmarshalAuthRequest(data)
}

func (s *RedisStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	requestID, err := s.rdb.Get(ctx, s.key(keyPrefixCode, code)).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("code invalid or expired")
	} else if err != nil {
		return nil, err
	}
	return s.AuthRequestByID(ctx, requestID)
}

func (s *RedisStorage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return s.rdb.Set(ctx, s.key(keyPrefixCode, code), id, codeTTL).Err()
}

func (s *RedisStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	s.rdb.Del(ctx, s.key(keyPrefixAuthRequest, id))
	// also clean up any codes pointing to this request
	iter := s.rdb.Scan(ctx, 0, s.key(keyPrefixCode, "*"), 100).Iterator()
	for iter.Next(ctx) {
		val, err := s.rdb.Get(ctx, iter.Val()).Result()
		if err == nil && val == id {
			s.rdb.Del(ctx, iter.Val())
		}
	}
	return nil
}

func (s *RedisStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	var applicationID string
	switch req := request.(type) {
	case *AuthRequest:
		applicationID = req.ApplicationID
	case op.TokenExchangeRequest:
		applicationID = req.GetClientID()
	}

	token := &Token{
		ID:            uuid.NewString(),
		ApplicationID: applicationID,
		Subject:       request.GetSubject(),
		Audience:      request.GetAudience(),
		Expiration:    time.Now().Add(accessTokenTTL),
		Scopes:        request.GetScopes(),
	}
	data, err := json.Marshal(token)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := s.rdb.Set(ctx, s.key(keyPrefixToken, token.ID), data, accessTokenTTL).Err(); err != nil {
		return "", time.Time{}, err
	}
	return token.ID, token.Expiration, nil
}

func (s *RedisStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	if teReq, ok := request.(op.TokenExchangeRequest); ok {
		return s.exchangeRefreshToken(ctx, teReq)
	}

	applicationID, authTime, amr := getInfoFromRequest(request)

	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken := &Token{
			ID:             uuid.NewString(),
			ApplicationID:  applicationID,
			RefreshTokenID: refreshTokenID,
			Subject:        request.GetSubject(),
			Audience:       request.GetAudience(),
			Expiration:     time.Now().Add(accessTokenTTL),
			Scopes:         request.GetScopes(),
		}
		atData, _ := json.Marshal(accessToken)
		s.rdb.Set(ctx, s.key(keyPrefixToken, accessToken.ID), atData, accessTokenTTL)

		refreshToken := &RefreshToken{
			ID:            refreshTokenID,
			Token:         refreshTokenID,
			AuthTime:      authTime,
			AMR:           amr,
			ApplicationID: applicationID,
			UserID:        request.GetSubject(),
			Audience:      request.GetAudience(),
			Expiration:    time.Now().Add(refreshTokenTTL),
			Scopes:        request.GetScopes(),
			AccessToken:   accessToken.ID,
		}
		rtData, _ := json.Marshal(refreshToken)
		s.rdb.Set(ctx, s.key(keyPrefixRefresh, refreshToken.ID), rtData, refreshTokenTTL)

		return accessToken.ID, refreshToken.Token, accessToken.Expiration, nil
	}

	// refresh token rotation
	rtData, err := s.rdb.Get(ctx, s.key(keyPrefixRefresh, currentRefreshToken)).Bytes()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid refresh token")
	}
	var oldRT RefreshToken
	if err := json.Unmarshal(rtData, &oldRT); err != nil {
		return "", "", time.Time{}, err
	}
	if oldRT.Expiration.Before(time.Now()) {
		return "", "", time.Time{}, fmt.Errorf("expired refresh token")
	}

	// delete old refresh + access tokens
	s.rdb.Del(ctx, s.key(keyPrefixRefresh, currentRefreshToken))
	s.rdb.Del(ctx, s.key(keyPrefixToken, oldRT.AccessToken))

	newRefreshTokenID := uuid.NewString()
	accessToken := &Token{
		ID:             uuid.NewString(),
		ApplicationID:  applicationID,
		RefreshTokenID: newRefreshTokenID,
		Subject:        request.GetSubject(),
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(accessTokenTTL),
		Scopes:         request.GetScopes(),
	}
	atData, _ := json.Marshal(accessToken)
	s.rdb.Set(ctx, s.key(keyPrefixToken, accessToken.ID), atData, accessTokenTTL)

	newRT := &RefreshToken{
		ID:            newRefreshTokenID,
		Token:         newRefreshTokenID,
		AuthTime:      oldRT.AuthTime,
		AMR:           oldRT.AMR,
		ApplicationID: applicationID,
		UserID:        request.GetSubject(),
		Audience:      request.GetAudience(),
		Expiration:    time.Now().Add(refreshTokenTTL),
		Scopes:        request.GetScopes(),
		AccessToken:   accessToken.ID,
	}
	newRTData, _ := json.Marshal(newRT)
	s.rdb.Set(ctx, s.key(keyPrefixRefresh, newRT.ID), newRTData, refreshTokenTTL)

	return accessToken.ID, newRT.Token, accessToken.Expiration, nil
}

func (s *RedisStorage) exchangeRefreshToken(ctx context.Context, request op.TokenExchangeRequest) (string, string, time.Time, error) {
	applicationID := request.GetClientID()
	authTime := request.GetAuthTime()

	refreshTokenID := uuid.NewString()
	accessToken := &Token{
		ID:             uuid.NewString(),
		ApplicationID:  applicationID,
		RefreshTokenID: refreshTokenID,
		Subject:        request.GetSubject(),
		Audience:       request.GetAudience(),
		Expiration:     time.Now().Add(accessTokenTTL),
		Scopes:         request.GetScopes(),
	}
	atData, _ := json.Marshal(accessToken)
	s.rdb.Set(ctx, s.key(keyPrefixToken, accessToken.ID), atData, accessTokenTTL)

	refreshToken := &RefreshToken{
		ID:            refreshTokenID,
		Token:         refreshTokenID,
		AuthTime:      authTime,
		ApplicationID: applicationID,
		UserID:        request.GetSubject(),
		Audience:      request.GetAudience(),
		Expiration:    time.Now().Add(refreshTokenTTL),
		Scopes:        request.GetScopes(),
		AccessToken:   accessToken.ID,
	}
	rtData, _ := json.Marshal(refreshToken)
	s.rdb.Set(ctx, s.key(keyPrefixRefresh, refreshToken.ID), rtData, refreshTokenTTL)

	return accessToken.ID, refreshToken.Token, accessToken.Expiration, nil
}

func (s *RedisStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixRefresh, refreshToken)).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("invalid refresh_token")
	} else if err != nil {
		return nil, err
	}
	var token RefreshToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return RefreshTokenRequestFromBusiness(&token), nil
}

func (s *RedisStorage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	// scan access tokens to find matching ones
	iter := s.rdb.Scan(ctx, 0, s.key(keyPrefixToken, "*"), 100).Iterator()
	for iter.Next(ctx) {
		data, err := s.rdb.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			continue
		}
		var token Token
		if json.Unmarshal(data, &token) == nil && token.ApplicationID == clientID && token.Subject == userID {
			s.rdb.Del(ctx, iter.Val())
			if token.RefreshTokenID != "" {
				s.rdb.Del(ctx, s.key(keyPrefixRefresh, token.RefreshTokenID))
			}
		}
	}
	return iter.Err()
}

func (s *RedisStorage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// try as access token
	data, err := s.rdb.Get(ctx, s.key(keyPrefixToken, tokenIDOrToken)).Bytes()
	if err == nil {
		var token Token
		if json.Unmarshal(data, &token) == nil {
			if token.ApplicationID != clientID {
				return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
			}
			s.rdb.Del(ctx, s.key(keyPrefixToken, token.ID))
			return nil
		}
	}
	// try as refresh token
	data, err = s.rdb.Get(ctx, s.key(keyPrefixRefresh, tokenIDOrToken)).Bytes()
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return nil
	}
	var rt RefreshToken
	if json.Unmarshal(data, &rt) != nil {
		return nil
	}
	if rt.ApplicationID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	s.rdb.Del(ctx, s.key(keyPrefixRefresh, rt.ID))
	s.rdb.Del(ctx, s.key(keyPrefixToken, rt.AccessToken))
	return nil
}

func (s *RedisStorage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixRefresh, token)).Bytes()
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	var rt RefreshToken
	if err := json.Unmarshal(data, &rt); err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.UserID, rt.ID, nil
}

func (s *RedisStorage) SigningKey(_ context.Context) (op.SigningKey, error) {
	return &s.signingKey, nil
}

func (s *RedisStorage) SignatureAlgorithms(_ context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

func (s *RedisStorage) KeySet(_ context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s.signingKey}}, nil
}

// ===================== OPStorage =====================

func (s *RedisStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixClient, clientID)).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("client not found")
	} else if err != nil {
		return nil, err
	}
	client, err := unmarshalClient(data)
	if err != nil {
		return nil, err
	}
	return RedirectGlobsClient(client), nil
}

func (s *RedisStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixClient, clientID)).Bytes()
	if err != nil {
		return fmt.Errorf("client not found")
	}
	client, err := unmarshalClient(data)
	if err != nil {
		return err
	}
	if client.secret != clientSecret {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

func (s *RedisStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

func (s *RedisStorage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, token.GetSubject(), token.GetClientID(), scopes)
}

func (s *RedisStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixToken, tokenID)).Bytes()
	if err != nil {
		return fmt.Errorf("token is invalid or has expired")
	}
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return err
	}
	if token.Expiration.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	return s.setUserinfo(ctx, userinfo, token.Subject, token.ApplicationID, token.Scopes)
}

func (s *RedisStorage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixToken, tokenID)).Bytes()
	if err != nil {
		return fmt.Errorf("token is invalid")
	}
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return err
	}
	introspection.Expiration = oidc.FromTime(token.Expiration)
	if token.Expiration.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	for _, aud := range token.Audience {
		if aud == clientID {
			userInfo := new(oidc.UserInfo)
			if err := s.setUserinfo(ctx, userInfo, subject, clientID, token.Scopes); err != nil {
				return err
			}
			introspection.SetUserInfo(userInfo)
			introspection.Scope = token.Scopes
			introspection.ClientID = token.ApplicationID
			return nil
		}
	}
	return fmt.Errorf("token is not valid for this client")
}

func (s *RedisStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	var claims map[string]any
	for _, scope := range scopes {
		if scope == CustomScope {
			claims = appendClaim(claims, CustomClaim, customClaim(clientID))
		}
	}
	return claims, nil
}

func (s *RedisStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	service, ok := s.services[clientID]
	if !ok {
		return nil, fmt.Errorf("clientID not found")
	}
	key, ok := service.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return &jose.JSONWebKey{
		KeyID: keyID,
		Use:   "sig",
		Key:   key,
	}, nil
}

func (s *RedisStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	allowedScopes := make([]string, 0)
	for _, scope := range scopes {
		if scope == oidc.ScopeOpenID {
			allowedScopes = append(allowedScopes, scope)
		}
	}
	return allowedScopes, nil
}

func (s *RedisStorage) Health(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

// ===================== userinfo helper =====================

func (s *RedisStorage) setUserinfo(_ context.Context, userInfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	user := s.userStore.GetUserByID(userID)
	if user == nil {
		return fmt.Errorf("user not found")
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userInfo.Subject = user.ID
		case oidc.ScopeEmail:
			userInfo.Email = user.Email
			userInfo.EmailVerified = oidc.Bool(user.EmailVerified)
		case oidc.ScopeProfile:
			userInfo.PreferredUsername = user.Username
			userInfo.Name = user.FirstName + " " + user.LastName
			userInfo.FamilyName = user.LastName
			userInfo.GivenName = user.FirstName
			userInfo.Locale = oidc.NewLocale(user.PreferredLanguage)
		case oidc.ScopePhone:
			userInfo.PhoneNumber = user.Phone
			userInfo.PhoneNumberVerified = oidc.Bool(user.PhoneVerified)
		case CustomScope:
			userInfo.AppendClaims(CustomClaim, customClaim(clientID))
		}
	}
	return nil
}

// ===================== TokenExchangeStorage =====================

func (s *RedisStorage) ValidateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	if request.GetRequestedTokenType() == "" {
		request.SetRequestedTokenType(oidc.RefreshTokenType)
	}
	if request.GetExchangeSubjectTokenType() == oidc.IDTokenType && request.GetRequestedTokenType() == oidc.RefreshTokenType {
		return errors.New("exchanging id_token to refresh_token is not supported")
	}
	if request.GetExchangeActor() == "" && !s.userStore.GetUserByID(request.GetExchangeSubject()).IsAdmin {
		return errors.New("user doesn't have impersonation permission")
	}

	allowedScopes := make([]string, 0)
	for _, scope := range request.GetScopes() {
		if scope == oidc.ScopeAddress {
			continue
		}
		if strings.HasPrefix(scope, CustomScopeImpersonatePrefix) {
			subject := strings.TrimPrefix(scope, CustomScopeImpersonatePrefix)
			request.SetSubject(subject)
		}
		allowedScopes = append(allowedScopes, scope)
	}
	request.SetCurrentScopes(allowedScopes)
	return nil
}

func (s *RedisStorage) CreateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	return nil
}

func (s *RedisStorage) GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) (map[string]any, error) {
	claims, err := s.GetPrivateClaimsFromScopes(ctx, "", request.GetClientID(), request.GetScopes())
	if err != nil {
		return nil, err
	}
	for _, scope := range request.GetScopes() {
		if strings.HasPrefix(scope, CustomScopeImpersonatePrefix) && request.GetExchangeActor() == "" {
			claims = appendClaim(claims, "act", map[string]any{
				"sub": request.GetExchangeSubject(),
			})
		}
	}
	return claims, nil
}

func (s *RedisStorage) SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.TokenExchangeRequest) error {
	if err := s.setUserinfo(ctx, userinfo, request.GetSubject(), request.GetClientID(), request.GetScopes()); err != nil {
		return err
	}
	for _, scope := range request.GetScopes() {
		if strings.HasPrefix(scope, CustomScopeImpersonatePrefix) && request.GetExchangeActor() == "" {
			userinfo.AppendClaims("act", map[string]any{
				"sub": request.GetExchangeSubject(),
			})
		}
	}
	return nil
}

// ===================== ClientCredentialsStorage =====================

func (s *RedisStorage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixServiceUser, clientID)).Bytes()
	if err != nil {
		return nil, errors.New("wrong service user or password")
	}
	client, err := unmarshalClient(data)
	if err != nil {
		return nil, err
	}
	if client.secret != clientSecret {
		return nil, errors.New("wrong service user or password")
	}
	return client, nil
}

func (s *RedisStorage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	data, err := s.rdb.Get(ctx, s.key(keyPrefixServiceUser, clientID)).Bytes()
	if err != nil {
		return nil, errors.New("wrong service user or password")
	}
	client, err := unmarshalClient(data)
	if err != nil {
		return nil, err
	}
	return &oidc.JWTTokenRequest{
		Subject:  client.id,
		Audience: []string{clientID},
		Scopes:   scopes,
	}, nil
}

// ===================== DeviceAuthorizationStorage =====================

type deviceAuthEntry struct {
	DeviceCode string                      `json:"device_code"`
	UserCode   string                      `json:"user_code"`
	State      *op.DeviceAuthorizationState `json:"state"`
}

func (s *RedisStorage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	// verify client exists
	if _, err := s.rdb.Get(ctx, s.key(keyPrefixClient, clientID)).Result(); err != nil {
		return errors.New("client not found")
	}
	// check duplicate user code
	if _, err := s.rdb.Get(ctx, s.key(keyPrefixUserCode, userCode)).Result(); err == nil {
		return op.ErrDuplicateUserCode
	}

	ttl := time.Until(expires)
	entry := deviceAuthEntry{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		State: &op.DeviceAuthorizationState{
			ClientID: clientID,
			Scopes:   scopes,
			Expires:  expires,
		},
	}
	data, _ := json.Marshal(entry)
	s.rdb.Set(ctx, s.key(keyPrefixDeviceCode, deviceCode), data, ttl)
	s.rdb.Set(ctx, s.key(keyPrefixUserCode, userCode), deviceCode, ttl)
	return nil
}

func (s *RedisStorage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data, err := s.rdb.Get(ctx, s.key(keyPrefixDeviceCode, deviceCode)).Bytes()
	if err != nil {
		return nil, errors.New("device code not found for client")
	}
	var entry deviceAuthEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	if entry.State.ClientID != clientID {
		return nil, errors.New("device code not found for client")
	}
	return entry.State, nil
}

func (s *RedisStorage) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	deviceCode, err := s.rdb.Get(ctx, s.key(keyPrefixUserCode, userCode)).Result()
	if err != nil {
		return nil, errors.New("user code not found")
	}
	data, err := s.rdb.Get(ctx, s.key(keyPrefixDeviceCode, deviceCode)).Bytes()
	if err != nil {
		return nil, errors.New("user code not found")
	}
	var entry deviceAuthEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return entry.State, nil
}

func (s *RedisStorage) CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error {
	deviceCode, err := s.rdb.Get(ctx, s.key(keyPrefixUserCode, userCode)).Result()
	if err != nil {
		return errors.New("user code not found")
	}
	data, err := s.rdb.Get(ctx, s.key(keyPrefixDeviceCode, deviceCode)).Bytes()
	if err != nil {
		return errors.New("user code not found")
	}
	var entry deviceAuthEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	entry.State.Subject = subject
	entry.State.Done = true

	ttl := time.Until(entry.State.Expires)
	updated, _ := json.Marshal(entry)
	return s.rdb.Set(ctx, s.key(keyPrefixDeviceCode, deviceCode), updated, ttl).Err()
}

func (s *RedisStorage) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	deviceCode, err := s.rdb.Get(ctx, s.key(keyPrefixUserCode, userCode)).Result()
	if err != nil {
		return errors.New("user code not found")
	}
	data, err := s.rdb.Get(ctx, s.key(keyPrefixDeviceCode, deviceCode)).Bytes()
	if err != nil {
		return errors.New("user code not found")
	}
	var entry deviceAuthEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	entry.State.Denied = true

	ttl := time.Until(entry.State.Expires)
	updated, _ := json.Marshal(entry)
	return s.rdb.Set(ctx, s.key(keyPrefixDeviceCode, deviceCode), updated, ttl).Err()
}

// AuthRequestDone is used by testing
func (s *RedisStorage) AuthRequestDone(id string) error {
	ctx := context.Background()
	data, err := s.rdb.Get(ctx, s.key(keyPrefixAuthRequest, id)).Bytes()
	if err != nil {
		return errors.New("request not found")
	}
	req, err := unmarshalAuthRequest(data)
	if err != nil {
		return err
	}
	req.done = true
	updated, err := marshalAuthRequest(req)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key(keyPrefixAuthRequest, id), updated, authRequestTTL).Err()
}
