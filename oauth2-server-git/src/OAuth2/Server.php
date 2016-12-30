<?php

namespace OAuth2;

use OAuth2\Controller\ResourceControllerInterface;
use OAuth2\Controller\ResourceController;
use OAuth2\OpenID\Controller\UserInfoControllerInterface;
use OAuth2\OpenID\Controller\UserInfoController;
use OAuth2\OpenID\Controller\AuthorizeController as OpenIDAuthorizeController;
use OAuth2\OpenID\ResponseType\AuthorizationCode as OpenIDAuthorizationCodeResponseType;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use OAuth2\OpenID\GrantType\AuthorizationCode as OpenIDAuthorizationCodeGrantType;
use OAuth2\Controller\AuthorizeControllerInterface;
use OAuth2\Controller\AuthorizeController;
use OAuth2\Controller\TokenControllerInterface;
use OAuth2\Controller\TokenController;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\ClientAssertionType\HttpBasic;
use OAuth2\ResponseType\ResponseTypeInterface;
use OAuth2\ResponseType\AuthorizationCode as AuthorizationCodeResponseType;
use OAuth2\ResponseType\AccessToken;
use OAuth2\ResponseType\JwtAccessToken;
use OAuth2\OpenID\ResponseType\CodeIdToken;
use OAuth2\OpenID\ResponseType\IdToken;
use OAuth2\OpenID\ResponseType\IdTokenToken;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\TokenType\Bearer;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\GrantType\UserCredentials;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\Storage\JwtAccessToken as JwtAccessTokenStorage;
use OAuth2\Storage\JwtAccessTokenInterface;

/**
* Server class for OAuth2
* This class serves as a convience class which wraps the other Controller classes
*
* @see OAuth2\Controller\ResourceController
* @see OAuth2\Controller\AuthorizeController
* @see OAuth2\Controller\TokenController
*/
class Server implements ResourceControllerInterface,
    AuthorizeControllerInterface,
    TokenControllerInterface,
    UserInfoControllerInterface
{
    // misc properties
    protected $response;
    protected $config;
    protected $storages;

    // servers
    protected $authorizeController;
    protected $tokenController;
    protected $resourceController;
    protected $userInfoController;

    // config classes
    protected $grantTypes;
    protected $responseTypes;
    protected $tokenType;
    protected $scopeUtil;
    protected $clientAssertionType;

    protected $storageMap = array(
        'access_token' => 'OAuth2\Storage\AccessTokenInterface',
        'authorization_code' => 'OAuth2\Storage\AuthorizationCodeInterface',
        'client_credentials' => 'OAuth2\Storage\ClientCredentialsInterface',
        'client' => 'OAuth2\Storage\ClientInterface',
        'refresh_token' => 'OAuth2\Storage\RefreshTokenInterface',
        'user_credentials' => 'OAuth2\Storage\UserCredentialsInterface',
        'user_claims' => 'OAuth2\OpenID\Storage\UserClaimsInterface',
        'public_key' => 'OAuth2\Storage\PublicKeyInterface',
        'jwt_bearer' => 'OAuth2\Storage\JWTBearerInterface',
        'scope' => 'OAuth2\Storage\ScopeInterface',
    );

    protected $responseTypeMap = array(
        'token' => 'OAuth2\ResponseType\AccessTokenInterface',
        'code' => 'OAuth2\ResponseType\AuthorizationCodeInterface',
        'id_token' => 'OAuth2\OpenID\ResponseType\IdTokenInterface',
        'id_token token' => 'OAuth2\OpenID\ResponseType\IdTokenTokenInterface',
        'code id_token' => 'OAuth2\OpenID\ResponseType\CodeIdTokenInterface',
    );

    /**
     */
    public function __construct($storage = array(), array $config = array(), array $grantTypes = array(), array $responseTypes = array(), TokenTypeInterface $tokenType = null, ScopeInterface $scopeUtil = null, ClientAssertionTypeInterface $clientAssertionType = null)
    {
        $storage = is_array($storage) ? $storage : array($storage);
        $this->storages = array();

        foreach ($storage as $key => $service) {
            $this->addStorage($service, $key);
        }

        // merge all config values.  These get passed to our controller objects
        $this->config = array_merge(array(
            'use_jwt_access_tokens'        => false,
            'store_encrypted_token_string' => true,
            'use_openid_connect'       => false,
            'id_lifetime'              => 3600,
            'access_lifetime'          => 3600,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'enforce_state'            => true,
            'require_exact_redirect_uri' => true,
            'allow_implicit'           => false,
            'allow_credentials_in_request_body' => true,
            'allow_public_clients'     => true,
            'always_issue_new_refresh_token' => false,
            'unset_refresh_token_after_use' => true,
        ), $config);

        foreach ($grantTypes as $key => $grantType) {
            $this->addGrantType($grantType, $key);
        }

        foreach ($responseTypes as $key => $responseType) {
            $this->addResponseType($responseType, $key);
        }

        $this->tokenType = $tokenType;
        $this->scopeUtil = $scopeUtil;
        $this->clientAssertionType = $clientAssertionType;

        if ($this->config['use_openid_connect']) {
            $this->validateOpenIdConnect();
        }
    }
//获得Authorize控制器
    public function getAuthorizeController()
    {
        if (is_null($this->authorizeController)) {
            $this->authorizeController = $this->createDefaultAuthorizeController();
        }

        return $this->authorizeController;
    }
//获得Token控制器
    public function getTokenController()
    {
        if (is_null($this->tokenController)) {
            $this->tokenController = $this->createDefaultTokenController();
        }

        return $this->tokenController;
    }
//获得Resource控制器
    public function getResourceController()
    {
        if (is_null($this->resourceController)) {
            $this->resourceController = $this->createDefaultResourceController();
        }

        return $this->resourceController;
    }
//获得用户信息控制器
    public function getUserInfoController()
    {
        if (is_null($this->userInfoController)) {
            $this->userInfoController = $this->createDefaultUserInfoController();
        }

        return $this->userInfoController;
    }

    /**
     * 自定义Authorize控制器
     */
    public function setAuthorizeController(AuthorizeControllerInterface $authorizeController)
    {
        $this->authorizeController = $authorizeController;
    }

    /**
     * 自定义token控制器
     */
    public function setTokenController(TokenControllerInterface $tokenController)
    {
        $this->tokenController = $tokenController;
    }

    /**
     * 自定义Resource控制器
     */
    public function setResourceController(ResourceControllerInterface $resourceController)
    {
        $this->resourceController = $resourceController;
    }

    /**
     * every getter deserves a setter
     */
    public function setUserInfoController(UserInfoControllerInterface $userInfoController)
    {
        $this->userInfoController = $userInfoController;
    }

    /**
     * 处理UserInfo请求
     */
    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getUserInfoController()->handleUserInfoRequest($request, $this->response);

        return $this->response;
    }

    /**
     * 处理Token请求
     */
    public function handleTokenRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getTokenController()->handleTokenRequest($request, $this->response);

        return $this->response;
    }
    /**
     * 获得token
     */
    public function grantAccessToken(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getTokenController()->grantAccessToken($request, $this->response);

        return $value;
    }

    /**
     * Handle a revoke token request
     * This would be called from the "/revoke" endpoint as defined in the draft Token Revocation spec
     */
    public function handleRevokeRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getTokenController()->handleRevokeRequest($request, $this->response);

        return $this->response;
    }

    /**
     * 处理Authorize请求
     */
    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null)
    {
        $this->response = $response;
        $this->getAuthorizeController()->handleAuthorizeRequest($request, $this->response, $is_authorized, $user_id);

        return $this->response;
    }

    /**
     * 验证Authorize请求
     */
    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request, $this->response);

        return $value;
    }
    /**
     * 验证资源请求
     */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response = null, $scope = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getResourceController()->verifyResourceRequest($request, $this->response, $scope);

        return $value;
    }
    /**
     * 获取AccessToken信息
     */
    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getResourceController()->getAccessTokenData($request, $this->response);

        return $value;
    }

    /**
     * 增加授权类型
     */
    public function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (!is_string($identifier)) {
            $identifier = $grantType->getQuerystringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;

        // persist added grant type down to TokenController
        if (!is_null($this->tokenController)) {
            $this->getTokenController()->addGrantType($grantType, $identifier);
        }
    }

    /**
     * Set a storage object for the server
     */
    public function addStorage($storage, $key = null)
    {
        // if explicitly set to a valid key, do not "magically" set below
        if (isset($this->storageMap[$key])) {
            if (!is_null($storage) && !$storage instanceof $this->storageMap[$key]) {
                throw new \InvalidArgumentException(sprintf('storage of type "%s" must implement interface "%s"', $key, $this->storageMap[$key]));
            }
            $this->storages[$key] = $storage;

            // special logic to handle "client" and "client_credentials" strangeness
            if ($key === 'client' && !isset($this->storages['client_credentials'])) {
                if ($storage instanceof \OAuth2\Storage\ClientCredentialsInterface) {
                    $this->storages['client_credentials'] = $storage;
                }
            } elseif ($key === 'client_credentials' && !isset($this->storages['client'])) {
                if ($storage instanceof \OAuth2\Storage\ClientInterface) {
                    $this->storages['client'] = $storage;
                }
            }
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown storage key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->storageMap))));
        } else {
            $set = false;
            foreach ($this->storageMap as $type => $interface) {
                if ($storage instanceof $interface) {
                    $this->storages[$type] = $storage;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('storage of class "%s" must implement one of [%s]', get_class($storage), implode(', ', $this->storageMap)));
            }
        }
    }

    public function addResponseType(ResponseTypeInterface $responseType, $key = null)
    {
        $key = $this->normalizeResponseType($key);

        if (isset($this->responseTypeMap[$key])) {
            if (!$responseType instanceof $this->responseTypeMap[$key]) {
                throw new \InvalidArgumentException(sprintf('responseType of type "%s" must implement interface "%s"', $key, $this->responseTypeMap[$key]));
            }
            $this->responseTypes[$key] = $responseType;
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown responseType key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->responseTypeMap))));
        } else {
            $set = false;
            foreach ($this->responseTypeMap as $type => $interface) {
                if ($responseType instanceof $interface) {
                    $this->responseTypes[$type] = $responseType;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('Unknown response type %s.  Please implement one of [%s]', get_class($responseType), implode(', ', $this->responseTypeMap)));
            }
        }
    }

    //获得scope操作实例
    public function getScopeUtil()
    {
        if (!$this->scopeUtil) {
            $storage = isset($this->storages['scope']) ? $this->storages['scope'] : null;
            $this->scopeUtil = new Scope($storage);
        }

        return $this->scopeUtil;
    }

    /**
     * 自定义scope操作实例
     */
    public function setScopeUtil($scopeUtil)
    {
        $this->scopeUtil = $scopeUtil;
    }

    //创建默认授权控制器
    protected function createDefaultAuthorizeController()
    {
        if (!isset($this->storages['client'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\ClientInterface to use the authorize server");
        }
        if (0 == count($this->responseTypes)) {
            $this->responseTypes = $this->getDefaultResponseTypes();
        }
        if ($this->config['use_openid_connect'] && !isset($this->responseTypes['id_token'])) {
            $this->responseTypes['id_token'] = $this->createDefaultIdTokenResponseType();
            if ($this->config['allow_implicit']) {
                $this->responseTypes['id_token token'] = $this->createDefaultIdTokenTokenResponseType();
            }
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_implicit enforce_state require_exact_redirect_uri')));

        if ($this->config['use_openid_connect']) {
            return new OpenIDAuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
        }

        return new AuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
    }

    protected function createDefaultTokenController()
    {
        if (0 == count($this->grantTypes)) {
            $this->grantTypes = $this->getDefaultGrantTypes();
        }

        if (is_null($this->clientAssertionType)) {
            // see if HttpBasic assertion type is requred.  If so, then create it from storage classes.
            foreach ($this->grantTypes as $grantType) {
                if (!$grantType instanceof ClientAssertionTypeInterface) {
                    if (!isset($this->storages['client_credentials'])) {
                        throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\ClientCredentialsInterface to use the token server");
                    }
                    $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_credentials_in_request_body allow_public_clients')));
                    $this->clientAssertionType = new HttpBasic($this->storages['client_credentials'], $config);
                    break;
                }
            }
        }

        if (!isset($this->storages['client'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\ClientInterface to use the token server");
        }

        $accessTokenResponseType = $this->getAccessTokenResponseType();

        return new TokenController($accessTokenResponseType, $this->storages['client'], $this->grantTypes, $this->clientAssertionType, $this->getScopeUtil());
    }

    protected function createDefaultResourceController()
    {
        if ($this->config['use_jwt_access_tokens']) {
            // overwrites access token storage with crypto token storage if "use_jwt_access_tokens" is set
            if (!isset($this->storages['access_token']) || !$this->storages['access_token'] instanceof JwtAccessTokenInterface) {
                $this->storages['access_token'] = $this->createDefaultJwtAccessTokenStorage();
            }
        } elseif (!isset($this->storages['access_token'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\AccessTokenInterface or use JwtAccessTokens to use the resource server");
        }

        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }

        $config = array_intersect_key($this->config, array('www_realm' => ''));

        return new ResourceController($this->tokenType, $this->storages['access_token'], $config, $this->getScopeUtil());
    }

    protected function createDefaultUserInfoController()
    {
        if ($this->config['use_jwt_access_tokens']) {
            // overwrites access token storage with crypto token storage if "use_jwt_access_tokens" is set
            if (!isset($this->storages['access_token']) || !$this->storages['access_token'] instanceof JwtAccessTokenInterface) {
                $this->storages['access_token'] = $this->createDefaultJwtAccessTokenStorage();
            }
        } elseif (!isset($this->storages['access_token'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\AccessTokenInterface or use JwtAccessTokens to use the UserInfo server");
        }

        if (!isset($this->storages['user_claims'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use the UserInfo server");
        }

        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }

        $config = array_intersect_key($this->config, array('www_realm' => ''));

        return new UserInfoController($this->tokenType, $this->storages['access_token'], $this->storages['user_claims'], $config, $this->getScopeUtil());
    }

    protected function getDefaultTokenType()
    {
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));

        return new Bearer($config);
    }

    //获得默认的反应类型
    protected function getDefaultResponseTypes()
    {
        $responseTypes = array();

        if ($this->config['allow_implicit']) {
            $responseTypes['token'] = $this->getAccessTokenResponseType();
        }

        if ($this->config['use_openid_connect']) {
            $responseTypes['id_token'] = $this->getIdTokenResponseType();
            if ($this->config['allow_implicit']) {
                $responseTypes['id_token token'] = $this->getIdTokenTokenResponseType();
            }
        }

        if (isset($this->storages['authorization_code'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'enforce_redirect auth_code_lifetime')));
            if ($this->config['use_openid_connect']) {
                if (!$this->storages['authorization_code'] instanceof OpenIDAuthorizationCodeInterface) {
                    throw new \LogicException("Your authorization_code storage must implement OAuth2\OpenID\Storage\AuthorizationCodeInterface to work when 'use_openid_connect' is true");
                }
                $responseTypes['code'] = new OpenIDAuthorizationCodeResponseType($this->storages['authorization_code'], $config);
                $responseTypes['code id_token'] = new CodeIdToken($responseTypes['code'], $responseTypes['id_token']);
            } else {
                $responseTypes['code'] = new AuthorizationCodeResponseType($this->storages['authorization_code'], $config);
            }
        }

        if (count($responseTypes) == 0) {
            throw new \LogicException("You must supply an array of response_types in the constructor or implement a OAuth2\Storage\AuthorizationCodeInterface storage object or set 'allow_implicit' to true and implement a OAuth2\Storage\AccessTokenInterface storage object");
        }

        return $responseTypes;
    }

    protected function getDefaultGrantTypes()
    {
        $grantTypes = array();

        if (isset($this->storages['user_credentials'])) {
            $grantTypes['password'] = new UserCredentials($this->storages['user_credentials']);
        }

        if (isset($this->storages['client_credentials'])) {
            $config = array_intersect_key($this->config, array('allow_credentials_in_request_body' => ''));
            $grantTypes['client_credentials'] = new ClientCredentials($this->storages['client_credentials'], $config);
        }

        if (isset($this->storages['refresh_token'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'always_issue_new_refresh_token unset_refresh_token_after_use')));
            $grantTypes['refresh_token'] = new RefreshToken($this->storages['refresh_token'], $config);
        }

        if (isset($this->storages['authorization_code'])) {
            if ($this->config['use_openid_connect']) {
                if (!$this->storages['authorization_code'] instanceof OpenIDAuthorizationCodeInterface) {
                    throw new \LogicException("Your authorization_code storage must implement OAuth2\OpenID\Storage\AuthorizationCodeInterface to work when 'use_openid_connect' is true");
                }
                $grantTypes['authorization_code'] = new OpenIDAuthorizationCodeGrantType($this->storages['authorization_code']);
            } else {
                $grantTypes['authorization_code'] = new AuthorizationCode($this->storages['authorization_code']);
            }
        }

        if (count($grantTypes) == 0) {
            throw new \LogicException("Unable to build default grant types - You must supply an array of grant_types in the constructor");
        }

        return $grantTypes;
    }

    protected function getAccessTokenResponseType()
    {
        if (isset($this->responseTypes['token'])) {
            return $this->responseTypes['token'];
        }

        if ($this->config['use_jwt_access_tokens']) {
            return $this->createDefaultJwtAccessTokenResponseType();
        }

        return $this->createDefaultAccessTokenResponseType();
    }

    protected function getIdTokenResponseType()
    {
        if (isset($this->responseTypes['id_token'])) {
            return $this->responseTypes['id_token'];
        }

        return $this->createDefaultIdTokenResponseType();
    }

    protected function getIdTokenTokenResponseType()
    {
        if (isset($this->responseTypes['id_token token'])) {
            return $this->responseTypes['id_token token'];
        }

        return $this->createDefaultIdTokenTokenResponseType();
    }

    /**
     * For Resource Controller
     */
    protected function createDefaultJwtAccessTokenStorage()
    {
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use crypto tokens");
        }
        $tokenStorage = null;
        if (!empty($this->config['store_encrypted_token_string']) && isset($this->storages['access_token'])) {
            $tokenStorage = $this->storages['access_token'];
        }
        // wrap the access token storage as required.
        return new JwtAccessTokenStorage($this->storages['public_key'], $tokenStorage);
    }

    /**
     * For Authorize and Token Controllers
     */
    protected function createDefaultJwtAccessTokenResponseType()
    {
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use crypto tokens");
        }

        $tokenStorage = null;
        if (isset($this->storages['access_token'])) {
            $tokenStorage = $this->storages['access_token'];
        }

        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'store_encrypted_token_string issuer access_lifetime refresh_token_lifetime')));

        return new JwtAccessToken($this->storages['public_key'], $tokenStorage, $refreshStorage, $config);
    }

    protected function createDefaultAccessTokenResponseType()
    {
        if (!isset($this->storages['access_token'])) {
            throw new \LogicException("You must supply a response type implementing OAuth2\ResponseType\AccessTokenInterface, or a storage object implementing OAuth2\Storage\AccessTokenInterface to use the token server");
        }

        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'access_lifetime refresh_token_lifetime')));
        $config['token_type'] = $this->tokenType ? $this->tokenType->getTokenType() :  $this->getDefaultTokenType()->getTokenType();

        return new AccessToken($this->storages['access_token'], $refreshStorage, $config);
    }

    protected function createDefaultIdTokenResponseType()
    {
        if (!isset($this->storages['user_claims'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use openid connect");
        }
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use openid connect");
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'issuer id_lifetime')));

        return new IdToken($this->storages['user_claims'], $this->storages['public_key'], $config);
    }

    protected function createDefaultIdTokenTokenResponseType()
    {
        return new IdTokenToken($this->getAccessTokenResponseType(), $this->getIdTokenResponseType());
    }

    protected function validateOpenIdConnect()
    {
        $authCodeGrant = $this->getGrantType('authorization_code');
        if (!empty($authCodeGrant) && !$authCodeGrant instanceof OpenIDAuthorizationCodeGrantType) {
            throw new \InvalidArgumentException('You have enabled OpenID Connect, but supplied a grant type that does not support it.');
        }
    }

    protected function normalizeResponseType($name)
    {
        // for multiple-valued response types - make them alphabetical
        if (!empty($name) && false !== strpos($name, ' ')) {
            $types = explode(' ', $name);
            sort($types);
            $name = implode(' ', $types);
        }

        return $name;
    }

    public function getResponse()
    {
        return $this->response;
    }

    public function getStorages()
    {
        return $this->storages;
    }

    public function getStorage($name)
    {
        return isset($this->storages[$name]) ? $this->storages[$name] : null;
    }

    public function getGrantTypes()
    {
        return $this->grantTypes;
    }

    public function getGrantType($name)
    {
        return isset($this->grantTypes[$name]) ? $this->grantTypes[$name] : null;
    }

    public function getResponseTypes()
    {
        return $this->responseTypes;
    }

    public function getResponseType($name)
    {
        // for multiple-valued response types - make them alphabetical
        $name = $this->normalizeResponseType($name);

        return isset($this->responseTypes[$name]) ? $this->responseTypes[$name] : null;
    }

    public function getTokenType()
    {
        return $this->tokenType;
    }

    public function getClientAssertionType()
    {
        return $this->clientAssertionType;
    }

    public function setConfig($name, $value)
    {
        $this->config[$name] = $value;
    }

    public function getConfig($name, $default = null)
    {
        return isset($this->config[$name]) ? $this->config[$name] : $default;
    }
}
