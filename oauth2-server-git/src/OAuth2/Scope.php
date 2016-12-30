<?php

namespace OAuth2;

use OAuth2\Storage\Memory;
use OAuth2\Storage\ScopeInterface as ScopeStorageInterface;

/**
* @see OAuth2\ScopeInterface
*/
class Scope implements ScopeInterface
{
    protected $storage;

    /**
     * @param mixed @storage
     * Either an array of supported scopes, or an instance of OAuth2\Storage\ScopeInterface
     */
    public function __construct($storage = null)
    {
        if (is_null($storage) || is_array($storage)) {
            $storage = new Memory((array) $storage);
        }

        if (!$storage instanceof ScopeStorageInterface) {
            throw new \InvalidArgumentException("Argument 1 to OAuth2\Scope must be null, an array, or instance of OAuth2\Storage\ScopeInterface");
        }

        $this->storage = $storage;
    }

    /**
     * Check if everything in required scope is contained in available scope.
     *判断请求的是否都在可用的范围内
     */
    public function checkScope($required_scope, $available_scope)
    {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    /**
     * Check if the provided scope exists in storage.
     *$scope是否在'openid', 'offline_access
     */
    public function scopeExists($scope)
    {
        // Check reserved scopes first.
        $scope = explode(' ', trim($scope));
        $reservedScope = $this->getReservedScopes();
        $nonReservedScopes = array_diff($scope, $reservedScope);
        if (count($nonReservedScopes) == 0) {
            return true;
        } else {
            // Check the storage for non-reserved scopes.
            $nonReservedScopes = implode(' ', $nonReservedScopes);

            return $this->storage->scopeExists($nonReservedScopes);
        }
    }

    //从请求中获取scope
    public function getScopeFromRequest(RequestInterface $request)
    {
        // "scope" is valid if passed in either POST or QUERY
        return $request->request('scope', $request->query('scope'));
    }

    public function getDefaultScope($client_id = null)
    {
        return $this->storage->getDefaultScope($client_id);
    }

    /**
     * Get reserved scopes needed by the server.
     *
     * In case OpenID Connect is used, these scopes must include:
     * 'openid', offline_access'.
     *
     * @return
     * An array of reserved scopes.
     */
    public function getReservedScopes()
    {
        return array('openid', 'offline_access');
    }
}
