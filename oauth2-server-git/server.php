<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2016/12/22
 * Time: 15:03
 */
$dsn      = 'mysql:dbname=oauth;host=localhost';
$username = 'root';
$password = 'wangjia5693';

// error reporting (this is a demo, after all!)
ini_set('display_errors',1);error_reporting(E_ALL);

// Autoloading (composer is preferred, but for this example let's just do this)
require_once('./src/OAuth2/Autoloader.php');
//自动加载
OAuth2\Autoloader::register();

// $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
//存储
$storage = new OAuth2\Storage\Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));

// Pass a storage object or array of storage objects to the OAuth2 server class
//实例化服务端
$server = new OAuth2\Server($storage);

// Add the "Client Credentials" grant type (it is the simplest of the grant types)
$server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage));

// Add the "Authorization Code" grant type (this is where the oauth magic happens)
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage));


// password
$users = array('bshaffer' => array('password' => 'brent123', 'first_name' => 'Brent', 'last_name' => 'Shaffer'));
$storage1 = new OAuth2\Storage\Memory(array('user_credentials' => $users));
$grantType = new OAuth2\GrantType\UserCredentials($storage1);
$server->addGrantType($grantType);

//scope check
$defaultScope = 'basic';
$supportedScopes = array(
    'basic',
    'postonwall',
    'accessphonenumber'
);
$memory = new OAuth2\Storage\Memory(array(
    'default_scope' => $defaultScope,
    'supported_scopes' => $supportedScopes
));
$scopeUtil = new OAuth2\Scope($memory);

$server->setScopeUtil($scopeUtil);