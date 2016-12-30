<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2016/12/22
 * Time: 15:11
 */
require_once __DIR__.'/server.php';

// Handle a request for an OAuth2.0 Access Token and send the response to the client
$server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();

//curl -u testclient:testpass http://localhost:1689/token.php --data "grant_type=password&username=bshaffer&password=brent123"
//curl  http://localhost:1689/resource.php -d "access_token=2dc136ff2796bd50829526d393fd0297d155f518"
