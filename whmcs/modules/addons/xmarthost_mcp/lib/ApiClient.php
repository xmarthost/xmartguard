<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

class ApiException extends \Exception
{
}

/**
 * Calls the WHMCS API, either over HTTP with an API credential
 * (identifier + secret, the default) or in-process with localAPI().
 */
class ApiClient
{
    private $mode;
    private $url;
    private $identifier;
    private $secret;
    private $accessKey;
    private $verifySsl;
    private $localAdmin;

    public function __construct($mode, $url, $identifier, $secret, $accessKey = '', $verifySsl = true, $localAdmin = '')
    {
        $this->mode = $mode === 'local' ? 'local' : 'api';
        $this->url = self::normalizeUrl($url);
        $this->identifier = (string) $identifier;
        $this->secret = (string) $secret;
        $this->accessKey = (string) $accessKey;
        $this->verifySsl = (bool) $verifySsl;
        $this->localAdmin = (string) $localAdmin;
    }

    public static function fromSettings()
    {
        return new self(
            Settings::get('connection_mode'),
            Settings::get('api_url') !== '' ? Settings::get('api_url') : Settings::systemUrl(),
            Settings::get('api_identifier'),
            Settings::get('api_secret'),
            Settings::get('api_accesskey'),
            Settings::bool('verify_ssl'),
            Settings::get('local_admin')
        );
    }

    /** Accepts the WHMCS root URL or the full api.php URL. */
    public static function normalizeUrl($url)
    {
        $url = trim((string) $url);
        if ($url === '') {
            return '';
        }
        if (!preg_match('#/includes/api\.php$#i', $url)) {
            $url = rtrim($url, '/') . '/includes/api.php';
        }
        return $url;
    }

    public function mode()
    {
        return $this->mode;
    }

    public function url()
    {
        return $this->url;
    }

    public function isConfigured()
    {
        if ($this->mode === 'local') {
            return function_exists('localAPI');
        }
        return $this->url !== '' && $this->identifier !== '' && $this->secret !== '';
    }

    /**
     * @return array decoded API response
     * @throws ApiException
     */
    public function call($action, array $params = [])
    {
        if (!$this->isConfigured()) {
            throw new ApiException('The WHMCS API connection is not configured. Open Addons > XMart Host MCP > API Connection.');
        }
        unset($params['action'], $params['identifier'], $params['secret'], $params['accesskey'], $params['username'], $params['password'], $params['responsetype']);

        $result = $this->mode === 'local' ? $this->callLocal($action, $params) : $this->callHttp($action, $params);

        if (!is_array($result)) {
            throw new ApiException('WHMCS returned an unreadable response for ' . $action . '.');
        }
        if (isset($result['result']) && $result['result'] === 'error') {
            $msg = isset($result['message']) ? (string) $result['message'] : 'unknown error';
            throw new ApiException($action . ' failed: ' . $msg);
        }
        return $result;
    }

    private function callLocal($action, array $params)
    {
        if ($this->localAdmin !== '') {
            return localAPI($action, $params, $this->localAdmin);
        }
        return localAPI($action, $params);
    }

    private function callHttp($action, array $params)
    {
        $post = array_merge($params, [
            'action' => $action,
            'identifier' => $this->identifier,
            'secret' => $this->secret,
            'responsetype' => 'json',
        ]);
        if ($this->accessKey !== '') {
            $post['accesskey'] = $this->accessKey;
        }

        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($post),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 90,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => $this->verifySsl,
            CURLOPT_SSL_VERIFYHOST => $this->verifySsl ? 2 : 0,
            CURLOPT_USERAGENT => 'XMartHost-MCP/' . XMH_MCP_VERSION,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $body = curl_exec($ch);
        $err = curl_error($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false) {
            throw new ApiException('Could not reach the WHMCS API at ' . $this->url . ': ' . $err);
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            $hint = $code === 403 ? ' (HTTP 403: add this server\'s IP under Setup > General Settings > Security > API IP Access Restriction, or set an API Access Key)' : ' (HTTP ' . $code . ')';
            throw new ApiException('The WHMCS API did not return JSON' . $hint . '.');
        }
        return $data;
    }
}
