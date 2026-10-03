<?php
// Stand-in for WHMCS's includes/api.php: checks identifier/secret, then answers with the fake localAPI.
require __DIR__ . '/../../bootstrap.php';
header('Content-Type: application/json');
if (($_POST['identifier'] ?? '') !== 'ID123' || ($_POST['secret'] ?? '') !== 'SECRET456') {
    echo json_encode(['result' => 'error', 'message' => 'Authentication Failed']);
    exit;
}
if (($_POST['responsetype'] ?? '') !== 'json') {
    echo 'result=error;message=xml';
    exit;
}
$params = $_POST;
$action = $params['action'];
unset($params['action'], $params['identifier'], $params['secret'], $params['responsetype'], $params['accesskey']);
echo json_encode(localAPI($action, $params));
