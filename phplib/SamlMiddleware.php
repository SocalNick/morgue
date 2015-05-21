<?php
// FIXME
date_default_timezone_set('UTC');

class SamlMiddleware extends Slim_Middleware {
    public function call() {
        $this->app->getLog()->debug("Executing SAML Middleware Pre");

        $pathInfo = $this->app->request()->getPathInfo();

        if ($pathInfo != $this->app->urlFor('saml-acs') && !isset($_SESSION['samlNameId'])) {
            $settings = $this->app->samlSettings;
            $authRequest = new OneLogin_Saml2_AuthnRequest($settings);
            $samlRequest = $authRequest->getRequest();
            $parameters = array('SAMLRequest' => $samlRequest);
            $parameters['RelayState'] = $pathInfo;
            $idpData = $settings->getIdPData();
            $ssoUrl = $idpData['singleSignOnService']['url'];
            $url = OneLogin_Saml2_Utils::redirect($ssoUrl, $parameters, true);
            $this->app->redirect($url);
        }

        $this->next->call();
        $this->app->getLog()->debug("Executing SAML Middleware Post");
    }
}

function morgue_get_user_data() {
    if (!isset($_SESSION['samlNameId'])) {
        return;
    }

    return array("username" => $_SESSION['samlNameId']);
}

$app->post('/saml/consume', function() use ($app) {
    if (!isset($_POST['SAMLResponse'])) {
        throw new Exception('No SAML Response found in POST');
    }

    $settings = $app->samlSettings;
    $samlResponse = new OneLogin_Saml2_Response($settings, $_POST['SAMLResponse']);
    if (!$samlResponse->isValid()) {
        throw new Exception('Invalid SAML Response');
    }

    $_SESSION['samlNameId'] = $samlResponse->getNameId();
    $_SESSION['samlUserdata'] = $samlResponse->getAttributes();
    $_SESSION['IdPSessionIndex'] = $samlResponse->getSessionIndex();

    if (isset($_POST['RelayState']) && $_POST['RelayState'] != $app->request()->getPathInfo()) {
        $app->redirect($_POST['RelayState']);
    }
})->name('saml-acs');

$app->get('/saml-sls', function() use ($app) {
    die('SLS!');
})->name('saml-sls');

$app->get('/saml/metadata', function() use ($app) {
    $settings = $app->samlSettings;
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);
    if (!empty($errors)) {
        throw new OneLogin_Saml2_Error(
            'Invalid SP metadata: '.implode(', ', $errors),
            OneLogin_Saml2_Error::METADATA_SP_INVALID
        );
    }

    $app->response()->header('Content-Type', 'text/xml');
    echo $metadata;
})->name('saml-metadata');
