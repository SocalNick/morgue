<?php
// FIXME
date_default_timezone_set('UTC');

class SamlMiddleware extends Slim_Middleware {
    public function call() {
        $this->app->getLog()->debug("Executing SAML Middleware Pre");

        $pathInfo = $this->app->request()->getPathInfo();

        if ($pathInfo != $this->app->urlFor('saml-acs') && !isset($_SESSION['samlUserdata'])) {
          $settings = $this->app->samlSettings;
          $authRequest = new OneLogin_Saml2_AuthnRequest($settings);
          $samlRequest = $authRequest->getRequest();
          $parameters = array('SAMLRequest' => $samlRequest);
          $parameters['RelayState'] = OneLogin_Saml2_Utils::getSelfURLNoQuery();
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
    if (!isset($_SESSION['samlUserdata'])) {
        return;
    }

    return;
    // NEED TO GET USER NICKNAME
    return array("username" => $userDetails->nickname);
}

$app->post('/saml/consume', function() use ($app) {
    try {
        if (isset($_POST['SAMLResponse'])) {
            $settings = $app->samlSettings;
            $samlResponse = new OneLogin_Saml2_Response($settings, $_POST['SAMLResponse']);
            if ($samlResponse->isValid()) {
                echo 'You are: ' . $samlResponse->getNameId() . '<br>';
                $attributes = $samlResponse->getAttributes();
                $_SESSION['samlUserdata'] = $attributes;
                $_SESSION['IdPSessionIndex'] = $samlResponse->getSessionIndex();
                if (!empty($attributes)) {
                    echo 'You have the following attributes:<br>';
                    echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
                    foreach ($attributes as $attributeName => $attributeValues) {
                        echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
                        foreach ($attributeValues as $attributeValue) {
                            echo '<li>' . htmlentities($attributeValue) . '</li>';
                        }
                        echo '</ul></td></tr>';
                    }
                    echo '</tbody></table>';
                }

                var_dump($_SESSION);

                if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
                    var_dump($_POST['RelayState']);
                    die('redirect?');
                    $auth->redirectTo($_POST['RelayState']);
                }
            } else {
                echo 'Invalid SAML Response';
            }
        } else {
            echo 'No SAML Response found in POST.';
        }
    } catch (Exception $e) {
        echo 'Invalid SAML Response: ' . $e->getMessage();
    }
})->name('saml-acs');

$app->get('/saml-sls', function() use ($app) {
    die('SLS!');
})->name('saml-sls');
