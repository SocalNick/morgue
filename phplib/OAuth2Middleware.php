<?php
class Oauth2Middleware extends Slim_Middleware {
    public function call() {
        $this->app->getLog()->debug("Executing OAuth2 Middleware Pre");

        $provider = $this->app->oauth2Provider;

        $pathInfo = $this->app->request()->getPathInfo();

        if ($pathInfo != $this->app->urlFor('oauth2-callback') && !isset($_SESSION['oauth2token'])) {
            $authUrl = $provider->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $provider->state;
            $this->app->redirect($authUrl);
        }

        $this->next->call();
        $this->app->getLog()->debug("Executing OAuth2 Middleware Post: {$_SESSION['oauth2token']}");
    }
}

function morgue_get_user_data() {
    if (!isset($_SESSION['oauth2token'])) {
        return;
    }

    $app = Slim::getInstance();
    $provider = $app->oauth2Provider;
    $userDetails = $provider->getUserDetails($_SESSION['oauth2token']);
    return array("username" => $userDetails->nickname);
}

$app->get('/oauth2-callback', function() use ($app) {
    $provider = $app->oauth2Provider;

    // If we don't have an authorization code then get one
    if (!isset($_GET['code'])) {
        $authUrl = $provider->getAuthorizationUrl();
        $_SESSION['oauth2state'] = $provider->state;
        $app->redirect($authUrl);
    }

    // Check given state against previously stored one to mitigate CSRF attack
    if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
        $app->halt(500, 'Invalid state');
    }

    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    $_SESSION['oauth2token'] = $token;

    $app->redirect('/');

})->name('oauth2-callback');

