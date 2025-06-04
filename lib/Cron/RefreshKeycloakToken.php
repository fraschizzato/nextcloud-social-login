<?php
namespace OCA\SocialLogin\Cron;

use OCP\BackgroundJob\TimedJob;
use OCP\IConfig;
use OCP\IAppConfig;
use OCP\User\IUserManager;
use Hybridauth\HttpClient\Curl;

class RefreshKeycloakToken extends TimedJob
{
    private IConfig $config;
    private IAppConfig $appConfig;
    private IUserManager $userManager;
    private Curl $httpClient;

    public function __construct(IConfig $config, IAppConfig $appConfig, IUserManager $userManager)
    {
        parent::__construct();
        $this->config = $config;
        $this->appConfig = $appConfig;
        $this->userManager = $userManager;
        $this->httpClient = new Curl();
        $this->setInterval(1800); // run every 30 minutes
    }

    protected function run($argument)
    {
        $provider = $this->getKeycloakProvider();
        if (!$provider) {
            return;
        }
        foreach ($this->userManager->search('') as $user) {
            $uid = $user->getUID();
            $refreshToken = $this->config->getUserValue($uid, 'sociallogin', 'refresh_token', '');
            $expiresAt = (int)$this->config->getUserValue($uid, 'sociallogin', 'expires_at', 0);
            if (!$refreshToken || $expiresAt > time() + 60) {
                continue;
            }
            $tokens = $this->refreshToken($provider, $refreshToken);
            if (!$tokens) {
                continue;
            }
            if (isset($tokens['access_token'])) {
                $this->config->setUserValue($uid, 'sociallogin', 'access_token', $tokens['access_token']);
            }
            if (isset($tokens['refresh_token'])) {
                $this->config->setUserValue($uid, 'sociallogin', 'refresh_token', $tokens['refresh_token']);
            }
            if (isset($tokens['id_token'])) {
                $this->config->setUserValue($uid, 'sociallogin', 'token', $tokens['id_token']);
            }
            if (isset($tokens['expires_in'])) {
                $this->config->setUserValue($uid, 'sociallogin', 'expires_at', time() + (int)$tokens['expires_in']);
            }
        }
    }

    private function getKeycloakProvider(): ?array
    {
        $providers = $this->appConfig->getValueArray('sociallogin', 'custom_providers');
        foreach ($providers['custom_oidc'] ?? [] as $prov) {
            if (($prov['name'] ?? '') === 'keycloak') {
                return $prov;
            }
        }
        return null;
    }

    private function refreshToken(array $provider, string $refreshToken): ?array
    {
        $response = $this->httpClient->request(
            $provider['tokenUrl'],
            'POST',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => $provider['clientId'],
                'client_secret' => $provider['clientSecret'],
            ],
            ['Content-Type' => 'application/x-www-form-urlencoded']
        );
        $data = json_decode($response, true);
        return is_array($data) ? $data : null;
    }
}
