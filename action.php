<?php

use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthazure\Azure;

/**
 * Service Implementation for Azure authentication
 */
class action_plugin_oauthazure extends Adapter
{
    /** @inheritdoc */
    public function registerServiceClass()
    {
        return Azure::class;
    }

    /**
     * @inheritdoc
     * @throws \OAuth\Common\Exception\Exception
     */
    public function logout()
    {
        /** @var Azure */
        $oauth = $this->getOAuthService();
        $oauth->logout();
    }

    /** * @inheritDoc */
    public function getUser()
    {
        /** @var Azure */
        $oauth = $this->getOAuthService();

        $tokenExtras = $oauth->getStorage()->retrieveAccessToken($oauth->service())->getExtraParams();
        $idToken = $tokenExtras['id_token'] ?? '';

        $decodedObj = json_decode(base64_decode(str_replace('_', '/',
            str_replace('-', '+', explode('.', $idToken)[1]))));
        $result = (array)$decodedObj;
        if (!$result) throw new OAuthException('Failed to parse data from userinfo from JWT');

        $data = [];
        $data['user'] = $result['preferred_username'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];
        $data['grps'] = array_merge($result['groups'] ?? [], $result['roles'] ?? []);

        if ($this->getConf('fetchgroups')) {
            $usergroups = $oauth->request(Azure::GRAPH_MEMBEROF);
            $usergroups = json_decode($usergroups, true);
            if (!$usergroups) throw new OAuthException('Failed to parse group data');

            if (isset($usergroups['value'])) {
                $data['grps'] = array_map(function ($item) {
                    return $item['displayName'] ?? $item['id'];
                }, $usergroups['value']);
            }
        }

        return $data;
    }

    /** @inheritdoc */
    public function getScopes()
    {
        $scopes = [
            Azure::SCOPE_OPENID,
            Azure::SCOPE_EMAIL,
            Azure::SCOPE_PROFILE,
            Azure::SCOPE_OFFLINE,
        ];

        // use additional scopes to read group membership
        if ($this->getConf('fetchgroups')) {
            $scopes[] = Azure::SCOPE_USERREAD;
            $scopes[] = Azure::SCOPE_GROUPMEMBER;
        }

        return $scopes;
    }

    /** @inheritDoc */
    public function getLabel()
    {
        return 'USYD Email';
    }

    /** @inheritDoc */
    public function getColor()
    {
        return '#e64626';
    }

    public function getSvgLogo()
    {
        $logo = DOKU_PLUGIN . $this->getPluginName() . '/logo.svg';
        if (file_exists($logo)) return '<div class="plugin_oauthazure_logo">'.file_get_contents($logo).'</div>';
        return '';
    }
}
