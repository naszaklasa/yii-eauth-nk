<?php
/**
 * NKOAuthService class file.
 *
 * Register application: https://developers.nk.pl/developers/oauth2client/form
 * 
 * 
 * @author Marek Ziółkowski
 * @license http://www.opensource.org/licenses/bsd-license.php
 */

require_once dirname(dirname(__FILE__)).'/EOAuth2Service.php';

/**
 * Odnoklassniki.Ru provider class.
 * @package application.extensions.eauth.services
 */
class NKOAuthService extends EOAuth2Service {
	
	protected $name = 'nk';
	protected $title = 'NK';
	protected $type = 'OAuth';
	protected $jsArguments = array('popup' => array('width' => 484, 'height' => 300));
	
	protected $client_id = '';
	protected $client_secret = '';
	protected $client_public = '';
	protected $scope = '';
	protected $providerOptions = array(
			'authorize' => 'https://nk.pl/oauth2/login',
			'access_token' => 'https://nk.pl/oauth2/token',
	);
	
	public function makeSignedRequest($url, $fields) {
		
		if (isset($this->access_token)) {
		
			$params = array(
					"nk_token" => $this->access_token,
					"fields"   => $fields,
			);
		
			$consumer = new OAuthConsumer($this->client_id, $this->client_secret);
		
			$req = OAuthRequest::from_consumer_and_token($consumer, null, 'GET', $url, $params);
			$req->sign_request(new OAuthSignatureMethod_HMAC_SHA1(), $consumer, null);
		
			$auth_header = $req->to_header();
			$options['headers'] = array($auth_header, 'Content-Type: application/json');
		
			$url = $url . "?" . OAuthUtil::build_http_query($params);
			
			return $this->makeRequest($url, $options);
		
		}
	}
	
	protected function fetchAttributes() {
		$info = (object) $this->makeSignedRequest('http://opensocial.nk-net.pl/v09/social/rest/people/@me', 'id,age,name,currentLocation,emails');
	
		$this->attributes['id'] = $info->entry->id;
		$this->attributes['name'] = $info->entry->displayName;
		
	}
	
	protected function getCodeUrl($redirect_uri) {
		$this->setState('redirect_uri', $redirect_uri);
		return parent::getCodeUrl($redirect_uri);
	}
	
	protected function getTokenUrl() {
		return $this->providerOptions['access_token'];	
	}
	
	protected function getAccessToken($code) {
		$params = array(
				'client_id' => $this->client_id,
				'client_secret' => $this->client_secret,
				'grant_type' => 'authorization_code',
				'scope' => $this->scope,
				'redirect_uri' => $this->getState('redirect_uri'),
				'code' => $code
		);
		return $this->makeRequest($this->getTokenUrl(), array('data' => $params));
	}
	
	protected function saveAccessToken($token) {
		$this->setState('auth_token', $token->access_token);
		$this->setState('expires', isset($token->expires_in) ? time() + (int)$token->expires_in - 60 : 0);
		$this->access_token = $token->access_token;
	}

}
