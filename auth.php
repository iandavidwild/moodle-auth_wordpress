<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authenticates against a WordPress installation using OAuth 1.0a.
 *
 * @package auth_wordpress
 * @author Ian Wild
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot . '/auth/wordpress/Oauth.php');
require_once($CFG->dirroot . '/auth/wordpress/BasicOauth.php');

use \OAuth1\BasicOauth;
 
/**
 * Plugin for WordPress authentication.
 */
class auth_plugin_wordpress extends auth_plugin_base {

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'wordpress';
        $this->config = get_config('auth/wordpress');
    }

    /**
     * Old syntax of class constructor. Deprecated in PHP7.
     *
     * @deprecated since Moodle 3.1
     */
    public function auth_plugin_wordpress() {
        debugging('Use of class name as constructor is deprecated', DEBUG_DEVELOPER);
        self::__construct();
    }

    /**
     * Returns true if the username and password work or don't exist and false
     * if the user exists and the password is wrong.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login ($username, $password) {
        global $CFG, $DB;
        if ($user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id))) {
            return validate_internal_user_password($user, $password);
        }
        return true;
    }

    /**
     * Updates the user's password.
     *
     * called when the user password is updated.
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     * @return boolean result
     *
     */
    function user_update_password($user, $newpassword) {
        $user = get_complete_user_data('id', $user->id);
        // This will also update the stored hash to the latest algorithm
        // if the existing hash is using an out-of-date algorithm (or the
        // legacy md5 algorithm).
        return update_internal_user_password($user, $newpassword);
    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    function can_be_manually_set() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        // Set to defaults if undefined
        if (!isset($config->wordpress_host)) {
            $config->wordpress_host = '';
        }
        if (!isset($config->client_key)) {
            $config->client_key = '';
        }
        if (!isset($config->client_secret)) {
            $config->client_secret = '';
        }
        set_config('wordpress_host', trim($config->wordpress_host), 'auth/wordpress');
        set_config('client_key', trim($config->client_key), 'auth/wordpress');
        set_config('client_secret', trim($config->client_secret), 'auth/wordpress');
        
        return true;
    }
    
    /**
     * Will get called before the login page is shown. 
     *
     */
    function loginpage_hook() {
        global $CFG;    
    
        $client_key = $this->config->client_key;
        $client_secret = $this->config->client_secret;
        $wordpress_host = $this->config->wordpress_host;
       
        if( (strlen($wordpress_host) > 0) && (strlen($client_key) > 0) && (strlen($client_secret) > 0) ) {
            // kick ff the authentication process
            $connection = new BasicOAuth($client_key, $client_secret);
       
            // strip the trailing slashes from the end of the host URL to avoid any confusion (and to make the code easier to read)
            $wordpress_host = rtrim($wordpress_host, '/');
            
            $connection->host = $wordpress_host . "/wp-json";
            $connection->requestTokenURL = $wordpress_host . "/oauth1/request";
       
            $callback = $CFG->wwwroot . '/auth/wordpress/callback.php';
            $tempCredentials = $connection->getRequestToken($callback);
       
            $_SESSION['oauth_token'] = $tempCredentials['oauth_token'];
            $_SESSION['oauth_token_secret'] = $tempCredentials['oauth_token_secret'];
       
            $connection->authorizeURL = $wordpress_host . "/oauth1/authorize";
       
            $redirect_url = $connection->getAuthorizeURL($tempCredentials);
       
            header('Location: ' . $redirect_url);
            die;
        }// if   
    }
    
    /**
     * 
     */
    function oauth_callback() {
        global $CFG, $DB;
        
        $client_key = $this->config->client_key;
        $client_secret = $this->config->client_secret;
        $wordpress_host = $this->config->wordpress_host;
        
        // strip the trailing slashes from the end of the host URL to avoid any confusion (and to make the code easier to read)
        $wordpress_host = rtrim($wordpress_host, '/');
        
        session_start();
        
        // at this stage we have been provided with new permanent token
        $connection = new BasicOAuth($client_key, $client_secret, $_SESSION['oauth_token'], $_SESSION['oauth_token_secret']);
        
        $connection->host = $wordpress_host . "/wp-json";
        
        $connection->accessTokenURL = $wordpress_host . "/oauth1/access";
        
        $tokenCredentials = $connection->getAccessToken($_REQUEST['oauth_verifier']);
        
        $perm_connection = new BasicOAuth($client_key, $client_secret, $tokenCredentials['oauth_token'],
                $tokenCredentials['oauth_token_secret']);
        
        $account = $perm_connection->get($wordpress_host . '/wp-json/wp/v2/users/me');
        
        // do something with this account
    
    }

}
