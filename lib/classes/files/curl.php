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

namespace core\files;

/**
 * RESTful cURL class
 *
 * This is a wrapper class for curl, it is quite easy to use:
 * <code>
 * $c = new curl;
 * // enable cache
 * $c = new curl(array('cache'=>true));
 * // enable cookie
 * $c = new curl(array('cookie'=>true));
 * // enable proxy
 * $c = new curl(array('proxy'=>true));
 *
 * // HTTP GET Method
 * $html = $c->get('http://example.com');
 * // HTTP POST Method
 * $html = $c->post('http://example.com/', array('q'=>'words', 'name'=>'moodle'));
 * // HTTP PUT Method
 * $html = $c->put('http://example.com/', array('file'=>'/var/www/test.txt');
 * </code>
 *
 * @package   core
 * @category files
 * @copyright Dongsheng Cai <dongsheng@moodle.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class curl {
    /** @var \curl_cache|false Caches http request contents */
    public $cache    = false;
    /** @var bool Uses proxy, null means automatic based on URL */
    public $proxy    = null;
    /** @var string library version */
    public $version  = '0.4 dev';
    /** @var array http's response */
    public $response = [];
    /** @var array Raw response headers, needed for BC in download_file_content(). */
    public $rawresponse = [];
    /** @var array http header */
    public $header   = [];
    /** @var array cURL information */
    public $info;
    /** @var string error */
    public $error;
    /** @var int error code */
    public $errno;
    /** @var bool Perform redirects at PHP level instead of relying on native cURL functionality. Always true now. */
    public $emulateredirects = null;

    /** @var array cURL options */
    private $options;

    /** @var string Proxy host */
    private $proxyhost = '';
    /** @var string Proxy auth */
    private $proxyauth = '';
    /** @var string Proxy type */
    private $proxytype = '';
    /** @var bool Debug mode on */
    private $debug    = false;
    /** @var bool|string Path to cookie file */
    private $cookie   = false;
    /** @var bool tracks multiple headers in response - redirect detection */
    private $responsefinished = false;
    /** @var ?\core\files\curl_security_helper security helper class, responsible for checking host/ports against allowed/blocked entries.*/
    private $securityhelper;
    /** @var bool ignoresecurity a flag which can be supplied to the constructor, allowing security to be bypassed. */
    private $ignoresecurity;
    /** @var array $mockresponses For unit testing only - return the head of this list instead of making the next request. */
    private static $mockresponses = [];
    /** @var array $curlresolveinfo Resolve addresses for the URL that have passed cuRL security checks, in a CURLOPT_RESOLVE compatible format. */
    private $curlresolveinfo = [];
    /** @var array temporary params value if the value is not belongs to class stored_file. */
    public $tmpfilepostparams = [];

    /**
     * Curl constructor.
     *
     * Allowed settings are:
     *  proxy: (bool) use proxy server, null means autodetect non-local from url
     *  debug: (bool) use debug output
     *  cookie: (string) path to cookie file, false if none
     *  cache: (bool) use cache
     *  module_cache: (string) type of cache
     *  securityhelper: (\core\files\curl_security_helper_base) helper object providing URL checking for requests.
     *  ignoresecurity: (bool) set true to override and ignore the security helper when making requests.
     *
     * @param array $settings
     */
    public function __construct($settings = []) {
        global $CFG;
        if (!function_exists('curl_init')) {
            $this->error = 'cURL module must be enabled!';
            trigger_error($this->error, E_USER_ERROR);
            return;
        }

        // All settings of this class should be init here.
        $this->resetopt();
        if (!empty($settings['debug'])) {
            $this->debug = true;
        }
        if (!empty($settings['cookie'])) {
            if ($settings['cookie'] === true) {
                $this->cookie = $CFG->dataroot . '/curl_cookie.txt';
            } else {
                $this->cookie = $settings['cookie'];
            }
        }
        if (!empty($settings['cache'])) {
            if (class_exists('curl_cache')) {
                if (!empty($settings['module_cache'])) {
                    $this->cache = new \curl_cache($settings['module_cache']);
                } else {
                    $this->cache = new \curl_cache('misc');
                }
            }
        }
        if (!empty($CFG->proxyhost)) {
            if (empty($CFG->proxyport)) {
                $this->proxyhost = $CFG->proxyhost;
            } else {
                $this->proxyhost = $CFG->proxyhost . ':' . $CFG->proxyport;
            }
            if (!empty($CFG->proxyuser) && !empty($CFG->proxypassword)) {
                $this->proxyauth = $CFG->proxyuser . ':' . $CFG->proxypassword;
                $this->setopt([
                            'proxyauth' => CURLAUTH_BASIC | CURLAUTH_NTLM,
                            'proxyuserpwd' => $this->proxyauth]);
            }
            if (!empty($CFG->proxytype)) {
                if ($CFG->proxytype == 'SOCKS5') {
                    $this->proxytype = CURLPROXY_SOCKS5;
                } else {
                    $this->proxytype = CURLPROXY_HTTP;
                    $this->setopt([
                        'httpproxytunnel' => false,
                    ]);
                    if (defined('CURLOPT_SUPPRESS_CONNECT_HEADERS')) {
                        $this->setopt([
                            'suppress_connect_headers' => true,
                        ]);
                    }
                }
                $this->setopt(['proxytype' => $this->proxytype]);
            }

            if (isset($settings['proxy'])) {
                $this->proxy = $settings['proxy'];
            }
        } else {
            $this->proxy = false;
        }

        // All redirects are performed at PHP level now and each one is checked against blocked URLs rules. We do not
        // want to let cURL naively follow the redirect chain and visit every URL for security reasons. Even when the
        // caller explicitly wants to ignore the security checks, we would need to fall back to the original
        // implementation and use emulated redirects if open_basedir is in effect to avoid the PHP warning
        // "CURLOPT_FOLLOWLOCATION cannot be activated when in safe_mode or an open_basedir". So it is better to simply
        // ignore this property and always handle redirects at this PHP wrapper level and not inside the native cURL.
        $this->emulateredirects = true;

        // Curl security setup. Allow injection of a security helper, but if not found, default to the core helper.
        if (isset($settings['securityhelper']) && $settings['securityhelper'] instanceof \core\files\curl_security_helper_base) {
            $this->set_security($settings['securityhelper']);
        } else {
            $this->set_security(new \core\files\curl_security_helper());
        }
        $this->ignoresecurity = isset($settings['ignoresecurity']) ? $settings['ignoresecurity'] : false;
    }

    /**
     * Resets the CURL options that have already been set
     */
    public function resetopt() {
        $this->options = [];
        $this->options['CURLOPT_USERAGENT']         = \core_useragent::get_moodlebot_useragent();
        // True to include the header in the output.
        $this->options['CURLOPT_HEADER']            = 0;
        // True to Exclude the body from the output.
        $this->options['CURLOPT_NOBODY']            = 0;
        // Redirect ny default.
        $this->options['CURLOPT_FOLLOWLOCATION']    = 1;
        $this->options['CURLOPT_MAXREDIRS']         = 10;
        $this->options['CURLOPT_ENCODING']          = '';
        // TRUE to return the transfer as a string of the return
        // value of curl_exec() instead of outputting it out directly.
        $this->options['CURLOPT_RETURNTRANSFER']    = 1;
        $this->options['CURLOPT_SSL_VERIFYPEER']    = 0;
        $this->options['CURLOPT_SSL_VERIFYHOST']    = 2;
        $this->options['CURLOPT_CONNECTTIMEOUT']    = 30;

        if ($cacert = self::get_cacert()) {
            $this->options['CURLOPT_CAINFO'] = $cacert;
        }
    }

    /**
     * Get the location of ca certificates.
     * @return string absolute file path or empty if default used
     */
    public static function get_cacert() {
        global $CFG;

        // Bundle in dataroot always wins.
        if (is_readable("$CFG->dataroot/moodleorgca.crt")) {
            return realpath("$CFG->dataroot/moodleorgca.crt");
        }

        // Next comes the default from php.ini.
        $cacert = ini_get('curl.cainfo');
        if (!empty($cacert) && is_readable($cacert)) {
            return realpath($cacert);
        }

        // Windows PHP does not have any certs, we need to use something.
        if ($CFG->ostype === 'WINDOWS') {
            if (is_readable("$CFG->libdir/cacert.pem")) {
                return realpath("$CFG->libdir/cacert.pem");
            }
        }

        // Use default, this should work fine on all properly configured *nix systems.
        return null;
    }

    /**
     * Reset Cookie
     */
    public function resetcookie() {
        if (!empty($this->cookie)) {
            if (is_file($this->cookie)) {
                $fp = fopen($this->cookie, 'w');
                if (!empty($fp)) {
                    fwrite($fp, '');
                    fclose($fp);
                }
            }
        }
    }

    /**
     * Set curl options.
     *
     * Do not use the curl constants to define the options, pass a string
     * corresponding to that constant. Ie. to set CURLOPT_MAXREDIRS, pass
     * array('CURLOPT_MAXREDIRS' => 10) or array('maxredirs' => 10) to this method.
     *
     * @param array $options If array is null, this function will reset the options to default value.
     * @return void
     * @throws coding_exception If an option uses constant value instead of option name.
     */
    public function setopt($options = []) {
        if (is_array($options)) {
            foreach ($options as $name => $val) {
                if (!is_string($name)) {
                    throw new \coding_exception('Curl options should be defined using strings, not constant values.');
                }
                if (stripos($name, 'CURLOPT_') === false) {
                    // Only prefix with CURLOPT_ if the option doesn't contain CURLINFO_,
                    // which is a valid prefix for at least one option CURLINFO_HEADER_OUT.
                    if (stripos($name, 'CURLINFO_') === false) {
                        $name = strtoupper('CURLOPT_' . $name);
                    }
                } else {
                    $name = strtoupper($name);
                }
                $this->options[$name] = $val;
            }
        }
    }

    /**
     * Reset http method
     */
    public function cleanopt() {
        unset($this->options['CURLOPT_HTTPGET']);
        unset($this->options['CURLOPT_POST']);
        unset($this->options['CURLOPT_POSTFIELDS']);
        unset($this->options['CURLOPT_PUT']);
        unset($this->options['CURLOPT_INFILE']);
        unset($this->options['CURLOPT_INFILESIZE']);
        unset($this->options['CURLOPT_CUSTOMREQUEST']);
        unset($this->options['CURLOPT_FILE']);
    }

    /**
     * Resets the HTTP Request headers (to prepare for the new request)
     */
    public function resetheader() {
        $this->header = [];
    }

    /**
     * Set HTTP Request Header
     *
     * @param array|string $header
     */
    public function setheader($header) {
        if (is_array($header)) {
            foreach ($header as $v) {
                $this->setHeader($v);
            }
        } else {
            // Remove newlines, they are not allowed in headers.
            $newvalue = preg_replace('/[\r\n]/', '', $header);
            if (!in_array($newvalue, $this->header)) {
                $this->header[] = $newvalue;
            }
        }
    }

    /**
     * Get HTTP Response Headers
     * @return array of arrays
     */
    public function getresponse() {
        return $this->response;
    }

    /**
     * Get raw HTTP Response Headers
     * @return array of strings
     */
    public function get_raw_response() {
        return $this->rawresponse;
    }

    /**
     * private callback function
     * Formatting HTTP Response Header
     *
     * We only keep the last headers returned. For example during a redirect the
     * redirect headers will not appear in {@see self::getresponse()}, if you need
     * to use those headers, refer to {@see self::get_raw_response()}.
     *
     * @param resource $ch Apparently not used
     * @param string $header
     * @return int The strlen of the header
     */
    private function formatheader($ch, $header) {
        $this->rawresponse[] = $header;

        if (trim($header, "\r\n") === '') {
            // This must be the last header.
            $this->responsefinished = true;
        }

        if (strlen($header) > 2) {
            if ($this->responsefinished) {
                // We still have headers after the supposedly last header, we must be
                // in a redirect so let's empty the response to keep the last headers.
                $this->responsefinished = false;
                $this->response = [];
            }
            $parts = explode(" ", rtrim($header, "\r\n"), 2);
            $key = rtrim($parts[0], ':');
            $value = isset($parts[1]) ? $parts[1] : null;
            if (!empty($this->response[$key])) {
                if (is_array($this->response[$key])) {
                    $this->response[$key][] = $value;
                } else {
                    $tmp = $this->response[$key];
                    $this->response[$key] = [];
                    $this->response[$key][] = $tmp;
                    $this->response[$key][] = $value;
                }
            } else {
                $this->response[$key] = $value;
            }
        }
        return strlen($header);
    }

    /**
     * Set options for individual curl instance
     *
     * @param resource|CurlHandle $curl A curl handle
     * @param array $options
     * @return resource The curl handle
     */
    private function apply_opt($curl, $options) {
        // Clean up.
        $this->cleanopt();
        // Set cookie.
        if (!empty($this->cookie) || !empty($options['cookie'])) {
            $this->setopt(['cookiejar' => $this->cookie,
                            'cookiefile' => $this->cookie,
                            ]);
        }

        // Bypass proxy if required.
        if ($this->proxy === null) {
            if (!empty($this->options['CURLOPT_URL']) && is_proxybypass($this->options['CURLOPT_URL'])) {
                $proxy = false;
            } else {
                $proxy = true;
            }
        } else {
            $proxy = (bool)$this->proxy;
        }

        // Set proxy.
        if ($proxy) {
            $options['CURLOPT_PROXY'] = $this->proxyhost;
        } else {
            unset($this->options['CURLOPT_PROXY']);
        }

        $this->setopt($options);

        // Reset before set options.
        curl_setopt($curl, CURLOPT_HEADERFUNCTION, [$this, 'formatheader']);

        // Setting the User-Agent based on options provided.
        $useragent = '';

        if (!empty($options['CURLOPT_USERAGENT'])) {
            $useragent = $options['CURLOPT_USERAGENT'];
        } else if (!empty($this->options['CURLOPT_USERAGENT'])) {
            $useragent = $this->options['CURLOPT_USERAGENT'];
        } else {
            $useragent = \core_useragent::get_moodlebot_useragent();
        }

        // Set headers.
        if (empty($this->header)) {
            $this->setheader([
                'User-Agent: ' . $useragent,
                'Connection: keep-alive',
                ]);
        } else if (!in_array('User-Agent: ' . $useragent, $this->header)) {
            // Remove old User-Agent if one existed.
            // We have to partial search since we don't know what the original User-Agent is.
            if ($match = preg_grep('/User-Agent.*/', $this->header)) {
                $key = array_keys($match)[0];
                unset($this->header[$key]);
            }
            $this->setheader(['User-Agent: ' . $useragent]);
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $this->header);

        if ($this->debug) {
            echo '<h1>Options</h1>';
            var_dump($this->options);
            echo '<h1>Header</h1>';
            var_dump($this->header);
        }

        // Do not allow infinite redirects.
        if (!isset($this->options['CURLOPT_MAXREDIRS'])) {
            $this->options['CURLOPT_MAXREDIRS'] = 0;
        } else if ($this->options['CURLOPT_MAXREDIRS'] > 100) {
            $this->options['CURLOPT_MAXREDIRS'] = 100;
        } else {
            $this->options['CURLOPT_MAXREDIRS'] = (int)$this->options['CURLOPT_MAXREDIRS'];
        }

        // Make sure we always know if redirects expected.
        if (!isset($this->options['CURLOPT_FOLLOWLOCATION'])) {
            $this->options['CURLOPT_FOLLOWLOCATION'] = 0;
        }

        // Limit the protocols to HTTP and HTTPS.
        if (defined('CURLOPT_PROTOCOLS')) {
            $this->options['CURLOPT_PROTOCOLS'] = (CURLPROTO_HTTP | CURLPROTO_HTTPS);
            $this->options['CURLOPT_REDIR_PROTOCOLS'] = (CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }

        // Set options.
        foreach ($this->options as $name => $val) {
            if ($name === 'CURLOPT_FOLLOWLOCATION') {
                // All the redirects are emulated at PHP level.
                curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 0);
                continue;
            }
            $name = constant($name);
            curl_setopt($curl, $name, $val);
        }

        return $curl;
    }

    /**
     * Download multiple files in parallel
     *
     * Calls {@see self::multi()} with specific download headers
     *
     * <code>
     * $c = new curl();
     * $file1 = fopen('a', 'wb');
     * $file2 = fopen('b', 'wb');
     * $c->download(array(
     *     array('url'=>'http://localhost/', 'file'=>$file1),
     *     array('url'=>'http://localhost/20/', 'file'=>$file2)
     * ));
     * fclose($file1);
     * fclose($file2);
     * </code>
     *
     * or
     *
     * <code>
     * $c = new curl();
     * $c->download(array(
     *              array('url'=>'http://localhost/', 'filepath'=>'/tmp/file1.tmp'),
     *              array('url'=>'http://localhost/20/', 'filepath'=>'/tmp/file2.tmp')
     *              ));
     * </code>
     *
     * @param array $requests An array of files to request {
     *                  url => url to download the file [required]
     *                  file => file handler, or
     *                  filepath => file path
     * }
     * If 'file' and 'filepath' parameters are both specified in one request, the
     * open file handle in the 'file' parameter will take precedence and 'filepath'
     * will be ignored.
     *
     * @param array $options An array of options to set
     * @return array An array of results
     */
    public function download($requests, $options = []) {
        $options['RETURNTRANSFER'] = false;
        return $this->multi($requests, $options);
    }

    /**
     * Returns the current curl security helper.
     *
     * @return \core\files\curl_security_helper instance.
     */
    public function get_security() {
        return $this->securityhelper;
    }

    /**
     * Sets the curl security helper.
     *
     * @param \core\files\curl_security_helper $securityobject instance/subclass of the base curl_security_helper class.
     * @return bool true if the security helper could be set, false otherwise.
     */
    public function set_security($securityobject) {
        if ($securityobject instanceof \core\files\curl_security_helper) {
            $this->securityhelper = $securityobject;
            return true;
        }
        return false;
    }

    /**
     * Multi HTTP Requests
     * This function could run multi-requests in parallel.
     *
     * @param array $requests An array of files to request
     * @param array $options An array of options to set
     * @return array An array of results
     */
    protected function multi($requests, $options = []) {
        $count   = count($requests);
        $handles = [];
        $results = [];
        $main    = curl_multi_init();
        for ($i = 0; $i < $count; $i++) {
            if (!empty($requests[$i]['filepath']) && empty($requests[$i]['file'])) {
                // Open file.
                $requests[$i]['file'] = fopen($requests[$i]['filepath'], 'w');
                $requests[$i]['auto-handle'] = true;
            }
            foreach ($requests[$i] as $n => $v) {
                $options[$n] = $v;
            }
            $handles[$i] = curl_init($requests[$i]['url']);
            $this->apply_opt($handles[$i], $options);
            curl_multi_add_handle($main, $handles[$i]);
        }
        $running = 0;
        do {
            curl_multi_exec($main, $running);
        } while ($running > 0);
        for ($i = 0; $i < $count; $i++) {
            if (!empty($options['CURLOPT_RETURNTRANSFER'])) {
                $results[] = true;
            } else {
                $results[] = curl_multi_getcontent($handles[$i]);
            }
            curl_multi_remove_handle($main, $handles[$i]);
        }
        curl_multi_close($main);

        for ($i = 0; $i < $count; $i++) {
            if (!empty($requests[$i]['filepath']) && !empty($requests[$i]['auto-handle'])) {
                // Close file handler if file is opened in this function.
                fclose($requests[$i]['file']);
            }
        }
        return $results;
    }

    /**
     * Helper function to reset the request state vars.
     *
     * @return void.
     */
    protected function reset_request_state_vars() {
        $this->info             = [];
        $this->error            = '';
        $this->errno            = 0;
        $this->response         = [];
        $this->rawresponse      = [];
        $this->responsefinished = false;
    }

    /**
     * For use only in unit tests - we can pre-set the next curl response.
     * This is useful for unit testing APIs that call external systems.
     * @param string $response
     */
    public static function mock_response($response) {
        if ((defined('PHPUNIT_TEST') && PHPUNIT_TEST)) {
            array_push(self::$mockresponses, $response);
        } else {
            throw new \coding_exception('mock_response function is only available for unit tests.');
        }
    }

    /**
     * check_securityhelper_blocklist.
     * Checks whether the given URL is blocked by checking both plugin's security helpers
     * and core curl security helper or any curl security helper that passed to curl class constructor.
     * If ignoresecurity is set to true, skip checking and consider the url is not blocked.
     * This augments all installed plugin's security helpers if there is any.
     *
     * @param string $url the url to check.
     * @return ?string - an error message if URL is blocked or null if URL is not blocked.
     */
    protected function check_securityhelper_blocklist(string $url): ?string {

        // If curl security is not enabled, do not proceed.
        if ($this->ignoresecurity) {
            return null;
        }

        // Augment all installed plugin's security helpers if there is any.
        // The plugin's function has to be defined as plugintype_pluginname_curl_security_helper in pluginname/lib.php.
        $plugintypes = get_plugins_with_function('curl_security_helper');

        // If any of the security helper's function returns true, treat as URL is blocked.
        foreach ($plugintypes as $plugins) {
            foreach ($plugins as $pluginfunction) {
                // Get curl security helper object from plugin lib.php.
                $pluginsecurityhelper = $pluginfunction();
                if ($pluginsecurityhelper instanceof \core\files\curl_security_helper_base) {
                    if ($pluginsecurityhelper->url_is_blocked($url)) {
                        $this->error = $pluginsecurityhelper->get_blocked_url_string();
                        return $this->error;
                    }
                }
            }
        }

        // Check if the URL is blocked in core curl_security_helper or
        // curl security helper that passed to curl class constructor.
        if ($this->securityhelper->url_is_blocked($url)) {
            $this->error = $this->securityhelper->get_blocked_url_string();
            return $this->error;
        }

        // Set allowed resolve info if the URL is not blocked.
        $this->curlresolveinfo = $this->securityhelper->get_resolve_info();

        return null;
    }

    /**
     * Single HTTP Request
     *
     * @param string $url The URL to request
     * @param array $options
     * @return string
     */
    protected function request($url, $options = []) {
        // Reset here so that the data is valid when result returned from cache, or if we return due to a blocked URL hit.
        $this->reset_request_state_vars();

        if ((defined('PHPUNIT_TEST') && PHPUNIT_TEST)) {
            $mockresponse = array_pop(self::$mockresponses);
            if ($mockresponse !== null) {
                $this->info = ['http_code' => 200];
                return $mockresponse;
            }
        }

        if (empty($this->emulateredirects)) {
            // Just in case someone had tried to explicitly disable emulated redirects in legacy code.
            debugging('Attempting to disable emulated redirects has no effect any more!', DEBUG_DEVELOPER);
        }

        $urlisblocked = $this->check_securityhelper_blocklist($url);
        if (!is_null($urlisblocked)) {
            $this->trigger_url_blocked_event($url, $urlisblocked);
            return $urlisblocked;
        }

        // Set the URL as a curl option.
        $this->setopt(['CURLOPT_URL' => $url]);

        // Force cURL to only resolve the URL from IP/port combinations that were validated by the security helper.
        // This prevents re-fetching DNS data on subsequent requests, which could return un-validated hosts/ports.
        $this->setopt(['CURLOPT_RESOLVE' => $this->curlresolveinfo]);

        // Create curl instance.
        $curl = curl_init();

        $this->apply_opt($curl, $options);
        if ($this->cache && $ret = $this->cache->get($this->options)) {
            return $ret;
        }

        $ret = curl_exec($curl);
        $this->info  = curl_getinfo($curl);
        $this->error = curl_error($curl);
        $this->errno = curl_errno($curl);
        // Note: $this->response and $this->rawresponse are filled by $hits->formatHeader callback.

        if (intval($this->info['redirect_count']) > 0) {
            // For security reasons we do not allow the cURL handle to follow redirects on its own.
            // See setting CURLOPT_FOLLOWLOCATION in {@see self::apply_opt()} method.
            throw new \coding_exception(
                'Internal cURL handle should never follow redirects on its own!',
                'Reported number of redirects: ' . $this->info['redirect_count']
            );
        }

        if ($this->options['CURLOPT_FOLLOWLOCATION'] && $this->info['http_code'] != 200) {
            $redirects = 0;

            while ($redirects <= $this->options['CURLOPT_MAXREDIRS']) {
                // 301 Moved Permanently, 302 Found, 307 Temporary Redirect, 308 Permanent Redirect
                // Repeat the same request on new URL - no action needed.
                // 303 See Other - repeat only if GET, do not bother with POSTs.
                if ($this->info['http_code'] == 303 && empty($this->options['CURLOPT_HTTPGET'])) {
                    break;
                } else if (!in_array($this->info['http_code'], [301, 302, 303, 307, 308])) {
                    // Some other http code means do not retry!
                    break;
                }

                $redirects++;

                $currenturl = $redirecturl ?? $url;
                $redirecturl = null;
                if (isset($this->info['redirect_url'])) {
                    if (preg_match('|^https?://|i', $this->info['redirect_url'])) {
                        $redirecturl = $this->info['redirect_url'];
                    } else {
                        // Emulate CURLOPT_REDIR_PROTOCOLS behaviour which we have set to (CURLPROTO_HTTP | CURLPROTO_HTTPS) only.
                        $this->errno = CURLE_UNSUPPORTED_PROTOCOL;
                        $this->error = 'Redirect to a URL with unsupported protocol: ' . $this->info['redirect_url'];
                        curl_close($curl);
                        return $this->error;
                    }
                }
                if (!$redirecturl) {
                    foreach ($this->response as $k => $v) {
                        if (strtolower($k) === 'location') {
                            $redirecturl = $v;
                            break;
                        }
                    }
                    if ($redirecturl && !preg_match('|^https?://|i', $redirecturl)) {
                        $current = curl_getinfo($curl, CURLINFO_EFFECTIVE_URL);
                        if (strpos($redirecturl, '/') === 0) {
                            // Relative to server root - just guess.
                            $pos = strpos('/', $current, 8);
                            if ($pos === false) {
                                $redirecturl = $current . $redirecturl;
                            } else {
                                $redirecturl = substr($current, 0, $pos) . $redirecturl;
                            }
                        } else {
                            // Relative to current script.
                            $redirecturl = dirname($current) . '/' . $redirecturl;
                        }
                    }
                }

                $urlisblocked = $this->check_securityhelper_blocklist($redirecturl);
                if (!is_null($urlisblocked)) {
                    $this->reset_request_state_vars();
                    curl_close($curl);
                    $this->trigger_url_blocked_event($redirecturl, $urlisblocked, true);
                    return $urlisblocked;
                }

                // If the response body is written to a seekable stream resource, reset the stream pointer to avoid
                // appending multiple response bodies to the same resource.
                if (!empty($this->options['CURLOPT_FILE'])) {
                    $streammetadata = stream_get_meta_data($this->options['CURLOPT_FILE']);
                    if ($streammetadata['seekable']) {
                        ftruncate($this->options['CURLOPT_FILE'], 0);
                        rewind($this->options['CURLOPT_FILE']);
                    }
                }

                curl_setopt($curl, CURLOPT_URL, $redirecturl);

                // Force cURL to only resolve the URL from IP/port combinations that were validated by the security helper.
                // This prevents re-fetching DNS data on subsequent requests, which could return un-validated hosts/ports.
                $this->setopt(['CURLOPT_RESOLVE' => $this->curlresolveinfo]);

                // If CURLOPT_UNRESTRICTED_AUTH is empty/false, don't send credentials to other hosts.
                // Ref: https://curl.se/libcurl/c/CURLOPT_UNRESTRICTED_AUTH.html.
                $isdifferenthost = parse_url($currenturl)['host'] !== parse_url($redirecturl)['host'];
                $sendauthentication = !empty($this->options['CURLOPT_UNRESTRICTED_AUTH']);
                if ($isdifferenthost && !$sendauthentication) {
                    curl_setopt($curl, CURLOPT_HTTPAUTH, null);
                    curl_setopt($curl, CURLOPT_USERPWD, null);
                    // Check whether the CURLOPT_HTTPHEADER is specified.
                    if (!empty($this->options['CURLOPT_HTTPHEADER'])) {
                        // Remove the "Authorization:" header, if any.
                        $headerredirect = array_filter(
                            $this->options['CURLOPT_HTTPHEADER'],
                            fn($header) => strpos($header, 'Authorization:') === false
                        );
                        curl_setopt($curl, CURLOPT_HTTPHEADER, $headerredirect);
                    }
                }

                $ret = curl_exec($curl);

                $this->info  = curl_getinfo($curl);
                $this->error = curl_error($curl);
                $this->errno = curl_errno($curl);

                $this->info['redirect_count'] = $redirects;

                if ($this->info['http_code'] === 200) {
                    // Finally this is what we wanted.
                    break;
                }
                if ($this->errno != CURLE_OK) {
                    // Something wrong is going on.
                    break;
                }
            }
            if ($redirects > $this->options['CURLOPT_MAXREDIRS']) {
                $this->errno = CURLE_TOO_MANY_REDIRECTS;
                $this->error = 'Maximum (' . $this->options['CURLOPT_MAXREDIRS'] . ') redirects followed';
            }
        }

        if ($this->cache) {
            $this->cache->set($this->options, $ret);
        }

        if ($this->debug) {
            echo '<h1>Return Data</h1>';
            var_dump($ret);
            echo '<h1>Info</h1>';
            var_dump($this->info);
            echo '<h1>Error</h1>';
            var_dump($this->error);
        }

        curl_close($curl);

        if (empty($this->error)) {
            return $ret;
        } else {
            return $this->error;
            // Exception is not ajax friendly.
            // Throw new moodle_exception($this->error, 'curl').
        }
    }

    /**
     * Trigger url_blocked event
     *
     * @param string $url      The URL to request
     * @param string $reason   Reason for blocking
     * @param bool   $redirect true if it was a redirect
     */
    private function trigger_url_blocked_event($url, $reason, $redirect = false): void {
        $params = [
            'url' => $url,
            'reason' => $reason,
            'redirect' => $redirect,
        ];
        $event = \core\event\url_blocked::create(['other' => $params]);
        $event->trigger();
    }

    /**
     * HTTP HEAD method
     *
     * @see request()
     *
     * @param string $url
     * @param array $options
     * @return string
     */
    public function head($url, $options = []) {
        $options['CURLOPT_HTTPGET'] = 0;
        $options['CURLOPT_HEADER']  = 1;
        $options['CURLOPT_NOBODY']  = 1;
        return $this->request($url, $options);
    }

    /**
     * HTTP PATCH method
     *
     * @param string $url
     * @param array|string $params
     * @param array $options
     * @return string
     */
    public function patch($url, $params = '', $options = []) {
        $options['CURLOPT_CUSTOMREQUEST'] = 'PATCH';
        if (is_array($params)) {
            $this->tmpfilepostparams = [];
            foreach ($params as $key => $value) {
                if ($value instanceof stored_file) {
                    $value->add_to_curl_request($this, $key);
                } else {
                    $this->tmpfilepostparams[$key] = $value;
                }
            }
            $options['CURLOPT_POSTFIELDS'] = $this->tmpfilepostparams;
            unset($this->tmpfilepostparams);
        } else {
            // The variable $params is the raw post data.
            $options['CURLOPT_POSTFIELDS'] = $params;
        }
        return $this->request($url, $options);
    }

    /**
     * HTTP POST method
     *
     * @param string $url
     * @param array|string $params
     * @param array $options
     * @return string
     */
    public function post($url, $params = '', $options = []) {
        $options['CURLOPT_POST']       = 1;
        if (is_array($params)) {
            $this->tmpfilepostparams = [];
            foreach ($params as $key => $value) {
                if ($value instanceof stored_file) {
                    $value->add_to_curl_request($this, $key);
                } else {
                    $this->tmpfilepostparams[$key] = $value;
                }
            }
            $options['CURLOPT_POSTFIELDS'] = $this->tmpfilepostparams;
            unset($this->tmpfilepostparams);
        } else {
            // Params is the raw post data.
            $options['CURLOPT_POSTFIELDS'] = $params;
        }
        return $this->request($url, $options);
    }

    /**
     * HTTP GET method
     *
     * @param string $url
     * @param ?array $params
     * @param array $options
     * @return string
     */
    public function get($url, $params = [], $options = []) {
        $options['CURLOPT_HTTPGET'] = 1;

        if (!empty($params)) {
            $url .= (stripos($url, '?') !== false) ? '&' : '?';
            $url .= http_build_query($params, '', '&');
        }
        return $this->request($url, $options);
    }

    /**
     * Downloads one file and writes it to the specified file handler
     *
     * <code>
     * $c = new curl();
     * $file = fopen('savepath', 'w');
     * $result = $c->download_one('http://localhost/', null,
     *   array('file' => $file, 'timeout' => 5, 'followlocation' => true, 'maxredirs' => 3));
     * fclose($file);
     * $download_info = $c->get_info();
     * if ($result === true) {
     *   // file downloaded successfully
     * } else {
     *   $error_text = $result;
     *   $error_code = $c->get_errno();
     * }
     * </code>
     *
     * <code>
     * $c = new curl();
     * $result = $c->download_one('http://localhost/', null,
     *   array('filepath' => 'savepath', 'timeout' => 5, 'followlocation' => true, 'maxredirs' => 3));
     * // ... see above, no need to close handle and remove file if unsuccessful
     * </code>
     *
     * @param string $url
     * @param array|null $params key-value pairs to be added to $url as query string
     * @param array $options request options. Must include either 'file' or 'filepath'
     * @return bool|string true on success or error string on failure
     */
    public function download_one($url, $params, $options = []) {
        $options['CURLOPT_HTTPGET'] = 1;
        if (!empty($params)) {
            $url .= (stripos($url, '?') !== false) ? '&' : '?';
            $url .= http_build_query($params, '', '&');
        }
        if (!empty($options['filepath']) && empty($options['file'])) {
            // Open file.
            if (!($options['file'] = fopen($options['filepath'], 'w'))) {
                $this->errno = 100;
                return get_string('cannotwritefile', 'error', $options['filepath']);
            }
            $filepath = $options['filepath'];
        }
        unset($options['filepath']);
        $result = $this->request($url, $options);
        if (isset($filepath)) {
            fclose($options['file']);
            if ($result !== true) {
                unlink($filepath);
            }
        }
        return $result;
    }

    /**
     * HTTP PUT method
     *
     * @param string $url
     * @param array $params
     * @param array $options
     * @return ?string
     */
    public function put($url, $params = [], $options = []) {
        $file = '';
        $fp = false;
        if (isset($params['file'])) {
            $file = $params['file'];
            if (is_file($file)) {
                $fp   = fopen($file, 'r');
                $size = filesize($file);
                $options['CURLOPT_PUT']        = 1;
                $options['CURLOPT_INFILESIZE'] = $size;
                $options['CURLOPT_INFILE']     = $fp;
            } else {
                return null;
            }
            if (!isset($this->options['CURLOPT_USERPWD'])) {
                $this->setopt(['CURLOPT_USERPWD' => 'anonymous: noreply@moodle.org']);
            }
        } else {
            $options['CURLOPT_CUSTOMREQUEST'] = 'PUT';
            $options['CURLOPT_POSTFIELDS'] = $params;
        }

        $ret = $this->request($url, $options);
        if ($fp !== false) {
            fclose($fp);
        }
        return $ret;
    }

    /**
     * HTTP DELETE method
     *
     * @param string $url
     * @param array $param
     * @param array $options
     * @return string
     */
    public function delete($url, $param = [], $options = []) {
        $options['CURLOPT_CUSTOMREQUEST'] = 'DELETE';
        if (!isset($options['CURLOPT_USERPWD'])) {
            $options['CURLOPT_USERPWD'] = 'anonymous: noreply@moodle.org';
        }
        $ret = $this->request($url, $options);
        return $ret;
    }

    /**
     * HTTP TRACE method
     *
     * @param string $url
     * @param array $options
     * @return string
     */
    public function trace($url, $options = []) {
        $options['CURLOPT_CUSTOMREQUEST'] = 'TRACE';
        $ret = $this->request($url, $options);
        return $ret;
    }

    /**
     * HTTP OPTIONS method
     *
     * @param string $url
     * @param array $options
     * @return string
     */
    public function options($url, $options = []) {
        $options['CURLOPT_CUSTOMREQUEST'] = 'OPTIONS';
        $ret = $this->request($url, $options);
        return $ret;
    }

    /**
     * Get curl information
     *
     * @return array
     */
    public function get_info() {
        return $this->info;
    }

    /**
     * Get curl error code
     *
     * @return int
     */
    public function get_errno() {
        return $this->errno;
    }

    /**
     * When using a proxy, an additional HTTP response code may appear at
     * the start of the header. For example, when using https over a proxy
     * there may be 'HTTP/1.0 200 Connection Established'. Other codes are
     * also possible and some may come with their own headers.
     *
     * If using the return value containing all headers, this function can be
     * called to remove unwanted doubles.
     *
     * Note that it is not possible to distinguish this situation from valid
     * data unless you know the actual response part (below the headers)
     * will not be included in this string, or else will not 'look like' HTTP
     * headers. As a result it is not safe to call this function for general
     * data.
     *
     * @param string $input Input HTTP response
     * @return string HTTP response with additional headers stripped if any
     */
    public static function strip_double_headers($input) {
        // I have tried to make this regular expression as specific as possible
        // to avoid any case where it does weird stuff if you happen to put
        // HTTP/1.1 200 at the start of any line in your RSS file. This should
        // also make it faster because it can abandon regex processing as soon
        // as it hits something that doesn't look like an http header. The
        // header definition is taken from RFC 822, except I didn't support
        // folding which is never used in practice.
        $crlf = "\r\n";
        return preg_replace(
            // HTTP version and status code (ignore value of code).
            '~^HTTP/[1-9](\.[0-9])?.*' . $crlf .
            // Header name: character between 33 and 126 decimal, except colon.
            // Colon. Header value: any character except \r and \n. CRLF.
            '(?:[\x21-\x39\x3b-\x7e]+:[^' . $crlf . ']+' . $crlf . ')*' .
            // Headers are terminated by another CRLF (blank line).
            $crlf .
            // Second HTTP status code, this time must be 200.
            '(HTTP/[1-9](\.[0-9])? 200)~',
            '$2',
            $input
        );
    }
}

// Alias this class to the old name.
// This file will be autoloaded by the legacyclasses autoload system.
// In future all uses of this class will be corrected and the legacy references will be removed.
class_alias(curl::class, \curl::class);
