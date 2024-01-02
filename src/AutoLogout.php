<?php declare(strict_types=1);

namespace Pinga\Auth;

use Pinga\Auth\UserManager;

/**
 * Auto Logout for PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * 
 * @package ManyAuthentication
 * @author Engin Ypsilon <engin.ypsilon@gmail.com>
 */
class AutoLogout
{

    /** @var String session field for users last action time */
    const SESSION_FIELD_LAST_ACTION = 'auth_last_action';

    /** @var String get parameter name to prevent endless loops when redirect */
    const GET_IS_REDIRECTED = 'auth_redirected';

    /**
     * Logs the user automatically out after X seconds. Runs only, when a User is logged in
     * 
     * @param Int $seconds When the Login should expire, max lifetime in seconds
     * @param String $redirect Redirect user to a specific URL, otherwise the method will just destroy the SESSION
     * @param Callable $callback Callback function or a Closure function to do additional stuff
     * @param Int $statusCode Redirect Status code to set, default is: 301 "Moved Permanently"
     * @return VOID
     */
    public function watch(Int $seconds, String $redirect=null, Callable $callback=null, Int $statusCode=301): Void
    {
        if ($_SESSION[UserManager::SESSION_FIELD_LOGGED_IN] ?? false) {
            if ($l = ($_SESSION[self::SESSION_FIELD_LAST_ACTION] ?? false)) {
                if (\time() > $l+$seconds) {
                    \session_destroy();
                    if ($callback)
                        $callback($seconds, $redirect, $statusCode);
                    if ($redirect) {
                        $redirect .= (\strpos($redirect, '?') !== false ? '&' : '?') . self::GET_IS_REDIRECTED;
                        if (!isset($_GET[self::GET_IS_REDIRECTED]))
                            @\header("Location: {$redirect}", true, $statusCode);
                        exit(\sprintf('<h2>Redirection failed</h2><p>Go to: <a href="%1$s">URL %1$s</a></p>', \htmlspecialchars($redirect)));
                    }
                }
            }
            $_SESSION[self::SESSION_FIELD_LAST_ACTION] = \time();
        }
        return;
    }

}