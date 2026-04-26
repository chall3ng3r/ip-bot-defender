<?php
/**
 * Plugin Name: IP & Bot Defender
 * Description: Blocks IPs and bots that generate too many 404 errors or failed login attempts. Optimized for Cloudflare & Nginx setups.
 * Version: 1.2.1
 * Author: chall3ng3r.com
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class IP_Bot_Defender {

    private $option_name = 'ipbd_settings';

    public function __construct() {
        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'handle_admin_actions' ) );
        add_action( 'init', array( $this, 'intercept_bad_actors' ) );
        add_action( 'template_redirect', array( $this, 'track_404_errors' ) );
        
        // Login Protection Hooks
        add_action( 'wp_login_failed', array( $this, 'track_login_failed' ) );
        add_action( 'login_init', array( $this, 'intercept_login_blocked' ) );
        
        add_action( 'admin_footer', array( $this, 'render_admin_scripts' ) );
    }

    private function get_settings() {
        $defaults = array(
            'error_threshold' => 5,
            'time_limit'      => 24, 
            'status_code'     => 403,
            'bot_list'        => '',
            'bot_status_code' => 403,
            'block_empty_ua'  => 0,
            'login_threshold' => 3,
            'login_lockout'   => 3, 
        );
        return wp_parse_args( get_option( $this->option_name, array() ), $defaults );
    }

    public function add_admin_menu() {
        add_menu_page(
            'IP & Bot Defender Settings',
            'IP & Bot Defender',
            'edit_pages',
            'ip-bot-defender',
            array( $this, 'render_admin_page' ),
            'dashicons-shield',
            80
        );
    }

    /**
     * Helper to get count of active blocks from the database
     */
    private function get_block_count($type) {
        global $wpdb;
        $prefix = "_transient_ipbd_{$type}_";
        // We count the base transients, excluding the timeout records
        return (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(option_id) FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name NOT LIKE %s",
            $wpdb->esc_like( $prefix ) . '%',
            $wpdb->esc_like( '_transient_timeout_' ) . '%'
        ));
    }

    public function get_client_ip() {
        $ip = '0.0.0.0';
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
            $ip = trim( $ips[0] );
        } elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    private function is_cloudflare_infrastructure_ip($ip) {
        $cf_ipv4_ranges = array(
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        );
        foreach ($cf_ipv4_ranges as $range) {
            if ($this->ip_in_range($ip, $range)) return true;
        }
        return false;
    }

    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) $range .= '/32';
        list($range, $netmask) = explode('/', $range, 2);
        $range_dec = ip2long($range);
        $ip_dec = ip2long($ip);
        $wildcard_dec = pow(2, (32 - $netmask)) - 1;
        $netmask_dec = ~ $wildcard_dec;
        return (($ip_dec & $netmask_dec) == ($range_dec & $netmask_dec));
    }

    public function handle_admin_actions() {
        if ( ! current_user_can( 'edit_pages' ) ) return;

        if ( isset( $_POST['ipbd_save_settings'] ) ) {
            check_admin_referer( 'ipbd_save_action', 'ipbd_settings_nonce' );
            $new_settings = array(
                'error_threshold' => absint( $_POST['ipbd_error_threshold'] ),
                'time_limit'      => absint( $_POST['ipbd_time_limit'] ),
                'status_code'     => absint( $_POST['ipbd_status_code'] ),
                'bot_list'        => sanitize_textarea_field( wp_unslash( $_POST['ipbd_bot_list'] ) ),
                'bot_status_code' => absint( $_POST['ipbd_bot_status_code'] ),
                'block_empty_ua'  => isset( $_POST['ipbd_block_empty_ua'] ) ? 1 : 0,
                'login_threshold' => absint( $_POST['ipbd_login_threshold'] ),
                'login_lockout'   => absint( $_POST['ipbd_login_lockout'] ),
            );
            update_option( $this->option_name, $new_settings );
            add_settings_error( 'ipbd_messages', 'ipbd_message', 'Settings Saved.', 'updated' );
        }

        if ( (isset( $_POST['ipbd_bulk_unblock'] ) && !empty( $_POST['ipbd_ips'] )) || isset( $_POST['ipbd_unblock_ip'] ) ) {
            $is_bulk = isset($_POST['ipbd_bulk_unblock']);
            check_admin_referer( $is_bulk ? 'ipbd_bulk_action' : 'ipbd_unblock_action', $is_bulk ? 'ipbd_bulk_nonce' : 'ipbd_unblock_nonce' );
            
            $ips = $is_bulk ? $_POST['ipbd_ips'] : array($_POST['ipbd_unblock_ip']);
            $type = isset($_GET['tab']) && $_GET['tab'] === 'login-blocks' ? 'login' : 'blocked';

            foreach ( $ips as $ip ) {
                $safe_ip = sanitize_text_field($ip);
                delete_transient( "ipbd_{$type}_" . $safe_ip );
                delete_transient( "ipbd_" . ($type === 'login' ? 'login_strikes_' : 'strikes_') . $safe_ip );
            }
            add_settings_error( 'ipbd_messages', 'ipbd_message', "IP(s) unblocked.", 'updated' );
        }
    }

    public function render_admin_page() {
        $active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'settings';
        
        // Get counts for tab labels
        $count_404 = $this->get_block_count('blocked');
        $count_login = $this->get_block_count('login');
        ?>
        <div class="wrap">
            <h1>IP & Bot Defender</h1>
            <div class="notice notice-info is-dismissible">
                <p><strong>Cloudflare Detection Active:</strong> Your detected IP: <code><?php echo esc_html($this->get_client_ip()); ?></code></p>
            </div>
            <?php settings_errors( 'ipbd_messages' ); ?>
            
            <h2 class="nav-tab-wrapper">
                <a href="?page=ip-bot-defender&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
                <a href="?page=ip-bot-defender&tab=blocked-ips" class="nav-tab <?php echo $active_tab == 'blocked-ips' ? 'nav-tab-active' : ''; ?>">404 Blocks (<?php echo $count_404; ?>)</a>
                <a href="?page=ip-bot-defender&tab=login-blocks" class="nav-tab <?php echo $active_tab == 'login-blocks' ? 'nav-tab-active' : ''; ?>">Login Blocks (<?php echo $count_login; ?>)</a>
            </h2>

            <div class="dbb-tab-content" style="margin-top: 20px;">
                <?php
                if ( $active_tab == 'blocked-ips' ) $this->render_ips_tab('blocked');
                elseif ( $active_tab == 'login-blocks' ) $this->render_ips_tab('login');
                else $this->render_settings_tab();
                ?>
            </div>
        </div>
        <?php
    }

    private function render_ips_tab($type) {
        global $wpdb;
        $prefix = "_transient_ipbd_{$type}_";
        $results = $wpdb->get_results( $wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name NOT LIKE %s",
            $wpdb->esc_like( $prefix ) . '%',
            $wpdb->esc_like( '_transient_timeout_' ) . '%'
        ));
        ?>
        <form method="POST" action="">
            <?php wp_nonce_field( 'ipbd_bulk_action', 'ipbd_bulk_nonce' ); ?>
            <div class="tablenav top">
                <div class="alignleft actions bulkactions">
                    <input type="submit" name="ipbd_bulk_unblock" class="button action" value="Unblock Selected" onclick="return confirm('Unblock selected IPs?');">
                </div>
            </div>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <td class="manage-column column-cb check-column"><input id="cb-select-all-1" type="checkbox"></td>
                        <th>IP Address</th>
                        <th>User-Agent</th>
                        <th>Time Blocked</th>
                        <th>Time Remaining</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    if ( empty( $results ) ) {
                        echo '<tr><td colspan="6">No blocked IPs found here.</td></tr>';
                    } else {
                        $current_time = time();
                        foreach ( $results as $row ) {
                            $ip = str_replace( $prefix, '', $row->option_name );
                            $data = maybe_unserialize( $row->option_value );
                            $timeout = get_option( "_transient_timeout_ipbd_{$type}_" . $ip );
                            if ( $timeout && $timeout < $current_time ) continue;
                            $diff = $timeout - $current_time;
                            ?>
                            <tr>
                                <th scope="row" class="check-column"><input type="checkbox" name="ipbd_ips[]" value="<?php echo esc_attr($ip); ?>"></th>
                                <td><strong><?php echo esc_html($ip); ?></strong></td>
                                <td style="font-size:11px;"><?php echo esc_html($data['ua'] ?? 'Unknown'); ?></td>
                                <td><?php echo wp_date('M j, Y - g:i A', $data['time']); ?></td>
                                <td><?php echo ($diff > 0) ? floor($diff/3600).'h '.floor(($diff/60)%60).'m' : 'Expired'; ?></td>
                                <td>
                                    <button type="submit" name="ipbd_unblock_ip" value="<?php echo esc_attr($ip); ?>" class="button button-small">Unblock</button>
                                    <?php wp_nonce_field( 'ipbd_unblock_action', 'ipbd_unblock_nonce' ); ?>
                                </td>
                            </tr>
                            <?php
                        }
                    }
                    ?>
                </tbody>
            </table>
        </form>
        <?php
    }

    private function render_settings_tab() {
        $settings = $this->get_settings();
        ?>
        <form method="POST" action="?page=ip-bot-defender&tab=settings">
            <?php wp_nonce_field( 'ipbd_save_action', 'ipbd_settings_nonce' ); ?>
            <table class="form-table">
                <tr><th colspan="2"><h3>404 Protection Settings</h3></th></tr>
                <tr>
                    <th scope="row">Max 404 Errors</th>
                    <td><input type="number" name="ipbd_error_threshold" value="<?php echo esc_attr($settings['error_threshold']); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th scope="row">404 Block Duration (Hours)</th>
                    <td><input type="number" name="ipbd_time_limit" value="<?php echo esc_attr($settings['time_limit']); ?>" min="1" /></td>
                </tr>
                <tr><th colspan="2"><h3>Login Protection Settings</h3></th></tr>
                <tr>
                    <th scope="row">Max Login Retries</th>
                    <td><input type="number" name="ipbd_login_threshold" value="<?php echo esc_attr($settings['login_threshold']); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th scope="row">Login Block Duration (Hours)</th>
                    <td><input type="number" name="ipbd_login_lockout" value="<?php echo esc_attr($settings['login_lockout']); ?>" min="1" /></td>
                </tr>
                <tr><th colspan="2"><h3>Bot & Global Settings</h3></th></tr>
                <tr>
                    <th scope="row">Manual Bot List</th>
                    <td><textarea name="ipbd_bot_list" rows="5" cols="50"><?php echo esc_textarea($settings['bot_list']); ?></textarea></td>
                </tr>
                <tr>
                    <th scope="row">Block Empty User-Agent</th>
                    <td><input type="checkbox" name="ipbd_block_empty_ua" value="1" <?php checked(1, $settings['block_empty_ua']); ?> /></td>
                </tr>
                <tr>
                    <th scope="row">HTTP Status for Ban</th>
                    <td><input type="number" name="ipbd_status_code" value="<?php echo esc_attr($settings['status_code']); ?>" /></td>
                </tr>
            </table>
            <?php submit_button('Save Settings', 'primary', 'ipbd_save_settings'); ?>
        </form>
        <?php
    }

    public function intercept_bad_actors() {
        if (is_admin() || wp_doing_ajax()) return;
        $ip = $this->get_client_ip();
        $settings = $this->get_settings();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? trim($_SERVER['HTTP_USER_AGENT']) : '';

        if (get_transient('ipbd_blocked_' . $ip) || get_transient('ipbd_login_' . $ip)) {
            status_header($settings['status_code']);
            exit('Access Denied.');
        }

        if (!empty($settings['block_empty_ua']) && empty($ua)) {
            status_header(403);
            exit('Access Denied.');
        }

        if (!empty($settings['bot_list']) && !empty($ua)) {
            $bots = explode("\n", str_replace("\r", "", $settings['bot_list']));
            foreach ($bots as $bot) {
                if (!empty(trim($bot)) && stripos($ua, trim($bot)) !== false) {
                    status_header(403);
                    exit('Access Denied.');
                }
            }
        }
    }

    public function track_login_failed() {
        $ip = $this->get_client_ip();
        if ($this->is_cloudflare_infrastructure_ip($ip)) return;

        $settings = $this->get_settings();
        $strike_key = 'ipbd_login_strikes_' . $ip;
        $strikes = (int)get_transient($strike_key) + 1;
        
        if ($strikes >= $settings['login_threshold']) {
            set_transient('ipbd_login_'.$ip, array('time'=>time(), 'ua'=>$_SERVER['HTTP_USER_AGENT']??'Unknown'), $settings['login_lockout'] * HOUR_IN_SECONDS);
            delete_transient($strike_key);
        } else {
            set_transient($strike_key, $strikes, 1 * HOUR_IN_SECONDS);
        }
    }

    public function intercept_login_blocked() {
        $ip = $this->get_client_ip();
        if (get_transient('ipbd_login_' . $ip)) {
            status_header($this->get_settings()['status_code']);
            exit('Login Access Denied.');
        }
    }

    public function track_404_errors() {
        if (is_404()) {
            $ip = $this->get_client_ip();
            if ($this->is_cloudflare_infrastructure_ip($ip)) return;

            $settings = $this->get_settings();
            $strike_key = 'ipbd_strikes_' . $ip;
            $strikes = (int)get_transient($strike_key) + 1;
            $time = $settings['time_limit'] * HOUR_IN_SECONDS;

            if ($strikes >= $settings['error_threshold']) {
                set_transient('ipbd_blocked_'.$ip, array('time'=>time(), 'ua'=>$_SERVER['HTTP_USER_AGENT']??'Unknown'), $time);
                status_header($settings['status_code']);
                exit('Access Denied.');
            } else {
                set_transient($strike_key, $strikes, $time);
            }
        }
    }

    public function render_admin_scripts() {
        ?>
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                $('#cb-select-all-1').click(function() {
                    $('input[name="ipbd_ips[]"]').prop('checked', this.checked);
                });
            });
        </script>
        <?php
    }
}

new IP_Bot_Defender();