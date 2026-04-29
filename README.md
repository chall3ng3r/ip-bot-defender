# IP & Bot Defender

**IP & Bot Defender** is a lightweight, high-performance security plugin for WordPress designed to protect your website from aggressive bots, vulnerability scanners, and brute-force login attacks. It is specifically optimized for environments behind reverse proxies like **Cloudflare** and **Nginx**, ensuring that real offending client IPs are blocked rather than the proxy infrastructure.

## Overview

Modern websites are constantly bombarded by automated scripts hunting for plugin vulnerabilities or attempting to guess administrative passwords. These requests often result in 404 errors (scanning for missing files) or 403 errors. **IP & Bot Defender** monitors these patterns in real-time and drops the connection before the bot can cause further stress on your PHP-FPM or Database resources.

## Features

- **Automated 404 IP Blocking**: Automatically bans IPs that trigger a set number of 404 errors within a specific timeframe.
- **Brute-Force Login Protection**: Monitors failed login attempts and locks out offending IPs after reaching a retry threshold.
- **Bot & User-Agent Filtering**: Block specific bot names (e.g., `python-requests`, `Go-http-client`) or generic scripts.
- **Empty User-Agent Blocking**: Instantly drops requests that do not provide a User-Agent header—a common trait of poorly written scrapers.
- **Cloudflare & Nginx Optimized**: Accurately detects the real visitor IP using `CF-Connecting-IP` and `X-Forwarded-For` headers.
- **Infrastructure Safety Net**: Built-in protection to prevent accidental blocking of Cloudflare's own IP ranges.
- **Admin Dashboard**: A multi-tab interface to manage 404 blocks, login blocks, and global settings with real-time counters.

## Security Implementation

### Layered Defense
The plugin implements security at the **INIT** hook, the earliest possible point in the WordPress execution lifecycle. This prevents "bad actors" from loading your theme, CSS, or heavy plugins, significantly reducing server load during an attack.

### Non-Persistent Performance
By utilizing the **WordPress Transients API**, the plugin avoids permanent database bloat. Strike counts and bans live in the options table (or object cache like Redis/Memcached) and expire naturally, ensuring your database remains lean and fast.

### Proxy Awareness
Unlike standard security plugins that might block your own proxy server, this plugin verifies the source. It prioritizes headers provided by Cloudflare to ensure only the true offender is mitigated.

## Technical Details

- **Hardware Compatibility**: Optimized for low-power hardware (e.g., Intel i5-6500T mini PCs).
- **Data Storage**: Uses the `wp_options` table via Transients API.
- **Logic**: 
    - Case-insensitive string matching for bots.
    - Bitwise CIDR range checking for infrastructure protection.
    - Serialized data storage for block metadata (User-Agent, timestamp).
- **Permissions**: Settings and logs are restricted to `Administrator` and `Editor` roles (capability: `edit_pages`).

## Installation Guide

1.  **Download Plugin ZIP**: Navigate to **Releases** and download **ip-bot-defender-v1x.zip**.
2.  **Upload File**: In WordPress Dachboard > Plugins > Add Plugins > Click `Upload Plugin` button, and select the downloaded file.
3.  **Activate**: WordPress Dashboard, go to **Plugins**, and click **Activate** on **IP & Bot Defender**.
4.  **Configure**: 
    - Go to the **IP & Bot Defender** menu in the sidebar.
    - Set your **Max 404 Errors** (Recommended: 5).
    - Set your **Max Login Retries** (Recommended: 3).
    - Add custom scripts to the **Bot List** if necessary.
5.  **Verify**: Check the blue info box on the settings page to ensure your real IP is being detected correctly.

---
*Developed by chall3ng3r.com*
