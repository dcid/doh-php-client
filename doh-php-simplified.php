<?php

if ($argc < 3) {
    die("Usage: php {$argv[0]} [server|custom] [domain] [type: A, AAAA, CNAME, MX, NS] [custom_url]\n");
}

$server = $argv[1];
$domain = $argv[2];
$type = isset($argv[3]) ? strtoupper($argv[3]) : 'A';
$custom_url = isset($argv[4]) ? $argv[4] : null;

// Supported DNS record types
$supported_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS'];
if (!in_array($type, $supported_types)) {
    die("Error: Record type '$type' not supported. Supported types are: " . implode(', ', $supported_types) . "\n");
}

switch ($server) {
    case 'cloudflare':
        $doh_url = 'https://cloudflare-dns.com/dns-query';
        break;
    case 'google':
        $doh_url = 'https://dns.google/dns-query';
        break;
    case 'cleanbrowsing':
        $doh_url = 'https://doh.cleanbrowsing.org/doh/family-filter/';
        break;
    case 'custom':
        if (!$custom_url) {
            die("Error: Custom URL not provided. Use: php {$argv[0]} custom [domain] [type] [custom_url]\n");
        }
        if (!filter_var($custom_url, FILTER_VALIDATE_URL)) {
            die("Error: Invalid custom URL provided.\n");
        }
        $doh_url = $custom_url;
        break;
    default:
        die("Error: Unsupported server. Use 'cloudflare', 'google', 'cleanbrowsing', or 'custom'.\n");
}

function doh_connect_https($doh_url, $domain, $type) {
    // Prepare DNS query parameters
    $params = http_build_query([
        'name' => $domain,
        'type' => $type, // Ensure the type is explicitly passed
    ]);

    // Build full DoH query URL
    $url = $doh_url . '?' . $params;

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/dns-json',
    ]);

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        die("cURL error: " . curl_error($ch) . "\n");
    }

    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($http_code !== 200) {
        die("Error: DoH server responded with HTTP status $http_code.\n");
    }

    curl_close($ch);

    $response_data = json_decode($response, true);

    if (!$response_data || !isset($response_data['Answer'])) {
        die("Error: No valid response or DNS records found for {$domain}. Response: " . json_encode($response_data) . "\n");
    }

    echo "DNS Records for {$domain}:\n";
    foreach ($response_data['Answer'] as $answer) {
        $record_type = $answer['type'];
        $record_data = $answer['data'];

        // Decode record type for human-readable output
        switch ($record_type) {
            case 1:  // A
                echo "- A Record: {$record_data}\n";
                break;
            case 28: // AAAA
                echo "- AAAA Record: {$record_data}\n";
                break;
            case 5:  // CNAME
                echo "- CNAME Record: {$record_data}\n";
                break;
            case 15: // MX
                echo "- MX Record: {$record_data}\n";
                break;
            case 2:  // NS
                echo "- NS Record: {$record_data}\n";
                break;
            default:
                echo "- Unknown Record (Type {$record_type}): {$record_data}\n";
        }
    }
}

doh_connect_https($doh_url, $domain, $type);
