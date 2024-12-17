<?php

if ($argc < 3) {
    die("Usage: php {$argv[0]} [server|custom] [domain] [type: A, AAAA, CNAME] [custom_url]\n");
}

$server = $argv[1];
$domain = $argv[2];
$type = isset($argv[3]) ? $argv[3] : 'A';
$custom_url = isset($argv[4]) ? $argv[4] : null;

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
    $dns_query = [
        'name' => $domain,
        'type' => $type,
    ];

    $encoded_query = base64_encode(json_encode($dns_query));

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $doh_url . '?dns=' . $encoded_query);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/dns-json',
    ]);

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        die("cURL error: " . curl_error($ch) . "\n");
    }

    curl_close($ch);

    $response_data = json_decode($response, true);

    if (!$response_data || !isset($response_data['Answer'])) {
        die("Error: No valid response or DNS records found for {$domain}.\n");
    }

    echo "DNS Records for {$domain}:\n";
    foreach ($response_data['Answer'] as $answer) {
        echo "- Type: {$answer['type']} | Data: {$answer['data']}\n";
    }
}

doh_connect_https($doh_url, $domain, $type);
