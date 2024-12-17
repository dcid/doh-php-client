<?php

if ($argc < 3) {
    die("Usage: php {$argv[0]} [server: cloudflare, google, cleanbrowsing, custom] [domain] [type: A, AAAA, CNAME, MX, NS] [custom_url if server=custom]\n");
}

$server = $argv[1];
$domain = $argv[2];
$requesttype = isset($argv[3]) ? strtoupper($argv[3]) : 'A';
$custom_url = isset($argv[4]) ? $argv[4] : null;

// Supported DoH servers
$servers = [
    'cloudflare' => 'https://cloudflare-dns.com/dns-query',
    'google' => 'https://dns.google/dns-query',
    'cleanbrowsing' => 'https://doh.cleanbrowsing.org/doh/family-filter/dns-query',
    'custom' => $custom_url,
];

if (!isset($servers[$server])) {
    die("Error: Unsupported server '$server'. Use 'cloudflare', 'google', 'cleanbrowsing', or 'custom'.\n");
}

if ($server === 'custom' && !$custom_url) {
    die("Error: When using 'custom', you must provide a custom DoH URL as the fourth argument.\n");
}

$doh_url = $servers[$server];

/* DNS Functions */
function doh_domain2raw($domainname) {
    $raw = "";
    foreach (explode('.', $domainname) as $domainbit) {
        $raw .= chr(strlen($domainbit)) . $domainbit;
    }
    return $raw . chr(0);
}

function doh_get_qtypes($requesttype) {
    $types = ['A' => 1, 'AAAA' => 28, 'CNAME' => 5, 'MX' => 15, 'NS' => 2];
    return $types[$requesttype] ?? 1; // Default to 'A'
}

function doh_generate_dnsquery($domainname, $requesttype) {
    $rawtype = doh_get_qtypes($requesttype);
    return "\xab\xcd" . // Transaction ID
           "\x01\x00" . // Flags: standard query
           "\x00\x01" . // Questions
           "\x00\x00" . // Answer RRs
           "\x00\x00" . // Authority RRs
           "\x00\x00" . // Additional RRs
           doh_domain2raw($domainname) .
           chr(0) . chr($rawtype) . // QTYPE
           chr(0) . chr(1);         // QCLASS (IN)
}

function doh_connect_https($doh_url, $dnsquery) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $doh_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $dnsquery);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/dns-message', // RFC-compliant
        'Accept: application/dns-message',
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

    return $response;
}

function doh_read_dnsanswer($response, $requesttype) {
    $results = [];
    $header = unpack('nID/nFlags/nQDCount/nANCount/nNSCount/nARCount', substr($response, 0, 12));
    if ($header['ANCount'] == 0) {
        return $results;
    }

    $offset = 12; // Skip the header
    while ($header['QDCount']-- > 0) { // Skip Questions
        while (ord($response[$offset]) > 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5; // Null byte + QTYPE + QCLASS
    }

    while ($header['ANCount']-- > 0) {
        $name = resolve_compressed_name($response, $offset);
        $record = unpack('nType/nClass/NTTL/nLength', substr($response, $offset, 10));
        $offset += 10;

        $data = substr($response, $offset, $record['Length']);
        $offset += $record['Length'];

        if ($record['Type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === 'MX') {
                $priority = unpack('n', substr($data, 0, 2))[1];
                $host = resolve_compressed_name($response, $offset - $record['Length'] + 2);
                $results[] = "$host (priority $priority)";
            } elseif ($requesttype === 'NS' || $requesttype === 'CNAME') {
                $host = resolve_compressed_name($response, $offset - $record['Length']);
                $results[] = $host;
            } elseif ($requesttype === 'A' || $requesttype === 'AAAA') {
                $results[] = inet_ntop($data);
            }
        }
    }

    return $results;
}

function resolve_compressed_name($response, &$offset) {
    $domainname = "";
    $jumps = 0;
    $original_offset = $offset;

    while (true) {
        $len = ord($response[$offset]);
        if ($len == 0) { // End of domain name
            $offset++;
            break;
        }

        if (($len & 0xC0) == 0xC0) { // Pointer
            if ($jumps++ > 10) { // Avoid infinite loops
                die("Error: Possible infinite pointer loop.\n");
            }
            $pointer_offset = unpack('n', substr($response, $offset, 2))[1] & 0x3FFF;
            $offset += 2;
            return $domainname . resolve_compressed_name($response, $pointer_offset);
        } else {
            $offset++;
            $domainname .= substr($response, $offset, $len) . ".";
            $offset += $len;
        }
    }

    return rtrim($domainname, ".");
}

/* Main */
$dnsquery = doh_generate_dnsquery($domain, $requesttype);
$response = doh_connect_https($doh_url, $dnsquery);
$results = doh_read_dnsanswer($response, $requesttype);

if (empty($results)) {
    die("No records found for $domain ($requesttype).\n");
}

echo "DNS Records for $domain ($requesttype):\n";
foreach ($results as $record) {
    echo "- $record\n";
}
