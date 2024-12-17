<?php

if ($argc < 3) {
    die("Usage: php {$argv[0]} [server: cloudflare, google, cleanbrowsing] [domain] [type: A, AAAA, CNAME, MX, NS]\n");
}

$server = $argv[1];
$domain = $argv[2];
$requesttype = isset($argv[3]) ? strtoupper($argv[3]) : 'A';

// Supported DoH servers
$servers = [
    'cloudflare' => 'https://cloudflare-dns.com/dns-query',
    'google' => 'https://dns.google/dns-query',
    'cleanbrowsing' => 'https://doh.cleanbrowsing.org/doh/family-filter/dns-query',
];

if (!isset($servers[$server])) {
    die("Error: Unsupported server '$server'. Use 'cloudflare', 'google', or 'cleanbrowsing'.\n");
}

$doh_url = $servers[$server];

/* DNS Functions */
function doh_domain2raw($domainname)
{
    $raw = "";
    foreach (explode('.', $domainname) as $domainbit) {
        $raw .= chr(strlen($domainbit)) . $domainbit;
    }
    return $raw . chr(0);
}

function doh_get_qtypes($requesttype)
{
    $types = ['A' => 1, 'AAAA' => 28, 'CNAME' => 5, 'MX' => 15, 'NS' => 2];
    return $types[$requesttype] ?? 1; // Default to 'A'
}

function doh_generate_dnsquery($domainname, $requesttype)
{
    $rawtype = doh_get_qtypes($requesttype);
    return "\xab\xcd" . // Transaction ID
        "\x01\x00" .   // Flags: standard query
        "\x00\x01" .   // Questions
        "\x00\x00" .   // Answer RRs
        "\x00\x00" .   // Authority RRs
        "\x00\x00" .   // Additional RRs
        doh_domain2raw($domainname) .
        chr(0) . chr($rawtype) . // QTYPE
        chr(0) . chr(1);         // QCLASS (IN)
}

function doh_connect_https($doh_url, $dnsquery)
{
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

function doh_raw2domain($response, &$offset)
{
    $labels = [];
    $limit = strlen($response);

    while ($offset < $limit) {
        $length = ord($response[$offset]);

        if ($length === 0) {
            $offset++;
            break;
        } elseif (($length & 0xC0) === 0xC0) {
            $pointer = (($length & 0x3F) << 8) | ord($response[$offset + 1]);
            $offset += 2;
            $labels[] = doh_raw2domain($response, $pointer);
            break;
        } else {
            $offset++;
            $labels[] = substr($response, $offset, $length);
            $offset += $length;
        }
    }

    return implode('.', $labels);
}

function doh_read_dnsanswer($response, $requesttype)
{
    $results = [];
    $offset = 12;

    $header = unpack('nTransactionID/nFlags/nQDCount/nANCount/nNSCount/nARCount', substr($response, 0, 12));
    if ($header['ANCount'] == 0) {
        return $results;
    }

    // Skip questions
    while ($header['QDCount']-- > 0) {
        while (ord($response[$offset]) > 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5; // Null byte + QTYPE + QCLASS
    }

    // Process answers
    while ($header['ANCount']-- > 0) {
        $name = doh_raw2domain($response, $offset);
        $record = unpack('nType/nClass/NTTL/nLength', substr($response, $offset, 10));
        $offset += 10;

        $data = substr($response, $offset, $record['Length']);
        $offset += $record['Length'];

        if ($record['Type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === 'MX') {
                $priority = unpack('n', substr($data, 0, 2))[1];
                $host_offset = $offset - $record['Length'] + 2;
                $host = doh_raw2domain($response, $host_offset);
                $results[] = "$host (priority $priority)";
            } elseif ($requesttype === 'NS' || $requesttype === 'CNAME') {
                $host_offset = $offset - $record['Length'];
                $results[] = doh_raw2domain($response, $host_offset);
            } elseif ($requesttype === 'A' || $requesttype === 'AAAA') {
                $results[] = inet_ntop($data);
            }
        }
    }

    return $results;
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
