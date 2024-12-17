<?php

if ($argc < 3) {
    die("Usage: php {$argv[0]} [server: cloudflare, google, cleanbrowsing] [domain] [type: A, AAAA, CNAME, MX, NS]\n");
}

$server = $argv[1];
$domain = $argv[2];
$requesttype = isset($argv[3]) ? strtoupper($argv[3]) : 'A';

$servers = [
    'cloudflare' => 'https://cloudflare-dns.com/dns-query',
    'google' => 'https://dns.google/dns-query',
    'cleanbrowsing' => 'https://doh.cleanbrowsing.org/doh/family-filter/dns-query',
];

if (!isset($servers[$server])) {
    die("Error: Unsupported server '$server'. Use 'cloudflare', 'google', or 'cleanbrowsing'.\n");
}

$doh_url = $servers[$server];

function doh_domain2raw($domainname) {
    $raw = "";
    foreach (explode('.', $domainname) as $domainbit) {
        $raw .= chr(strlen($domainbit)) . $domainbit;
    }
    return $raw . chr(0);
}

function doh_get_qtypes($requesttype) {
    $types = ['A' => 1, 'AAAA' => 28, 'CNAME' => 5, 'MX' => 15, 'NS' => 2];
    return $types[$requesttype] ?? 1;
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
        'Content-Type: application/dns-message',
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

function doh_raw2domain($response, &$offset) {
    $domainname = "";
    $jumped = false;
    $original_offset = $offset;

    while (true) {
        if ($offset >= strlen($response)) {
            die("Error: Offset out of bounds while parsing domain name.\n");
        }

        $len = ord($response[$offset]);

        if ($len === 0) {
            $offset++;
            break;
        }

        if (($len & 0xC0) === 0xC0) {
            if (!$jumped) {
                $original_offset = $offset + 2;
            }
            $pointer_offset = (($len & 0x3F) << 8) | ord($response[$offset + 1]);
            $offset = $pointer_offset;
            $jumped = true;
            continue;
        }

        $offset++;
        if ($offset + $len > strlen($response)) {
            die("Error: Length out of bounds while parsing domain name.\n");
        }
        $domainname .= substr($response, $offset, $len) . ".";
        $offset += $len;
    }

    if (!$jumped) {
        $offset = $original_offset;
    }

    return rtrim($domainname, ".");
}

function doh_read_dnsanswer($response, $requesttype) {
    $results = [];
    $header = unpack('nID/nFlags/nQDCount/nANCount/nNSCount/nARCount', substr($response, 0, 12));
    if ($header['ANCount'] == 0) {
        echo "Debug: No answers found in the response.\n";
        return $results;
    }

    $offset = 12;
    while ($header['QDCount']-- > 0) {
        while (ord($response[$offset]) > 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5;
    }

    while ($header['ANCount']-- > 0) {
        $name = doh_raw2domain($response, $offset);
        if (strlen($response) < $offset + 10) {
            die("Error: Response too short to parse record.\n");
        }
        $record = unpack('nType/nClass/NTTL/nLength', substr($response, $offset, 10));
        $offset += 10;

        if (strlen($response) < $offset + $record['Length']) {
            die("Error: Record length exceeds response size.\n");
        }
        $data = substr($response, $offset, $record['Length']);
        $offset += $record['Length'];

        if ($record['Type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === 'MX') {
                if (strlen($data) < 2) {
                    die("Error: MX record data too short.\n");
                }
                $priority = unpack('n', substr($data, 0, 2))[1];
                $sub_offset = $offset - $record['Length'] + 2;
                $host = doh_raw2domain($response, $sub_offset);
                $results[] = "$host (priority $priority)";
            } elseif ($requesttype === 'NS' || $requesttype === 'CNAME') {
                $results[] = doh_raw2domain($response, $offset - $record['Length']);
            } elseif ($requesttype === 'A' || $requesttype === 'AAAA') {
                $results[] = inet_ntop($data);
            }
        }
    }

    return $results;
}

$dnsquery = doh_generate_dnsquery($domain, $requesttype);
$response = doh_connect_https($doh_url, $dnsquery);
echo "Debug: Raw response: " . bin2hex($response) . "\n";

$results = doh_read_dnsanswer($response, $requesttype);

if (empty($results)) {
    die("No records found for $domain ($requesttype).\n");
}

echo "DNS Records for $domain ($requesttype):\n";
foreach ($results as $record) {
    echo "- $record\n";
}
