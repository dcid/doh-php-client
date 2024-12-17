<?php

function doh_domain2raw($domainname)
{
    $raw = "";
    $domainpieces = explode('.', $domainname);
    foreach ($domainpieces as $domainbit) {
        $raw .= chr(strlen($domainbit)) . $domainbit;
    }
    $raw .= chr(0);
    return $raw;
}

function doh_raw2domain($response, &$offset)
{
    $labels = [];
    $limit = strlen($response); // Ensure we don’t exceed response size

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

function doh_get_qtypes($requesttype = "A")
{
    switch ($requesttype) {
        case "AAAA":
            return 28;
        case "CNAME":
            return 5;
        case "NS":
            return 2;
        case "MX":
            return 15;
        default:
            return 1; // A
    }
}

function doh_generate_dnsquery($domainname, $requesttype = "A")
{
    $rawtype = doh_get_qtypes($requesttype);
    $dns_query = sprintf("\xab\xcd") . chr(1) . chr(0) .
        chr(0) . chr(1) . // QDCount
        chr(0) . chr(0) . // ANCount
        chr(0) . chr(0) . // NSCount
        chr(0) . chr(0) . // ARCount
        doh_domain2raw($domainname) .
        chr(0) . chr($rawtype) .
        chr(0) . chr(1); // QClass
    return $dns_query;
}

function doh_connect_https($dnsquery, $server)
{
    $servers = [
        "google" => "https://dns.google/dns-query",
        "cloudflare" => "https://cloudflare-dns.com/dns-query"
    ];

    if (!isset($servers[$server])) {
        throw new Exception("Error: Unsupported DoH server '$server'.");
    }

    $doh_url = $servers[$server] . "?dns=" . base64_encode($dnsquery);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $doh_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/dns-message']);

    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        throw new Exception("cURL error: " . curl_error($ch));
    }
    curl_close($ch);

    return $response;
}

function doh_read_dnsanswer($response, $requesttype)
{
    $results = [];
    $offset = 12;

    echo "Raw response (hex): " . bin2hex($response) . "\n";

    $header = unpack("nTransactionID/nFlags/nQDCount/nANCount/nNSCount/nARCount", substr($response, 0, 12));
    print_r($header);

    $qdcount = $header['QDCount'];
    $ancount = $header['ANCount'];

    if ($ancount === 0) {
        echo "No answers found in the response.\n";
        return $results;
    }

    while ($qdcount-- > 0) {
        while (ord($response[$offset]) > 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5;
    }

    while ($ancount-- > 0) {
        $name = doh_raw2domain($response, $offset);
        $record = unpack("nType/nClass/NTTL/nLength", substr($response, $offset, 10));
        $offset += 10;

        $data = substr($response, $offset, $record['Length']);
        $offset += $record['Length'];

        if ($record['Type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === "MX") {
                $priority = unpack("n", substr($data, 0, 2))[1];
                $host_offset = $offset - $record['Length'] + 2;
                $host = doh_raw2domain($response, $host_offset);
                $results[] = "Priority $priority - $host";
            } elseif ($requesttype === "NS") {
                $results[] = doh_raw2domain($data, $offset);
            } elseif ($requesttype === "A" || $requesttype === "AAAA") {
                $results[] = inet_ntop($data);
            }
        }
    }

    return $results;
}

if ($argc < 4) {
    echo "Usage: php {$argv[0]} [server: google|cloudflare] [domain] [type: A|AAAA|MX|NS]\n";
    exit(1);
}

$server = $argv[1];
$domainname = $argv[2];
$requesttype = strtoupper($argv[3]);

$dnsquery = doh_generate_dnsquery($domainname, $requesttype);
$response = doh_connect_https($dnsquery, $server);
$results = doh_read_dnsanswer($response, $requesttype);

echo "DNS Records for $domainname ($requesttype):\n";
print_r($results);
