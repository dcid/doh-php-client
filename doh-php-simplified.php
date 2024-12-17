<?php

/* ... (all functions as previously defined) ... */

/* Connects via HTTPS to remote DoH servers */
function doh_connect_https($dnsquery)
{
    global $argv;

    $encoded_dnsquery = str_replace(
        ['+', '/', '='],
        ['-', '_', ''],
        base64_encode($dnsquery)
    );

    $doh_url = match ($argv[1]) {
        "cloudflare" => "https://cloudflare-dns.com/dns-query?dns=$encoded_dnsquery",
        "google" => "https://dns.google/dns-query?dns=$encoded_dnsquery",
        "cleanbrowsing" => "https://doh.cleanbrowsing.org/doh/family-filter/?dns=$encoded_dnsquery",
        default => die("Error: Unsupported DoH server.\n"),
    };

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $doh_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/dns-message',
        'Content-Type: application/dns-message',
    ]);

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        die("cURL error: " . curl_error($ch) . "\n");
    }

    curl_close($ch);

    return $response;
}

/* Parses DNS raw answers. */
function doh_read_dnsanswer($response, $requesttype)
{
    $results = [];
    $offset = 12;

    // Debug raw response
    echo "Raw response (hex): " . bin2hex($response) . "\n";

    $header = unpack("nTransactionID/nFlags/nQDCount/nANCount/nNSCount/nARCount", substr($response, 0, 12));
    print_r($header);

    if (empty($header['nANCount'])) {
        echo "No answers found in the response.\n";
        return $results;
    }

    while ($header['nQDCount']-- > 0) {
        while (ord($response[$offset]) > 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5;
    }

    while ($header['nANCount']-- > 0) {
        $name = doh_raw2domain($response, $offset);

        $record = unpack("nType/nClass/NTTL/nLength", substr($response, $offset, 10));
        $offset += 10;

        $data = substr($response, $offset, $record['nLength']);
        $offset += $record['nLength'];

        if ($record['Type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === "MX") {
                $priority = unpack("n", substr($data, 0, 2))[1];
                $sub_offset = $offset - $record['nLength'] + 2;
                $host = doh_raw2domain($response, $sub_offset);
                $results[] = "Priority $priority - $host";
            } elseif ($requesttype === "NS") {
                $results[] = doh_raw2domain($response, $offset - $record['nLength']);
            } elseif ($requesttype === "A" || $requesttype === "AAAA") {
                $results[] = inet_ntop($data);
            }
        }
    }

    return $results;
}

/* Testing. */
if (!isset($argv[2])) {
    die("Usage: {$argv[0]} [server:cloudflare,google,cleanbrowsing] [domain] [type: A, AAAA, CNAME, MX, NS]\n");
}

$domainname = $argv[2];
$requesttype = $argv[3] ?? "A";

$dnsquery = doh_generate_dnsquery($domainname, $requesttype);
$response = doh_connect_https($dnsquery);
$results = doh_read_dnsanswer($response, $requesttype);

echo "DNS Records for $domainname ($requesttype):\n";
print_r($results);
