<?php

/* PHP client implementation of DoH (DNS over HTTPS).
 * Supports A, AAAA, CNAME, MX, and NS records.
 */

/* Domain str to DNS raw qname */
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

/* DNS raw qname to domain str */
function doh_raw2domain($response, &$offset)
{
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

/* DNS type names to raw types */
function doh_get_qtypes($requesttype = "A")
{
    $types = [
        "A" => 1,
        "AAAA" => 28,
        "CNAME" => 5,
        "MX" => 15,
        "NS" => 2
    ];
    return $types[$requesttype] ?? 1;
}

/* Generate a DNS raw query */
function doh_generate_dnsquery($domainname, $requesttype = "A")
{
    $rawtype = doh_get_qtypes($requesttype);
    $dns_query = sprintf("\xab\xcd") . chr(1) . chr(0) .
        chr(0) . chr(1) .  /* qdc */
        chr(0) . chr(0) .  /* anc */
        chr(0) . chr(0) .  /* nsc */
        chr(0) . chr(0) .  /* arc */
        doh_domain2raw($domainname) .
        chr(0) . chr($rawtype) .
        chr(0) . chr(1);  /* qclass */
    return $dns_query;
}

/* Connects via HTTPS to remote DoH servers */
function doh_connect_https($dnsquery)
{
    global $argv;

    // Base64URL encode the DNS query
    $encoded_dnsquery = str_replace(
        ['+', '/', '='],
        ['-', '_', ''],
        base64_encode($dnsquery)
    );

    // Determine the DoH server URL
    $doh_url = match ($argv[1]) {
        "cloudflare" => "https://cloudflare-dns.com/dns-query?dns=$encoded_dnsquery",
        "google" => "https://dns.google/dns-query?dns=$encoded_dnsquery",
        "cleanbrowsing" => "https://doh.cleanbrowsing.org/doh/family-filter/?dns=$encoded_dnsquery",
        default => die("Error: Unsupported DoH server.\n"),
    };

    // Set up cURL request
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
    $offset = 12; // Start reading after the header

    // Debug raw response
    echo "Raw response (hex): " . bin2hex($response) . "\n";

    // Parse DNS header
    $header = unpack("nTransactionID/nFlags/nQDCount/nANCount/nNSCount/nARCount", substr($response, 0, 12));
    print_r($header);

    $qdcount = $header['nQDCount'];
    $ancount = $header['nANCount'];

    if ($ancount === 0) {
        echo "No answers found in the response.\n";
        return $results;
    }

    // Skip question section
    while ($qdcount-- > 0) {
        while (ord($response[$offset]) > 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5; // Null byte + QTYPE + QCLASS
    }

    // Parse answer records
    while ($ancount-- > 0) {
        $name = doh_raw2domain($response, $offset); // Decode domain name
        $record = unpack("nType/nClass/NTTL/nLength", substr($response, $offset, 10));
        $offset += 10;

        $data = substr($response, $offset, $record['nLength']);
        $offset += $record['nLength'];

        if ($record['Type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === "MX") {
                $priority = unpack("n", substr($data, 0, 2))[1];
                $sub_offset = $offset - $record['nLength'] + 2;
                $host = doh_raw2domain($data, $sub_offset);
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
