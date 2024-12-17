<?php

/* PHP client implementation of DoH (DNS over HTTPS).
 * Based on: https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-01
 * Supports A, AAAA, CNAME, MX, and NS records.
 * Author: dcid
 * License: GPLv3
 */

/* Public DoH servers:
 * cloudflare https://cloudflare-dns.com/dns-query
 * google https://dns.google.com/experimental?ct&dns=
 * cleanbrowsing https://doh.cleanbrowsing.org/doh/family-filter/
 */

/* Domain str to DNS raw qname */
function doh_domain2raw($domainname)
{
    $raw = "";
    $domainpieces = explode('.', $domainname);
    foreach($domainpieces as $domainbit)
    {
        $raw = $raw.chr(strlen($domainbit)).$domainbit;
    }
    $raw = $raw.chr(0);
    return($raw);
}

/* DNS raw qname to domain str */
function doh_raw2domain($qname, $response, &$offset)
{
    $domainname = "";
    $jumped = false;
    $original_offset = $offset;

    while(1)
    {
        $len = ord($qname[$offset]);

        if($len === 0)
        {
            $offset++;
            break;
        }

        // Handle compressed labels
        if (($len & 0xC0) === 0xC0) {
            if (!$jumped) {
                $original_offset = $offset + 2;
            }
            $pointer_offset = (($len & 0x3F) << 8) | ord($qname[$offset + 1]);
            $offset = $pointer_offset;
            $jumped = true;
            continue;
        }

        $offset++;
        $domainname .= substr($qname, $offset, $len) . ".";
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
function doh_generate_dnsquery($domainname, $requesttype="A")
{
    $rawtype = doh_get_qtypes($requesttype);
    $dns_query  = sprintf("\xab\xcd").chr(1).chr(0).
                  chr(0).chr(1).  /* qdc */
                  chr(0).chr(0).  /* anc */
                  chr(0).chr(0).  /* nsc */
                  chr(0).chr(0).  /* arc */
                  doh_domain2raw($domainname).
                  chr(0).chr($rawtype).
                  chr(0).chr(1);  /* qclass */
    return($dns_query);
}

/* base64url encode the request */
function doh_encoderequest($request)
{
    return(str_replace("=", "", base64_encode($request)));
}

/* Connects via HTTPS to remote DoH servers */
function doh_connect_https($dnsquery)
{
    global $argv;
    $ch = curl_init();
    $headers = ['Accept: application/dns-udpwireformat', 'Content-type: application/dns-udpwireformat'];

    if($argv[1] == "cloudflare")
    {
        curl_setopt($ch, CURLOPT_URL, "https://cloudflare-dns.com/dns-query?ct=application/dns-udpwireformat&dns=$dnsquery");
    }
    else if($argv[1] == "google")
    {
        curl_setopt($ch, CURLOPT_URL, "https://dns.google/dns-query?dns=$dnsquery");
    }
    else if($argv[1] == "cleanbrowsing")
    {
        curl_setopt($ch, CURLOPT_URL, "https://doh.cleanbrowsing.org/doh/family-filter/?dns=$dnsquery");
    }
    else
    {
        die("Error: Unsupported server. Use 'cloudflare', 'google', or 'cleanbrowsing'.\n");
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'DOH-Client-PHP');
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $output = curl_exec($ch);

    if($output === FALSE)
    {
        return(null);
    }

    return($output);
}

/* Parses DNS raw answers. */
function doh_read_dnsanswer($raw, $requesttype)
{
    $results = [];
    $offset = 12;

    $header = unpack("nid/nspec/nqdcount/nancount/nnscount/narcount", substr($raw, 0, 12));
    if ($header['ancount'] == 0) {
        return $results;
    }

    while($header['qdcount']-- > 0)
    {
        while(ord($raw[$offset]) > 0)
        {
            $offset += ord($raw[$offset]) + 1;
        }
        $offset += 5;
    }

    while($header['ancount']-- > 0)
    {
        $name = doh_raw2domain($raw, $raw, $offset);
        $record = unpack("ntype/nclass/Nttl/nlength", substr($raw, $offset, 10));
        $offset += 10;

        $data = substr($raw, $offset, $record['length']);
        $offset += $record['length'];

        if($record['type'] == doh_get_qtypes($requesttype)) {
            if ($requesttype === "MX") {
                $priority = unpack("n", substr($data, 0, 2))[1];
                $host = doh_raw2domain($data, $raw, $offset);
                $results[] = "$host (priority $priority)";
            } else {
                $results[] = doh_raw2domain($data, $raw, $offset);
            }
        }
    }

    return $results;
}

/* Testing. */
if(!isset($argv[2]))
{
    echo "Usage: ". $argv[0]. " [server:cloudflare,google,cleanbrowsing] [domain.com] <type: A, AAAA, CNAME, MX, NS>\n";
    exit(1);
}

$domainname = $argv[2];
$requesttype = $argv[3] ?? "A";

$dnsquery = doh_encoderequest(doh_generate_dnsquery($domainname, $requesttype));
$dnsrawresults = doh_connect_https($dnsquery);

if (!$dnsrawresults) {
    die("Error: Failed to fetch DNS results.\n");
}

$dnsresults = doh_read_dnsanswer($dnsrawresults, $requesttype);

if(empty($dnsresults))
{
    echo "Host $domainname not found: 3(NXDOMAIN)\n";
    exit(1);
}

foreach($dnsresults as $result)
{
    echo "$result\n";
}

exit(0);
