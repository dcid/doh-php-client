<?php

/* PHP client implementation of DoH (DNS over HTTPS).
 * Based on: https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-01
 * Supports A, AAAA and CNAME records.
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
function doh_raw2domain($qname)
{
    $mylenght = ord($qname[0]);
    $domainname = "";
    $i = 1;
    while(1)
    {
        while($mylenght)
        {
            $domainname = $domainname.$qname[$i++];
            $mylenght--;
        }
        $mylenght = ord($qname[$i]);
        $i++;

        if($mylenght == 0)
        {
            break;
        }
        else if($mylenght == 192)
        {
            /* cname pointing to itself */
            break;
        }
        $domainname = $domainname.".";
    }
    return($domainname);
}


/* DNS type names to raw types */
function doh_get_qtypes($requesttype = "A")
{
    if($requesttype === "AAAA")
    {   
        $rawtype = 28;
    }
    else if($requesttype === "CNAME")
    {   
        $rawtype = 5;
    }
    else if($requesttype === "NS")
    {   
        $rawtype = 2;
    }
    else
    {   
        $rawtype = 1;
    }
    return($rawtype);
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
    $ch = curl_init();
    $headers = array('Accept: application/dns-udpwireformat', 'Content-type: application/dns-udpwireformat');

    global $argv;
    if($argv[1] == "cloudflare-post")
    {
        curl_setopt($ch, CURLOPT_URL, "https://cloudflare-dns.com/dns-query"); // support POST
        curl_setopt($ch, CURLOPT_POSTFIELDS, base64_decode($dnsquery));
    }
    if($argv[1] == "experimental-post")
    {
        curl_setopt($ch, CURLOPT_URL, "https://dns.google.com/experimental?ct");
        curl_setopt($ch, CURLOPT_POSTFIELDS, base64_decode($dnsquery)); 
    }
    else if($argv[1] == "cloudflare")
    {
        curl_setopt($ch, CURLOPT_URL, "https://cloudflare-dns.com/dns-query?ct=application/dns-udpwireformat&dns=$dnsquery");
    }
    else if($argv[1] == "cleanbrowsing")
    {
        curl_setopt($ch, CURLOPT_URL, "https://doh.cleanbrowsing.org/doh/family-filter/?ct&dns=$dnsquery");
    }
    else
    {
        curl_setopt($ch, CURLOPT_URL, "https://dns.google.com/experimental?ct&dns=$dnsquery");
        curl_setopt($ch, CURLOPT_POSTFIELDS, base64_decode($dnsquery)); 
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'DOH-Client-PHP');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2); // true (or 1) removed in curl 7.28.1
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
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
    $results = array();
    $raw_counter = 0;

    $rawtype = doh_get_qtypes($requesttype);

    /* Getting header. */
    $qst_header = unpack("nid/nspec/nqdcount/nancount/nnscount/narcount", substr($raw, $raw_counter, 12));
    $raw_counter += 12;

    if($qst_header['ancount'] == 0)
    {
        return($results);
    }

    $domainresp = doh_raw2domain(substr( $raw, $raw_counter));


    $raw_counter += strlen($domainresp) + 2;
    $rawtype = ord($raw[$raw_counter + 7]);


    $ans_header = unpack("ntype/nclass/Nttl/nlength", substr( $raw, $raw_counter, 10 ) );
    $raw_counter += 13;

    /* Jumping to the IP address */
    $raw_counter += 3;

    $iplength = 4;
    if($rawtype === 28)
    {
        $iplength = 16;
    }

    if($rawtype == 1 || $rawtype == 28)
    {
        $result_ip = inet_ntop(substr( $raw, $raw_counter, $iplength ));
        if($rawtype == 1)
        {
            $results['ipv4'][] = $result_ip;
        }
        else
        {
            $results['ipv6'][] = $result_ip;
        }
        
        /* Looping through all answers */
        if($qst_header['ancount'] > 1)
        {
            $i = 1;
            while($i < $qst_header['ancount'])
            {
                $raw_counter += $iplength;
                $raw_counter += 12;
                if($rawtype == 1)
                {
                    $results['ipv4'][] = inet_ntop(substr( $raw, $raw_counter , $iplength ));
                }
                else
                {
                    $results['ipv6'][] = $result_ip;
                }
                $i++;
            }
        }
    }
    else if($rawtype == 5)
    {
        $domainresp = doh_raw2domain(substr( $raw, $raw_counter));
        $results['cname'][] = $domainresp;
    }
    return($results);
}



/* Testing. */
if(!isset($argv[2]))
{
    echo "Usage: ". $argv[0]. " [server:cloudflare,google,cleanbrowsing,cloudflare-post,experimental-post] [domain.com] <type: A, AAAA or CNAME>\n";
    exit(1);
}

$domainname = $argv[2];
if(!isset($argv[3]))
{
    $requesttype = "A";
}
else
{
    $requesttype = $argv[3];
}



/* Querying Google's by default. */
$dnsquery = doh_encoderequest(doh_generate_dnsquery($domainname, $requesttype));

$dnsrawresults = doh_connect_https($dnsquery);
$dnsresults = doh_read_dnsanswer($dnsrawresults, $requesttype);

if(empty($dnsresults))
{
    echo "Host $domainname not found: 3(NXDOMAIN)\n";
    exit(1);
}

if(isset($dnsresults['ipv4']))
{
    foreach($dnsresults['ipv4'] as $ipv4)
    {
        echo "$domainname has address $ipv4\n";
    }
}
if(isset($dnsresults['ipv6']))
{
    foreach($dnsresults['ipv6'] as $ipv6)
    {
        echo "$domainname has IPv6 address $ipv6\n";
    }
}
if(isset($dnsresults['cname']))
{
    foreach($dnsresults['cname'] as $cname)
    {
        echo "$domainname is an alias for $cname.\n";
    }
}



exit(0);
