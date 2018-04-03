# doh-php-client
DoH (DNS over HTTPS) PHP Client

This is a proof of concept for a DoH (DNS over HTTPS) client in PHP. It is based on the latest draft `https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-03` and supports the GET method with the DNS UDP wire format. This is a work in progress and only the A, AAAA and CNAME records are supported. 

MX and NS are coming soon.

It supports CloudFlare's , Google's and CleanBrowsing DoH servers.


## Examples

This tool should be executed from the command line and it has a similar output as the `host` command. Example:

     $ php doh-php-client.php 
     Usage: doh-php-client.php [server:cloudflare,google,cleanbrowsing] [domain.com] <type: A, AAAA or CNAME>

     $php doh-php-client.php cloudflare github.com
     github.com has address 192.30.255.113
     github.com has address 192.30.255.112

Or for IPv6:

     $ php doh-php-client.php google sucuri.net AAAA
     sucuri.net has IPv6 address 2a02:fe80:1010::16


You have to specify as the first argument which DoH server to use. We support "google", "cloudflare" or "cleanbrowsing". 


## Limitations

This is just an initial test version. We will be spliting it into a better organized package later. 
