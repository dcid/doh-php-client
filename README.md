# doh-php-client
DoH (DNS over HTTPS) PHP Client

This is a proof of concept for DoH (DNS over HTTPS) client in PHP. It has not been fully tested, but seems to be working properly for A, AAAA and CNAME records.

I will be adding NS and MX records when time permits.

## Examples

This tool should be executed from the command line and it has a similar output as the `host` command. Example:

     $php doh-php-client.php github.com
     github.com has address 192.30.255.113
     github.com has address 192.30.255.112

Or for IPv6:

     $ php doh-php-client.php sucuri.net AAAA
     sucuri.net has IPv6 address 2a02:fe80:1010::16

It will use Google's experimental DoH server, but you can switch to any other.

## Limitations

This is just an initial test version. We will be spliting it into a better package later. 
