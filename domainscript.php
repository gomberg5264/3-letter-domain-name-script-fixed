<?php
///////////////////////////////////////////////////////////////////////////////
//
// Scans for 3-letter domain names.
//
///////////////////////////////////////////////////////////////////////////////
// This is the number of domains the script will stop at.
$i = 1000;

ob_start();

function checkdomain($xserver, $xdomain) {
    $sock = fsockopen($xserver,43) or die("Error Connecting To Whois Server");
    fputs($sock,"$xdomain\r\n");
    $result = '';
    while(!feof($sock))
        $result .= fgets($sock,128);
    fclose($sock);
    return (strpos($result, "No match") !== FALSE ||
            strpos($result, "no matches") !== FALSE ||
            strpos($result, "NO MATCH") !== FALSE ||
            strpos($result, "not found") !== FALSE ||
            strpos($result, "Not found") !== FALSE ||
            strpos($result, "NOT FOUND") !== FALSE ||
            strpos($result, "Status:      FREE") !== FALSE ||
            strpos($result, "Status: free") != TRUE ||
            strpos($result, "No entries found") != FALSE);
}

Header("Content-Type: text/plain");

$chars = str_split("abcdefghijklmnopqrstuvwxyz");

$registrars = array(
   // "com"  => "whois.porkbun.com",
    //"net"  => "whois.porkbun.com",
    "org"  => "whois.pir.org",
    //"info" => "whois.porkbun.com",
    //"biz"  => "whois.porkbun.com",
    //"us"   => "whois.porkbun.com",
    //"nu"   => "whois.porkbun.com",
   // "se"   => "whois.porkbun.com",
   // "no"   => "whois.porkbun.com",
  //  "dk"   => "whois.porkbun.com",
    //"be"   => "whois.porkbun.com",
    //"de"   => "whois.porkbun.com",
);

set_time_limit(30);

while($i > 0){
    $current = $chars[array_rand($chars)].
               $chars[array_rand($chars)].
               $chars[array_rand($chars)];
               
    $found = false;

    foreach ($registrars as $tld => $server) {
        if (checkdomain($server,"$current.$tld")) {
            $found = true;
            echo "$current.$tld\n";
            $i-=1;
        }
    }

    if ($found)
        echo "\n";
        
    ob_flush();
    flush();
}

echo "\nDone.\n";
ob_flush();
flush();

?>
