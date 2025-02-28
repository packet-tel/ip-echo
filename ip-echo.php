<?php
// ip-echo.php - An IP Echo Tool that echos back your IP address & other browser information.
// Written By PACKET.TEL LLC
// LICENSED FOR FREE PERSONAL, NON-COMMERICAL USE. 
// COMMERCIAL AND/OR CORPORATE USE, EVEN INTERNALLY ONLY, IS FORBIDDEN WITHOUT A LICENSE. 
// PLEASE CONTACT licenses@packet.tel FOR PRICING.
// ------------------------------------------------------------------------------------------------- //
// Lets get started..
// Check for IP-Only Mode
$ip_only = isset($_GET['ip']); // Just ?ip triggers IP-only mode

// Get client IP (try multiple methods to grab proxified connection sources)
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $forwarded = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $client_ip = trim($forwarded[0]);
} elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
    $client_ip = $_SERVER['HTTP_CLIENT_IP'];
}

// Convert IP to integer for database lookup
$ip_num = ip2long($client_ip);

// Database lookup for country and ASN
$db_path = '/var/www/database/country_asn.db';
$country_code = 'Unknown';
$country_name = 'Unknown';
$continent_code = 'Unknown';
$continent_name = 'Unknown';
$asn = 'Unknown';
$as_name = 'Unknown';
$as_domain = 'Unknown';

if (file_exists($db_path)) {
    try {
        $db = new SQLite3($db_path);
        $query = 'SELECT country_code, country_name, continent_code, continent_name, asn, as_name, as_domain
                  FROM ip_ranges
                  WHERE start_ip <= :ip AND end_ip >= :ip
                  LIMIT 1';
        $stmt = $db->prepare($query);
        if ($stmt === false) {
            $country_code = 'DB Error: ' . $db->lastErrorMsg();
        } else {
            $stmt->bindValue(':ip', $ip_num, SQLITE3_INTEGER);
            $result = $stmt->execute();
            if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $country_code = $row['country_code'] ?: 'Unknown';
                $country_name = $row['country_name'] ?: 'Unknown';
                $continent_code = $row['continent_code'] ?: 'Unknown';
                $continent_name = $row['continent_name'] ?: 'Unknown';
                $asn = $row['asn'] ?: 'Unknown';
                $as_name = $row['as_name'] ?: 'Unknown';
                $as_domain = $row['as_domain'] ?: 'Unknown';
            }
        }
        $db->close();
    } catch (Exception $e) {
        $country_code = 'DB Error: ' . $e->getMessage();
    }
}

// Handle IP-only mode
if ($ip_only) {
    header('Content-Type: text/plain');
    echo "$client_ip";
    exit;
}

// Expected client X- headers (add any your app uses, lowercase)
$expected_x_headers = [
//    'x-requested-with', // Common for AJAX
//    'x-api-key', // Uncomment if your environment uses cloudflare or anything that expects X- style headers to avoid false positives. 
];

// Collect full request datas as well as all other datas
$data = [
    'generated' => date('Y-m-d H:i:s T'),
    'client_ip' => $client_ip,
    'country_code' => $country_code,
    'country_name' => $country_name,
    'continent_code' => $continent_code,
    'continent_name' => $continent_name,
    'asn' => $asn,
    'as_name' => $as_name,
    'as_domain' => $as_domain,
    'headers' => array_change_key_case(getallheaders(), CASE_LOWER),
    'server' => $_SERVER,
    'src_port' => htmlspecialchars($_SERVER['REMOTE_PORT'] ?? ''),
    'request' => $_REQUEST,
    'files' => $_FILES ?: 'None',
    'cookies' => $_COOKIE ?: 'None'
];

// Filter for X- headers
$additional_headers = [];
foreach ($data['headers'] as $k => $v) {
    if (str_starts_with($k, 'x-') && !in_array($k, $expected_x_headers)) {
        $additional_headers[$k] = $v;
    }
}

// Output as plain text
header('Content-Type: text/plain');
$echo = "::::::::::[ IP Echo ]::::::::::\n";
$echo .= "Client IP: " . $data['client_ip'] . "\n";
$echo .= "Client Port: " . $data['src_port'] . "\n";
$echo .= "Country Code: " . $data['country_code'] . "\n";
$echo .= "Country Name: " . $data['country_name'] . "\n";
//$echo .= "Continent Code: " . $data['continent_code'] . "\n";
$echo .= "Continent Name: " . $data['continent_name'] . "\n";
$echo .= "Hosting Company: " . $data['as_name'] . "\n";
$echo .= "Hosting Company Domain: " . $data['as_domain'] . "\n";
$echo .= "Hosting ASN: " . $data['asn'] . "\n\n";
$echo .= "Additional Headers (Possible Injections, X- Prefix):\n";
if (empty($additional_headers)) {
    $echo .= "None Detected\n";
} else {
    foreach ($additional_headers as $k => $v) {
        $echo .= "$k: $v\n";
    }
}
$echo .= "\nAdditional Unexpected Request Data?\n";
if (empty($data['request'])) {
    $echo .= "None Detected\n";
} else {
    foreach ($data['request'] as $k => $v) {
        $echo .= "$k: $v\n";
    }
}
$echo .= "\nInjected Uploaded Files?\n";
if ($data['files'] === 'None') {
    $echo .= "None Detected\n";
} else {
    $echo .= print_r($data['files'], true) . "\n";
}
$echo .= "\nInjected Cookies?\n";
if (empty($data['cookies'])) {
    $echo .= "None Detected\n";
} else {
    $echo .= print_r($data['cookies'], true) . "\n";
}
$echo .= "\nGenerated: " . $data['generated'] . " by an IP.URLS.IS node on PACKET.TEL Networks.\n";
$echo .= "For more information please visit https://packet.tel -=- ©MMXXV PACKET.TEL LLC\n";
echo $echo;
?>
