<?php
$api_key = "demo-php-key-123456789";
$name = $_GET['name'];
$file_path = $_GET['file'];
$query = "SELECT * FROM users WHERE name = '" . $name . "'";
echo "<h1>Hello " . $name . "</h1>";
include($file_path);
?>
