<?php
# AJAX handler to set content for a specific key
header("Access-Control-Allow-Origin: *");

if(!$_POST['keyhash'] || !$_POST['passhash'] || !$_POST['content']) {
  http_response_code(400); // Bad Request
  echo "FAILED: Missing arguments.";
  exit;
}

$keyhash = preg_replace('[^0-9a-f]', '', $_POST['keyhash']);
$passhash = preg_replace('[^0-9a-f]', '', $_POST['passhash']);
$contenthash = preg_replace('[^0-9a-f]', '', $_POST['contenthash']);
$content = preg_replace('[^0-9a-zA-Z\+/=]', '', $_POST['content']);

$MAXSIZE = 65536*2;

if(strlen($content) > $MAXSIZE) {
  http_response_code(413); // Payload Too Large
  echo "FAILED: Current maximum size for a page is $MAXSIZE bytes in encrypted form. Yours was " . strlen($content) . " bytes";
  exit;
}

include 'config.php'; # get DB_PASSWORD
$mysql = @mysqli_connect("localhost", "jokkebk_cryptiki", DB_PASSWORD, "jokkebk_cryptiki");

$result = mysqli_query($mysql, "SELECT passhash, LENGTH(content) AS len FROM pages WHERE keyhash = '$keyhash'");
$row = mysqli_fetch_row($result);

if($row) {
  $oldlen = (int)$row[1];
  $newlen = strlen($content);

  if(7 * $oldlen > 10 * $newlen && $oldlen > 100) {
    http_response_code(400); // Bad Request
    echo "FAILED: New page over 30 % smaller than old content ($newlen vs. $oldlen).";
    exit;
  }

  if($row[0] != $passhash) {
    http_response_code(403); // Forbidden
    echo "FAILED: Invalid password.";
    exit;
  }

  if(!mysqli_query($mysql, "UPDATE pages SET content = '$content', contenthash = '$contenthash', modified = NOW() WHERE keyhash = '$keyhash' AND passhash = '$passhash'")) {
    http_response_code(500); // Internal Server Error
    echo "FAILED: Could not update the page: " . $mysql->error;
    exit;
  }

  http_response_code(200); // OK
  echo "SUCCESS: " . strlen($content) . " bytes stored.";
} else {
  if(!mysqli_query($mysql, "INSERT INTO pages (keyhash, passhash, contenthash, content, modified, accessed) VALUES ('$keyhash', '$passhash', '$contenthash', '$content', NOW(), NOW())")) {
    http_response_code(500); // Internal Server Error
    echo "FAILED: Could not save page: " . $mysql->error;
    exit;
  }

  http_response_code(201); // Created
  echo "SUCCESS: Page created.";
}
?>
