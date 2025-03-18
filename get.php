<?php
# AJAX handler to get content for a specific key

if(!$_POST['keyhash'] && !$_GET['keyhash']) {
  http_response_code(400); // Bad Request
  echo "FAILED: No key defined.";
  exit;
}

$keyhash = preg_replace('[^0-9a-f]', '', $_POST['keyhash'] ? $_POST['keyhash'] : $_GET['keyhash']);

include 'config.php'; # get DB_PASSWORD
$mysql = @mysqli_connect("localhost", "jokkebk_cryptiki", DB_PASSWORD, "jokkebk_cryptiki");

$sql = "SELECT contenthash, content FROM pages WHERE keyhash = '$keyhash'";

$result = mysqli_query($mysql, $sql);

if(mysqli_num_rows($result) == 0) {
  $contenthash = '';
  $content = '';
} else {
  list($contenthash, $content) = mysqli_fetch_row($result);
  mysqli_query($mysql, "UPDATE pages SET accessed = NOW() WHERE keyhash = '$keyhash'"); # note when accessed
}

header("Access-Control-Allow-Origin: *");

if($_GET['raw'] == '1') {
  header('Content-type: text/plain');
  echo $content;
} else { // normal operation
  header('Content-type: application/json');
  echo json_encode(array('contenthash' => $contenthash, 'content' => $content));
}
?>
