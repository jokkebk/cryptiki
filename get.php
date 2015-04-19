<?php
# AJAX handler to get content for a specific key

if(!$_POST['keyhash']) {
  echo "FAILED: No key defined.";
  exit;
}

$keyhash = ereg_replace('[^0-9a-f]', '', $_POST['keyhash']);

$mysql = @mysql_connect("localhost", "jokkebk_cryptiki", "7e303d42");

header('Content-type: application/json');

if(!$mysql || !@mysql_select_db("jokkebk_cryptiki", $mysql)) {
  echo '{"error": "Database error."}';
  exit;
}

$sql = "SELECT contenthash, content FROM pages WHERE keyhash = '$keyhash'";

$result = mysql_query($sql);

if(mysql_num_rows($result) == 0) {
  $contenthash = '';
  $content = '';
} else {
  list($contenthash, $content) = mysql_fetch_row($result);
  mysql_query("UPDATE pages SET accessed = NOW() WHERE keyhash = '$keyhash'"); # note when accessed
}

echo json_encode(array('contenthash' => $contenthash, 'content' => $content));
?>
