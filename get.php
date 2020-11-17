<?php
# AJAX handler to get content for a specific key

if(!$_POST['keyhash'] && !$_GET['keyhash']) {
  echo "FAILED: No key defined.";
  exit;
}

$keyhash = preg_replace('[^0-9a-f]', '', $_POST['keyhash'] ? $_POST['keyhash'] : $_GET['keyhash']);

$mysql = @mysqli_connect("localhost", "jokkebk_cryptiki", "TqUFs!58PKYNarm", "jokkebk_cryptiki");

header('Content-type: application/json');

$sql = "SELECT contenthash, content FROM pages WHERE keyhash = '$keyhash'";

$result = mysqli_query($mysql, $sql);

if(mysqli_num_rows($result) == 0) {
  $contenthash = '';
  $content = '';
} else {
  list($contenthash, $content) = mysqli_fetch_row($result);
  mysqli_query("UPDATE pages SET accessed = NOW() WHERE keyhash = '$keyhash'"); # note when accessed
}

echo json_encode(array('contenthash' => $contenthash, 'content' => $content));
?>
