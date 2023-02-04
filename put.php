<?php
# AJAX handler to set content for a specific key

if(!$_POST['keyhash'] || !$_POST['passhash'] || !$_POST['content']) {
  echo "FAILED: Missing arguments.";
  exit;
}

$keyhash = preg_replace('[^0-9a-f]', '', $_POST['keyhash']);
$passhash = preg_replace('[^0-9a-f]', '', $_POST['passhash']);
$contenthash = preg_replace('[^0-9a-f]', '', $_POST['contenthash']);
$content = preg_replace('[^0-9a-zA-Z\+/=]', '', $_POST['content']);

$MAXSIZE = 65536;

if(strlen($content) > $MAXSIZE) {
  echo "FAILED: Current maximum size for a page is $MAXSIZE bytes in encrypted form. Yours was " . strlen($content) . " bytes";
  exit;
}

$mysql = @mysqli_connect("localhost", "jokkebk_cryptiki", "TqUFs!58PKYNarm", "jokkebk_cryptiki");

$result = mysqli_query($mysql, "SELECT passhash, LENGTH(content) AS len FROM pages WHERE keyhash = '$keyhash'");
$row = mysqli_fetch_row($result);

if($row) {
  $oldlen = (int)$row[1];
  $newlen = strlen($content);

  if(7 * $oldlen > 10 * $newlen && $oldlen > 100) {
    echo "FAILED: New page over 30 % smaller than old content ($newlen vs. $oldlen).";
    exit;
  }

  if($row[0] != $passhash) {
    echo "FAILED: Invalid password.";
    exit;
  }

  if(!mysqli_query($mysql, "UPDATE pages SET content = '$content', contenthash = '$contenthash', modified = NOW() WHERE keyhash = '$keyhash' AND passhash = '$passhash'")) {
    echo "FAILED: Could not update the page.";
    exit;
  }

  echo "SUCCESS: " . strlen($content) . " bytes stored.";
} else {
  if(!mysqli_query($mysql, "INSERT INTO pages (keyhash, passhash, contenthash, content, modified, accessed) VALUES ('$keyhash', '$passhash', '$contenthash', '$content', NOW(), NOW())")) {
    echo "FAILED: Could not save page: " . $mysql->error;
    exit;
  }

  echo "SUCCESS: Page created.";
}
?>
