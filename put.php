<?php
# AJAX handler to set content for a specific key

if(!$_POST['keyhash'] || !$_POST['passhash'] || !$_POST['content']) {
  echo "FAILED: Missing arguments.";
  exit;
}

$keyhash = ereg_replace('[^0-9a-f]', '', $_POST['keyhash']);
$passhash = ereg_replace('[^0-9a-f]', '', $_POST['passhash']);
$contenthash = ereg_replace('[^0-9a-f]', '', $_POST['contenthash']);
$content = ereg_replace('[^0-9a-zA-Z\+/=]', '', $_POST['content']);

$MAXSIZE = 65536;

if(strlen($content) > $MAXSIZE) {
  echo "FAILED: Current maximum size for a page is $MAXSIZE bytes in encrypted form. Yours was " . strlen($content) . " bytes";
  exit;
}

$mysql = @mysql_connect("localhost", "jokkebk_cryptiki", "7e303d42");

if(!$mysql || !@mysql_select_db("jokkebk_cryptiki", $mysql)) {
  echo "FAILED: Database error.";
  exit;
}

$result = mysql_query("SELECT passhash, LENGTH(content) AS len FROM pages WHERE keyhash = '$keyhash'");
$row = mysql_fetch_row($result);

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

  if(!mysql_query("UPDATE pages SET content = '$content', contenthash = '$contenthash', modified = NOW() WHERE keyhash = '$keyhash' AND passhash = '$passhash'")) {
    echo "FAILED: Could not update the page.";
    exit;
  }

  echo "SUCCESS: " . strlen($content) . " bytes stored.";
} else {
  if(!mysql_query("INSERT INTO pages (keyhash, passhash, contenthash, content, modified) VALUES ('$keyhash', '$passhash', '$contenthash', '$content', NOW())")) {
    echo "FAILED: Could not save page.";
    exit;
  }

  echo "SUCCESS: Page created.";
}
?>
