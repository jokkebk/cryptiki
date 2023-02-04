<?php
# AJAX handler to get content for a specific key

if(!$_GET['keyhash']) {
  echo "FAILED: No key defined.";
  exit;
}

$keyhash = preg_replace('[^0-9a-f]', '', $_GET['keyhash']);

$mysql = @mysqli_connect("localhost", "jokkebk_cryptiki", "TqUFs!58PKYNarm", "jokkebk_cryptiki");

$sql = "SELECT contenthash, content FROM pages WHERE keyhash = '$keyhash'";

$result = mysqli_query($mysql, $sql);

if(mysqli_num_rows($result) == 0) {
  echo "FAILED: Content not found.";
  exit;
}

list($contenthash, $content) = mysqli_fetch_row($result);
mysqli_query("UPDATE pages SET accessed = NOW() WHERE keyhash = '$keyhash'"); # note when accessed

header('Content-disposition: attachment; filename=cryptiki_backup.html');
header('Content-type: text/html');
?>

<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Cryptiki local backup</title>
  </head>
  <body>

      <p>This is a backup downloaded from Cryptiki.com containing AES256
      encrypted data using Chris Vaness' Javascript library. Enter your
      password to decrypt the contents to text box below.</p>

      <textarea id="content" cols="80" rows="25"></textarea>
        <script>
<?php
echo file_get_contents('media/js/aes256.js');
?>
        </script>
        <script>
        const data = '<?= $content ?>';
        const password = prompt('Enter your password');

        content = AESDecryptCtr(data, password, 256);
        // content SHA-256 should be <?= $contenthash ?>
        
        const textarea = document.getElementById('content');
        textarea.value = content;
        </script>
  </body>
</html>