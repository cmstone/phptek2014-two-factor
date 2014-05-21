<?php
include 'TwoFactor.php';
include 'Base32.php';

if (empty($_GET['secret']) || empty($_GET['username'])) {
    die ('Please specify a secret key and username');
}

$timestamp = TwoFactor::getTimestamp();
$secretKey = Base32::decode($_GET['secret']);                       // Decode it into binary
$currentPassword = TwoFactor::getSecret($secretKey, $timestamp);    // Get current token

if (!empty($_POST['key'])) {
    $result = TwoFactor::verifyKey($_GET['secret'], $_POST['key']);
    if ($result) {
        echo 'The secret code has been verified.';
    } else {
        echo 'INVALID Secret Code';
    }
}
?>
<form method="post">
    <table>
        <tr>
            <td>Username:</td>
            <td><?= $_GET['username']; ?></td>
        </tr>
        <tr>
            <td>Secret Code:</td>
            <td><input type="text" name="key" id="key" value="<?= $_GET['key']; ?>" />&nbsp;<input type="submit" name="submit" id="submit" />
            </td>
        </tr>
    </table>
</form>