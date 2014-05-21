<?php
include 'TwoFactor.php';
include 'Base32.php';

$username = 'chris@baltimorephp.org';
$userkey = TwoFactor::generateKey();
$timestamp = TwoFactor::getTimestamp();

$secretKey = Base32::decode($userkey);                              // Decode it into binary
$currentPassword = TwoFactor::getSecret($secretKey, $timestamp);    // Get current secret
?>
<table>
    <tr>
        <td>Initialization Key:</td>
        <td><?= $userkey; ?></td>
    </tr>
    <tr>
        <td>Timestamp:</td>
        <td><?= $timestamp; ?></td>
    </tr>
    <tr>
        <td>Current Password:</td>
        <td><?= $currentPassword; ?></td>
    </tr>
    <tr>
        <td>Username:</td>
        <td><?= $username; ?> - <a href="/login.php?secret=<?= $userkey; ?>&username=<?= $username; ?>">Test Login</a>
        </td>
    </tr>
</table>

<?= TwoFactor::getQrCode($username, $userkey); ?>