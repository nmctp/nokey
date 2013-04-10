<?php
session_start();
if (!isset($_SESSION['user'])) {
	header("Location: login.php");
	exit;
} else { 
?>
<html>
<head>
<title>Your application main page</title>
</head>
<body>
Your are authenticated as <strong>
<?php
echo $_SESSION['user']; }
?>
</strong></br>
<a href="logout.php">Logout</a>
</body>
</html>
