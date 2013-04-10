<?php
session_start();
if (isset($_SESSION['user'])) {
        header("Location: index.php");
        exit;
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/ 
xhtml1/DTD/xhtml1-transitional.dtd"> 
<html> 
<head>
<title>NoKey Test</title> 
<script src="js/nokey.js" type="text/javascript"></script>
<script src="js/jsbn/jsbn.js" type="text/javascript"></script>
<script src="js/jsbn/jsbn2.js" type="text/javascript"></script>
<script src="js/jsbn/prng4.js" type="text/javascript"></script>
<script src="js/jsbn/rng.js" type="text/javascript"></script>
<link rel='stylesheet' href='css/nokey.css' type='text/css' media='all' />

</head>
<!-- For best random results -->
<body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>

<div id="login">
<h2>No-Key Concept Test</h2>
<form name="loginform" id="loginform" method="post">
  <p>
    <label>Username<br />
      <input type="text" name="user" id="user_login" class="input" value="" size="20" tabindex="10" />
    </label>
  </p>
  <p>
    <label>Password<br />
      <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" tabindex="20" />
    </label>
  </p>
  <p class="submit">
    <input type="button" value="Log In" tabindex="100" onclick="safe_login()" />
  </p>
</form>
</div>

<div id="message">
username: <i>admin</i><br/>
password: <i>passw0rd</i>
</div>
<div id="login_error"></div>

</body> 
</html>

