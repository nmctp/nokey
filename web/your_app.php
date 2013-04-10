<?php

define("USER","admin"); //Demo user
define("PASSWORD","passw0rd"); //Demo password

function user_authentication ($user, $password){
	if (($user == USER) && ($password == PASSWORD)) {
		session_start();
		$_SESSION['user'] = USER;
    		return true;
	} else {
		return false;	
	}
}

?>
