<?php

require('nokey-config.php');
require('your_app.php');

$step = $_POST['step'];
if($step == 1){
	// The server provides de client with the modulus 'p'
	$cmd_ret = shell_exec(NO_KEY_SERVER);
	list ($tmp_dir, $p) = explode(" ", $cmd_ret);
	$step1_response = array ('tmpdir'=>$tmp_dir,'p'=>$p);
	echo json_encode($step1_response); // PHP >= 5.2.0
} elseif ($step == 2){
	// The server chooses another random unit 'u2' modulo 'p-1' and
	// computes 'q2 = q1^u2 mod(p)', sending this back to the client
	$tmp_dir = $_POST['tmpdir'];
	$q1 = $_POST['q1'];
	$cmd = NO_KEY_SERVER . " " . $tmp_dir . " " . $q1;
	$cmd_esc = escapeshellcmd($cmd);
	$cmd_ret = shell_exec($cmd_esc);
	list ($tmp_dir, $q2) = explode(" ", $cmd_ret);
	$q2 = str_replace("\n\n","",$q2);
	$step2_response = array ('tmpdir'=>$tmp_dir,'q2'=>$q2);
	echo json_encode($step2_response);
} elseif ($step == 3){
	// Finally, the server computes 'v2 = 1/u2 mod(p-1)' and
	// 'q4 = q3^v2 mod(p)'. By Fermat's little theorem, one has
	// 'q4 = k mod(p)', and the server can now verify the password
	// again its database
	$user = $_POST['user'];
	$tmp_dir = $_POST['tmpdir'];
	$q3 = $_POST['q3'];
	$end = $_POST['end'];
	$cmd = NO_KEY_SERVER . " " . $tmp_dir . " " . $q3 . " " . $end;
	$cmd_esc = escapeshellcmd($cmd);
	$password = shell_exec($cmd_esc);
	$valid_user = user_authentication($user, $password);
	$step3_response = array();
	if ( $valid_user == true) {
		$step3_response['valid_user'] = 1;
	} else {
		$step3_response['valid_user'] = 0;
	}
	echo json_encode($step3_response);
} else {
	echo "ERROR: step no specified or bad number";
}

?>
