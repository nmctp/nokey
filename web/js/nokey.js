var READY_STATE_COMPLETE=4;

var http_request = null;
var fname = null;
var p = null;
var no_key_len = null;
var p_1 = null;
var u1 = null;
var q1 = null;

var href = location.href;
var url = href.replace(/^((http[s]?):\/)?\/?([^:\/\s]+)((\/\w+)*\/)([\w\-\.]+[^#?\s]+)(.*)?(#[\w\-]+)?$/,"$2://$3$4");
var nokey_url = url + "nokey.php";

// Converts a string to hexadecimal
function str2hex(str){
    var r="";
    var e=str.length;
    var c=0;
    var h;
    while(c<e){
        h=str.charCodeAt(c++).toString(16);
        while(h.length<2) h="0"+h;
        r+=h;
    }
    return r;
}

// Creates an XMLHttpRequest object
function init_xhr() {
    if(window.XMLHttpRequest) {
	return new XMLHttpRequest();
    }
    else if(window.ActiveXObject) {
	return new ActiveXObject("Microsoft.XMLHTTP");
    }
}

// Client-side of Shamir's No Key protocol
function safe_login() {
    http_request = init_xhr();
    if(http_request) {
	http_request.onreadystatechange = step_1;
	http_request.open("POST", nokey_url, true);
	http_request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	var query_string = "step=1&nocache=" + Math.random(); // the 'nocache' param is used to avoid 
							      // the browser cache and to force it
							      // to request to the server
	http_request.send(query_string);
    } else {
	alert("XMLHttpRequest Error");
    }
}

// Choose a random number 'u1' which is a unit modulo 'p-1' and
// compute 'q1 = k^u1 mod(p)'. Then send 'q1' to the server.
function step_1() {
    if(http_request.readyState == READY_STATE_COMPLETE) {
	if(http_request.status == 200) {

	    // The server provides the tmpdir and the modulus 'p'
	    var json_response = http_request.responseText;
	    var json_object = eval("("+json_response+")");
	    fname = json_object.tmpdir;
	    p = json_object.p;
	    no_key_len = p.length * 4; // p bit-length
	    p = new BigInteger(p,16);

	    // u1 will be a random number between 0 and p-1
	    var rng = new SecureRandom();
	    var no_key_len_bytes = no_key_len/8;
	    var x = new Array(no_key_len_bytes);
	    rng.nextBytes(x);
	    u1 = new BigInteger(x);
	    p_1 = p.subtract(BigInteger.ONE);
 	    u1 = u1.mod(p_1);

 	    // make certain that u1 y p-1 are
 	    var gcd = u1.gcd(p_1);
	    var gcds = gcd.toString(16);
 	    while (gcds != "1"){
 	    	u1 = u1.add(BigInteger.ONE);
 	    	gcd = u1.gcd(p_1);
		gcds = gcd.toString(16);
 	    }

 	    // Convert the 'plain-key' to hex
	    var pass = document.getElementById("user_pass").value;
 	    pass = str2hex(pass);
 	    var K = new BigInteger(pass,16);

 	    // q1 = K^u1 mod(p)
	    q1 = K.modPow(u1,p);
	   
	    // Go to step_2
	    http_request = init_xhr();
 	    if(http_request) {
 		http_request.onreadystatechange = step_2;
 		http_request.open("POST", nokey_url, true);
 		http_request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
 		var query_string = "step=2&tmpdir=" + fname + "&q1=" + q1.toString(16) + "&nocache=" + Math.random();
 		http_request.send(query_string);
 	    } else {
 		alert("XMLHttpRequest Error");
 	    }

	}
    }
}

// Computes 'v1 = 1/u1 mod(p-1)' and send 'q3 = q2^v1 mod(p)'
// back to the server
function step_2(){
    if(http_request.readyState == READY_STATE_COMPLETE) {
	if(http_request.status == 200) {
	
	    // Receive tmpdir y q2
	    var json_response = http_request.responseText;
	    var json_object = eval("("+json_response+")");
	    fname = json_object.tmpdir;
	    var q2 = json_object.q2;
	    q2 = new BigInteger(q2,16);

            // Compute v1 and send q3
	    var v1 = u1.modInverse(p_1);
	    var q3 = q2.modPow(v1,p);

	    // get username
	    var user = document.getElementById("user_login").value;

	    // Go to step_3
	    http_request = init_xhr();
 	    if(http_request) {
 		http_request.onreadystatechange = step_3;
 		http_request.open("POST", nokey_url, true);
 		http_request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
 		var query_string = "step=3&user=" + user + "&tmpdir=" + fname + "&q3=" + q3.toString(16) + "&end=1&nocache=" + Math.random();
 		http_request.send(query_string);
 	   } else {
 		alert("XMLHttpRequest Error");
 	    }
	}
    }
}

// Check if username and password are valid and redirect to
// the index page (if valid) or show a error message (otherwise)
function step_3(){
    if(http_request.readyState == READY_STATE_COMPLETE) {
	if(http_request.status == 200) {

	    // Receive key in plain text
	    var json_response = http_request.responseText;
	    var json_object = eval("("+json_response+")");
	    var valid_user = json_object.valid_user;

	    if(valid_user == 1){
		// Valid username and password
		location.href="index.php"
	    } else {
		// Invalid username and password
		document.getElementById("login_error").style.visibility = "visible";
		document.getElementById("login_error").innerHTML = "<strong>ERROR: </strong>Invalid username or password";
	    }
	}
    }
}

