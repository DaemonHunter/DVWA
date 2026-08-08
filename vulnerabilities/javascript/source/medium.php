<?php

// Hardened: token is now generated server-side and stored in the session.
// The original medium level loaded medium.js which reversed a string client-side
// to build the token — trivially reversible by reading the source.
// The server now issues and validates the token; medium.js is not loaded.

if (session_status() == PHP_SESSION_NONE) {
	session_start();
}

$errors  = "";
$success = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$phrase = isset($_POST['phrase']) ? $_POST['phrase'] : '';
	$token  = isset($_POST['token'])  ? $_POST['token']  : '';

	// Validate against the server-side session token
	if (isset($_SESSION['js_medium_token']) && hash_equals($_SESSION['js_medium_token'], $token)) {
		if ($phrase === "success") {
			$success = "Well done!";
		} else {
			$errors = "Invalid phrase.";
		}
	} else {
		$errors = "Invalid token.";
	}
	// Regenerate token after each submission
	unset($_SESSION['js_medium_token']);
}

// Generate a fresh server-side token for this page load
$_SESSION['js_medium_token'] = bin2hex(random_bytes(32));

$page[ 'body' ] .= "
<p id='header'>What is the phrase?</p>
<form name='medium' method='POST'>
	<input type='hidden' name='token' id='token' value='" . htmlspecialchars($_SESSION['js_medium_token'], ENT_QUOTES, 'UTF-8') . "' />
	<label for='phrase'>Phrase:</label>
	<input type='text' name='phrase' id='phrase' />
	<input type='submit' id='send' value='Submit' />
</form>
";

if ($errors !== "") {
	$page[ 'body' ] .= '<div class="warning">' . htmlspecialchars($errors, ENT_QUOTES, 'UTF-8') . '</div>';
}
if ($success !== "") {
	$page[ 'body' ] .= '<div class="success">' . htmlspecialchars($success, ENT_QUOTES, 'UTF-8') . '</div>';
}
