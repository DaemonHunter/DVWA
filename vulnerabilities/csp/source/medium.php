<?php

// Hardened: removed 'unsafe-inline' and the static (hardcoded) nonce.
// A static nonce is equivalent to no nonce — an attacker who reads the source
// can reuse it. CSP is now restricted to 'self' only, mirroring impossible.php.

$headerCSP = "Content-Security-Policy: script-src 'self';";

header($headerCSP);

?>
<?php
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>The Content Security Policy for this page only permits scripts loaded from the same origin. Inline scripts and external sources are blocked.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Submit" />
</form>
';
if (isset ($_POST['include'])) {
	$page[ 'body' ] .= "<p>Submitted value: " . htmlspecialchars ($_POST['include'], ENT_QUOTES, 'UTF-8') . "</p>\n";
}
