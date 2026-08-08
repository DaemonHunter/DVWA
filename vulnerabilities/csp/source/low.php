<?php

// Hardened: CSP restricted to 'self' only (no external CDN domains, no JSONP endpoints).
// Unsanitized user-controlled <script src> injection removed; input is now echoed safely.

$headerCSP = "Content-Security-Policy: script-src 'self';";

header($headerCSP);

?>
<?php
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>The Content Security Policy for this page only permits scripts loaded from the same origin.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Submit" />
</form>
';
if (isset ($_POST['include'])) {
	$page[ 'body' ] .= "<p>Submitted value: " . htmlspecialchars ($_POST['include'], ENT_QUOTES, 'UTF-8') . "</p>\n";
}
