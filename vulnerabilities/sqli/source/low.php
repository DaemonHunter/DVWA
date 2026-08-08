<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
	// Get input
	$id = $_REQUEST[ 'id' ];

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ?;");
			mysqli_stmt_bind_param($stmt, 'i', $id);
			mysqli_stmt_execute($stmt);
			mysqli_stmt_bind_result($stmt, $first, $last);

			// Get results
			while( mysqli_stmt_fetch($stmt) ) {
				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}

			mysqli_stmt_close($stmt);
			mysqli_close($GLOBALS["___mysqli_ston"]);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$stmt = $sqlite_db_connection->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id;");
			$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
			$results = $stmt->execute();

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db_connection->lastErrorMsg();
			}
			break;
	}
}

?>
