<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$id = $_POST[ 'id' ];
	$id = intval($id);
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ?;");
			mysqli_stmt_bind_param($stmt, 'i', $id);
			mysqli_stmt_execute($stmt);
			mysqli_stmt_store_result($stmt);

			$exists = (mysqli_stmt_num_rows($stmt) > 0);

			mysqli_stmt_close($stmt);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$stmt = $sqlite_db_connection->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id;");
			$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
			try {
				$results = $stmt->execute();
				$row = $results->fetchArray();
				$exists = $row !== false;
			} catch(Exception $e) {
				$exists = false;
			}
			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}
}

?>
