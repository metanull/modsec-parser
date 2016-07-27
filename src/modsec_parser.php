<?php
	/**
	 * @author Pascal Havelange
	 */

	 /**
	  * Walk a serial log file; parsing it. Each parsed entry can then be further processed by a custom method or function
	  */
	class modsecParser {
	
		const SECTION_DELIMITER = '/^--([0-9a-z]{8})-([A-Z])--$/';
		const READ_RETRY = 3;			// Number of times to retry in case of read error (can be caused by a concurrent write operation on the file)
		const RETRY_AFTER = 1000000;	// Make a pause of RETRY_AFTER MICRO seconds before each attempts (NB: the duration is doubled at the second attempts; tripled at the third and so on)...
		// const LINE_SIZE = 8192;		// DON'T use a LINE_SIZE in fgets operations; as it breaks for longer lines and would force to manually buffer the input
		const LINES_IN_HISTORY = 50;
		const ENTRIES_IN_HISTORY = 1;
		const PROCESSED_ENTRIES_IN_HISTORY = 1;
		
		private $config = [];
		private $log_fp = null;
		
		private $history = [ 'cursor' => null, 'lines' => 0, 'entries' => 0, 'entry-id' => null, 'entry-section' => null, 'entry-data' => [], 'last-lines' => [], 'last-entries' => [], 'last-processed-entries' => [] ];
		private $errors = [];
		public $callback = null;
		
		public function walk( int $offset = null ) {
			if( null !== $offset ) {
				$this->seek( $offset );
			}
			
			$position = ftell( $this->log_fp );
			if( false === $position ) {
				throw new Exception( 'failed to retrieve the file pointer position', 500 );
			}
			
			// Remove the Byte Order Mark if necessary
			if( 0 === $position ) {
				$first_three_bytes = fread( $this->log_fp, 3); 
				$bom = pack('H*','EFBBBF');
				if( 0 !== strcmp( $first_three_bytes, $bom )) {
    				// No BOM found, seeks back to the beginning of the file
					$this->seek( 0 );
				} else {
					// BOM found, keep the current offset of 3 BYTES (the fread operation has moved the file pointer from 3 bytes already, no need to seek again!)
					$position = 3;
				}
			}

			// Read one line (
			// fgets may file when the file is being written at the same time... try again
			$attempts = self::READ_RETRY;
			while( true ) {
				$line = fgets( $this->log_fp );
				if( false === $line ) {
					if( $attempts > 0 ) {
						echo "\n!!! READ OPERATION FAILED, RETRYING IN AN INSTANT...\n";
						$this->close();
						usleep( self::RETRY_AFTER * (self::READ_RETRY - $attempts));
						$this->open();
						$this->seek( $position );
						$attempts --;
						continue;
					}
					// More was expected?
					if( null !== $this->history['entry-id'] ) {
						throw new Exception( 'reached the end of the file while more data was still expected', 500 );
					}
					
					// Return false to show that the file has completelly been processed
					return false;
				} else {
					// Read successful
					break;
				}
			}

			// Store the last LINES_IN_HISTORY lines
			if (count($this->history['last-lines']) >= self::LINES_IN_HISTORY ) {
				array_shift( $this->history['last-lines'] );
			}
			array_push( $this->history['last-lines'], $line );
			
			// Count the number of lines processed;
			$this->history['lines']++;
			
			$current_line_entry_id = null;
			$current_line_entry_section = null;
			$preg_rc = preg_match( self::SECTION_DELIMITER, $line, $matches );
			if( false === $preg_rc ) {
				throw new Exception( 'failed to parse line through regular expression ['.SECTION_DELIMITER.']', 500 );
			} else
			if( 1 === $preg_rc ) {
				list( $dummy, $current_line_entry_id, $current_line_entry_section ) = $matches;
			}

			if( null === $this->history['entry-id'] ) {
				// No entry currently processed; looking for an 'A' section
				if( 'A' == $current_line_entry_section ) {
					// Encountered the sarting point of a new entry, store the file pointer position to enable resuming on failure and increment the counter of entries
					$this->history['entries']++;
					$this->history['cursor'] = $position;
					
					// Initialize the history record
					$this->history['entry-id'] = $current_line_entry_id;
					$this->history['entry-section'] = $current_line_entry_section;
					$this->history['entry-data'][$current_line_entry_section] = '';
				} else {
					// Empty line, Nothing to do
				}
			} else {
				// Currently processing an entry; until the 'Z' section is found
				if( null !== $current_line_entry_section ) {
					// Check that the entry id in current line is the expected one
					if( null !== $current_line_entry_id && $current_line_entry_id != $this->history['entry-id'] ) {
						throw new Exception( 'invalid sequence in log file, new entry id ['.$current_line_entry_id.'] encountered before the end of the previous entry ['.$this->history['entry-id'].']', 500 );
					}
					if( 'Z' == $current_line_entry_section ) {
						// Reached the end of the current entry
						$entry = ['sequence' => $this->history['entries'], 'cursor' => $this->history['cursor'], 'id' => $this->history['entry-id'], 'sections' => $this->history['entry-data']];
						
						// Flag out the fact that this entry is completely processed
						$this->history['entry-id'] = null;
						$this->history['entry-section'] = null;
						
						// Store the entry in a file (only if 'copy-to' is set in the config)
						$this->copyTo( $entry );
						
						// Keep the last entries in the history
						if (count($this->history['last-entries']) >= self::ENTRIES_IN_HISTORY ) {
							array_shift( $this->history['last-entries'] );
						}
						array_push( $this->history['last-entries'], $entry );

						// Calls the user defined callback for this entry
						$processed_entry = ($this->callback)( $entry );
						
						// Keep the last entries in the history
						if (count($this->history['last-processed-entries']) >= self::PROCESSED_ENTRIES_IN_HISTORY ) {
							array_shift( $this->history['last-processed-entries'] );
						}
						array_push( $this->history['last-processed-entries'], $processed_entry );
						
						// return true to indicate that there is more
						return true;
					} else {
						// Reached a new section of the current entry
						$this->history['entry-section'] = $current_line_entry_section;
						$this->history['entry-data'][$current_line_entry_section] = '';
					}
				} else {
					// This line contains only date for the current entry's section
					$this->history['entry-data'][$this->history['entry-section']] .= $line;
				}
			}
			
			// Continue with the next line (until the current entry is completelly processed)
			return $this->walk();
		}

		
		public function __construct( array $config, callable $callback ) {
			$this->config = $config;
			$this->callback = $callback;
			
			$this->validateConfig();
			$this->open();
		}
		
		public function __destruct() {
			$this->close();
		}
		
		private function open() {
			$this->log_fp = fopen( $this->config('source'), 'rb' );
			if( false === $this->log_fp ) {
				throw new Exception( 'audit log is not readable', 404 );
			}
		}
		private function close() {
			if( null !== $this->log_fp && is_resource( $this->log_fp ) ) {
				fclose( $this->log_fp );
				$this->log_fp = null;
			}
		}
		
		private function seek( int $offset ) {
			if( -1 === fseek( $this->log_fp, $offset, SEEK_SET)) {
				throw new Exception( 'failed to seek to the requested position', 409 );
			}
		}
		
		
		private function validateConfig() {
			$log = $this->config( 'source' );
			if( null === $log ) {
				throw new Exception( '[config::source] is not defined', 409 );
			}
			
			if( null !== $this->config( 'copy-to' )) {
				$target = $this->config( 'copy-to' );
				if( null === $target ) {
					throw new Exception( '[config::target] is not defined', 409 );
				}
			
				if( !is_dir( $target ) ) {
					$rc = mkdir( $target, 0770, true );
					if( false === $rc ) {
						throw new Exception( 'failed to create the [config::target] directory', 409 );
					}
				}
			}
		}
		
		private function copyTo( $entry ) {
			$target = $this->config['copy-to'];
			if( null === $target ) {
				// 'copy-to' is not set; skip the operation
				return;
			}
			$target .= '/' . $entry['id'];
			$fp = null;
			try {
				$fp = fopen( $target, 'wb' );
				if( false === $fp ) {
					throw new Exception( 'save-to destination is not writable', 500 );
				}
				if( false === fwrite( $fp, serialize( $entry )) ) {
					throw new Exception( 'save-to destination is not writable', 500 );
				}
			} finally {
				if( is_resource( $fp )) {
					fclose( $fp );
				}
			}
		}
		
		
		private function config( $element, $value = null ) {
			$old_value = array_key_exists( $element, $this->config ) ? $this->config[$element] : null;
			if( null !== $value ) {
				$this->config[$element] = $value;
			}
			return $old_value;
		}
		
		public function lines() {
			return $this->history['lines'];
		}
		public function lastLines() {
			return $this->history['last-lines'];
		}
		public function lastEntries() {
			return $this->history['last-entries'];
		}
		public function lastProcessedEntries() {
			return $this->history['last-processed-entries'];
		}
		public function entries() {
			return $this->history['entries'];
		}
		public function cursor() {
			return $this->history['cursor'];
		}
		public function errors() {
			return $this->errors;
		}
		
	}
	
	/**
	 * A dummy processor for log entries retrieved from modsecParser
	 * It will just dump some information about the entry on stdout
	 */
	class dummyProcessor {
		static function run( $entry ){
			// A
			preg_match('/^(\[.*\]) [^ ]+ ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+)$/', $entry['sections']['A'], $matches );
			list( $dummy, $date, $client, $client_port, $interface, $port ) = $matches;
			
			printf( '% 4d, % 9d, %s, % 15s, % 5d' . "\n", $entry['sequence'], $entry['cursor'], $entry['id'], $client, $port );
			
			// B
			$headers = explode( "\n", $entry['sections']['B'] );
			$request = array_shift( $headers );
			$host = null;
			$user_agent = null;
			foreach( $headers as $header ) {
				if( null === $host && 0 === strpos( $header, 'Host: ' )) {
					$host = $header;
				}
				if( null === $user_agent && 0 === strpos( $header, 'User-agent: ' )) {
					$user_agent = $header;
				}
			}
			
			echo "\t" . $request . "\n";
			if( null !== $host ) {
				echo "\t" . $host . "\n";
			}
			if( null !== $user_agent ) {
				echo "\t" . $user_agent . "\n";
			}
			
			// H
			$modsec_messages = [];
			$messages = explode( "\n", $entry['sections']['H'] );
			foreach( $messages as $message ) {
				$details = [];
				if( 0 === strpos( $message, 'Message: ' )) {
					$pos = strpos( $message, '. [file "' );
					$message_header = substr( $message, 0, $pos + 2 );
					$details[0] = $message_header;
					
					$message_body = substr( $message, $pos + 3, -1 );
					$body_parts = explode( '] [', $message_body );
					foreach( $body_parts as $part ) {
						$parts = explode( ' ', $part, 2 );
						$details[$parts[0]] = $parts[1];
					}
					$modsec_messages[] = $details;
					printf( "\t%8s, %6s, %s\n" /*\t  %s\n\t  %s\n"*/, $details['severity'], $details['id'], $details['msg'] /*, $details[0], $details['data'] */);
				}
			}
			
			echo "\n";
			return null;
		}
	}
	
	/**
	 * More refined processor for log entries retrieved from modsecParser
	 * So far it is capable of parsing correctly the A, B, F and H section of the auditlog; any other section will be stored "as-is"
	 * Despite the name; it is not capable yet of uploading to mysql (that is the next step)
	 * In fact a third class sould probably be added to perform the save operation; in the end there would therefore be 3 classes with very distinct responsibilities:
	 * The Walker (read the file); the Parser (process the output of the walker); the Store (sends output of the Parser to some persistent storage)
	 */
	class mysqlProcessor {
	
		private $host = 'p:localhost';
		private $port = 3306;
		private $database = 'modsec';
		private $user = null;
		private $password = null;
		
		private $my = null;
		
		public function __construct( string $user, string $password, string $database = null, string $host = null, integer $port = null ) {
			if( null !== $host ) {
				$this->host = $host;
			}
			if( null !== $port ) {
				$this->port = (int)$port;
			}
			if( null !== $database ) {
				$this->database = $database;
			}
			$this->user = $user;
			$this->password = $password;
		}
		
		public function __destruct() {
			if( null !== $this->my ) {
				$this->my->close();
			}
		}
		
		private function connect() {
			if( null !== $this->my ) {
				if( true === $this->my->ping() ) {
					return true;
				}
			}
			$this->my = new mysqli( $this->host, $this->user, $this->password, $this->database, $this->port );
			if( $this->my->connect_error ) {
				throw new Exception( $this->my->connect_errno . ' ' . $this->my->connect_error, 500 );
			}
			return true;
		}
		
		
		private function A( $segment, &$parsed ) {
			if( 1 === preg_match('/^\[(.*)\] ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+)$/', $segment, $matches ) ) {
				list( $dummy, $date, $token, $client, $client_port, $interface, $port ) = $matches;
				$parsed['DT'] = $date;
				$parsed['TOKEN'] = $token;
				$parsed['CLIENT_IP'] = $client;
				$parsed['CLIENT_PORT'] = (int)$client_port;
				$parsed['SERVER_IP'] = $interface;
				$parsed['SERVER_PORT'] = (int)$port;
			} else {
				throw new Exception( 'failed to parse A segment: ' . $parsed['A'] );
			}
		}
		
		private function B( $segment, &$parsed ) {
			// Split lines
			$headers = explode( "\n", $segment );
			
			// Process the first line 
			$request = array_shift( $headers );
			// Note: there has been cases were there was two(2) spaces between the "URL" and the "HTTP_VERSION" so the following expression
			// 	'@^([A-Z]+) ([^ ]+) (HTTP/[0-9\.]{3})$@'
			// had to be replaced by:
			// 	'@^([A-Z]+) ([^ ]+)[ ]+(HTTP/[0-9\.]{3})$@'
			if( 1 === preg_match('@^([A-Z]+) ([^ ]+)[ ]+(HTTP/[0-9\.]{3})$@', $request, $matches ) ) {
				list( $dummy, $req_method, $req_url, $req_httpversion ) = $matches;
				$parsed['REQUEST_METHOD'] = $req_method;
				$parsed['REQUEST_VERSION'] = $req_httpversion;
				if( false !== strpos( $req_url, '?' )) {
					if( 1 === preg_match( '/^([^\?]*)\?(.*)$/', $req_url, $matches )) {
						list( $dummy, $url, $query ) = $matches;
						$parsed['REQUEST_URL'] = $url;
						$parsed['REQUEST_QUERYSTRING'] = $query;
					} else {
						throw new Exception( 'failed to parse B segment\'s HTTP REQUEST URL: ' . $req_url );
					}
				} else {
					$parsed['REQUEST_URL'] = $req_url;
					$parsed['REQUEST_QUERYSTRING'] = null;
				}
			} else {
				// Malformed request
				$exploded = explode( ' ', $request, 3 );
				switch( count( $exploded ) ) {
					case 3: {
						$parsed['REQUEST_VERSION'] = substr($exploded[2],0,8);	// DB allows only 8 characters for this field
					} /* NO BREAK, this is intentional! */
					case 2: {
						if( false !== strpos( $exploded[1], '?' )) {
							$exploded_url = explode( '?', $exploded[1], 2 );
							$parsed['REQUEST_URL'] = $exploded_url[0];
							$parsed['REQUEST_QUERYSTRING'] = $exploded_url[1];
						} else {
							$parsed['REQUEST_URL'] = $exploded;
						}
					} /* NO BREAK, this is intentional! */
					case 1: {
						$parsed['REQUEST_METHOD'] = substr($exploded[0],0,32);	// DB allows only 32 characters for this field
					} /* NO BREAK, this is intentional! */
				}
				// throw new Exception( 'failed to parse B segment\'s HTTP REQUEST: ' . $request );
			}
			
			// Process the headers (from 2nd line to the end)
			$parsed['HEADERS'] = [];
			$parsed['COOKIES'] = [];
			foreach( $headers as $header ) {
				if( 0 === strlen( $header ) ) {
					// Exit at the first empty lines
					break;
				}
				if( 1 === preg_match( '/^([^:]+): (.*)$/', $header, $matches )) {
					list( $dummy, $header_name, $header_value ) = $matches;
					switch( strtolower($header_name) ) {
						case 'host': {
							$parsed['REQUEST_HOST'] =  $header_value;
						} break;
						case 'user-agent': {
							$parsed['REQUEST_USERAGENT'] =  $header_value;
						} break;
						case 'accept': {
							$parsed['REQUEST_ACCEPT'] =  $header_value;
						} break;
						case 'cookie': {
							// There are case where the header doesn't have a value (ie: "Cookie:")
							if( 1 === preg_match( '/^([^=]+)=([^ ;]+)?(.*)$/', $header_value, $cookie_matches )) {
								list( $dummy, $cookie_name, $cookie_value, $cookie_attributes ) = $cookie_matches;
								if( 'phpsessid' == strtolower( $cookie_name ) ) {
									$parsed['PHPSESSID'] = $cookie_value;
								}
								$parsed['COOKIES'][] = [ 'NAME' => $cookie_name, 'VALUE' => $cookie_value, 'ATTRIBUTES' => $cookie_attributes ];
							} else {
								if( 0 !== strlen( $header_value )) {
									throw new Exception( 'failed to parse B segment\'s COOKIE: ' . $header );
								}
							}
						} break;
					}
					$parsed['HEADERS'][] = ['NAME' => $header_name, 'VALUE' => $header_value];
				} else {
					throw new Exception( 'failed to parse B segment\'s HTTP REQUEST HEADER: ' . $header );
				}
			}
		}
		
		private function F( $segment, &$parsed ) {
			// Split lines
			$headers = explode( "\n", $segment );
			
			// Process the first line 
			$response = array_shift( $headers );
			if( 1 === preg_match('@^(HTTP/[0-9\.]{3}) ([0-9]{3}) (.*)$@', $response, $matches ) ) {
				list( $dummy, $resp_httpversion, $resp_httpstatus, $resp_httpmessage ) = $matches;
				$parsed['RESPONSE_VERSION'] = $resp_httpversion;
				$parsed['RESPONSE_STATUS'] = $resp_httpstatus;
				$parsed['RESPONSE_MESSAGE'] = $resp_httpmessage;
			} else {
				// If no response was sent (ie because of a malformed request)
				if( 0 === strlen( $response ) ) {
					$parsed['RESPONSE_VERSION'] = null;
					$parsed['RESPONSE_STATUS'] = null;
					$parsed['RESPONSE_MESSAGE'] = null;
				} else {
					throw new Exception( 'failed to parse F segment\'s HTTP RESPONSE: ' . $response );
				}
			}
			
			// Process the headers (from 2nd line to the end)
			$parsed['RESPONSE_HEADERS'] = [];
			$parsed['RESPONSE_COOKIES'] = [];
			foreach( $headers as $header ) {
				if( 0 === strlen( $header ) ) {
					// Exit at the first empty lines
					break;
				}
				if( 1 === preg_match( '/^([^:]+): (.*)$/', $header, $matches )) {
					list( $dummy, $header_name, $header_value ) = $matches;
					switch( strtolower($header_name) ) {
						case 'content-type': {
							$parsed['RESPONSE_CONTENTTYPE'] =  $header_value;
						} break;
						case 'content-length': {
							$parsed['RESPONSE_CONTENTLENGTH'] =  $header_value;
						} break;
						case 'set-cookie': {
							if( 1 === preg_match( '/^([^=]+)=([^ ;]+)(.*)$/', $header_value, $cookie_matches )) {
								list( $dummy, $cookie_name, $cookie_value, $cookie_attributes ) = $cookie_matches;
								if( 'phpsessid' == strtolower( $cookie_name ) ) {
									$parsed['SET_PHPSESSID'] = $cookie_value;
								}
								$parsed['RESPONSE_COOKIES'][] = [ 'NAME' => $cookie_name, 'VALUE' => $cookie_value, 'ATTRIBUTES' => $cookie_attributes ];
							} else {
								throw new Exception( 'failed to parse F segment\'s SET-COOKIE: ' . $header );
							}
						} break;
					}
					$parsed['RESPONSE_HEADERS'][] = ['NAME' => $header_name, 'VALUE' => $header_value];
				} else {
					throw new Exception( 'failed to parse F segment\'s HTTP RESPONSE HEADER: ' . $header );
				}
			}
		}
		
		private function H( $segment, &$parsed ) {
			// Split lines
			$audit_lines = explode( "\n", $segment );
			
			// Process the audit lines
			$parsed['MESSAGES'] = [];
			foreach( $audit_lines as $line ) {
				if( 0 === strpos( $line, 'Message: ' )) {
					$parsed_message = [];
					
					// Some "messages" lines are truncated; and do not pass the regular expression; if it happens, cut the line at the last valid occurence
					$preg_rc = preg_match( '/^Message: (.*)\.(( \[[a-z]+ "[^"]+"\])+)?$/', $line, $matches );
					if( 1 !== $preg_rc ) {
						$pos = strrpos( $line, "] [");
						if ($pos !== false) {
							$preg_rc = preg_match( '/^Message: (.*)\.(( \[[a-z]+ "[^"]+"\])+)?$/', substr( $line,0, $pos + 1), $matches );
						}
					}
					if( 1 === $preg_rc ) {
						list( $dummy, $message, $attributes, $last ) = $matches;
						$parsed_message['MESSAGE'] = $message;
						$parsed_message['TAGS'] = [];
						
						// Parse the extra attributes
						$split_attributes = preg_split( '/^ \[|\] \[|\]$/', $attributes );
						foreach( $split_attributes as $attrib ) {
							if( 0 === strlen( $attrib )) {
								continue;
							}
							if( 1 === preg_match( '/^([a-z]+) "(.*)"$/', $attrib, $attribute_matches )) {
								list( $dummy, $attrib_name, $attrib_value ) = $attribute_matches;
								switch( strtolower( $attrib_name ) ) {
									case 'file':
									case 'ver':
									case 'msg':
									case 'severity':
									case 'data': {
										$parsed_message[strtoupper($attrib_name)] = $attrib_value;
									} break;
									
									case 'id':
									case 'line':
									case 'maturity':
									case 'accuracy':
									case 'rev': {	// Unsure about "REV", is it always an integer?
										$parsed_message[strtoupper($attrib_name)] = (int)$attrib_value;
									} break;
									
									case 'tag' : {
										$parsed_message['TAGS'][] = $attrib_value;
									} break;
									
									default: {
										echo '>>>> ' . strtoupper( $attrib_name ) . ' ::= ' .  strtoupper( $attrib_value ) . "\n";
									} break;
								}
								
							} else {
								throw new Exception( 'failed to parse H segment\'s MESSAGE ATTRIBUTE: ' . $attrib );
							}
						}
						$parsed_message['ATTRIBUTES'] = $attributes;
						$parsed['MESSAGES'][] = $parsed_message;
					} else {
						// Some "messages" lines do not have any attributes
						if( 1 === preg_match( '/^Message: (.*)\.?[ ]*$/', $line, $matches ) ) {
							list( $dummy, $message ) = $matches;
							$parsed_message['MESSAGE'] = $message;
							$parsed['MESSAGES'][] = $parsed_message;
						} else {
							throw new Exception( 'failed to parse H segment\'s MESSAGE: ' . $line );
						}
					}
				}
			}
		}
		
		public function run( $entry ){
			printf( "%04d %09d %s >>> ", $entry['sequence'], $entry['cursor'], $entry['id'] );
			
			$parsed_entry = [
				'ID' => $entry['id'],
				'OFFSET' => $entry['cursor'],
			];
			$sections = array_keys( $entry['sections'] );
			foreach( $sections as $section ) {
				// Store the whole segment
				$parsed_entry[$section] = $entry['sections'][$section];
				
				// Parse supported segments
				if( method_exists( $this, $section ) ) {
					$this->$section( $entry['sections'][$section], $parsed_entry );
				}
			}
		
			echo $parsed_entry['DT'] . ' ';
			echo $parsed_entry['CLIENT_IP'] . ' ';
			echo $parsed_entry['REQUEST_HOST'] . ' ';
			echo $parsed_entry['SERVER_PORT'] . "\n";
			echo '< ' . $parsed_entry['RESPONSE_STATUS'] . ' ';
			echo $parsed_entry['RESPONSE_MESSAGE'] . "\n";
			echo '< ' . $parsed_entry['REQUEST_METHOD'] . ' ';
			echo $parsed_entry['REQUEST_URL'] . "\n";
			if( array_key_exists(REQUEST_QUERYSTRING, $parsed_entry) && !empty($parsed_entry['REQUEST_QUERYSTRING']) ) {
				echo '<    ' . $parsed_entry['REQUEST_QUERYSTRING'] . "\n";
			}
			foreach( $parsed_entry['MESSAGES'] as $message ) {
				if( array_key_exists( 'ID', $message )) {
					echo '>  ' . $message['ID'] . ' ' . $message['SEVERITY'] . ' ' . $message['MSG']. ' ' . $message['DATA'] . "\n";
				}
			}
			echo "\n";
			
			return $parsed_entry;
		}
	}


	
	define( 'HISTORY_LINE_SIZE', 320 );
	define( 'MAX_ENTRIES', 100000 );
	
	$source = 'c:/temp/modsec_audit.log';
	$offset = null;
	$config = null;
/*	$config = [
		'copy-to' => sys_get_temp_dir();	// Optional, to disable saving of entities in individual files, simply don't define that option
	];
*/
	$more = true;
	
	try {
		// What log file to read?
		if( count( $argv ) > 1 ) {
			$config['source'] = $argv[1];
		}
		// Start from an offset or from set?
		if( count( $argv ) > 2  && is_numeric( $argv[2] )) {
			$offset = (int)$argv[2];
		}		
		
		// Initialize the processor...
		$processor = new mysqlProcessor( 'modsec', 'M0dS3cUr!7y P@r5eR' );
		
		// ... and register it with the parser
		$parser = new AuditReader( $source, array($processor,'run' ), $config );
		
		// Walk down the log file and process it
		$more = $parser->walk( $offset );
		for( $i = 1; $more && ( $i < MAX_ENTRIES ); $i ++ ) {
			$more = $parser->walk();
		}
	} catch( Exception $e ) {
		// Dump some information about the last processed lines/entries
		
		// Last entries that have been processed
		$last_entries = $parser->lastProcessedEntries();
		$k_offset = $parser->entries() - count( $last_entries );
		echo "\nHistory (Processed entries):\n";
		foreach( $last_entries as $k => $prev_line ) {
			printf( '  > % 6d %s', $k_offset + $k, print_r( $last_entries, true ) );
		}
		
		// Last lines read from the Log file
		$last_lines = $parser->lastLines();
		$k_offset = $parser->lines() - count( $last_lines );
		echo "\nHistory (Lines):\n";
		foreach( $last_lines as $k => $prev_line ) {
			printf( '  > % 12d %s', $k_offset + $k, ((strlen($prev_line) > HISTORY_LINE_SIZE) ? (substr($prev_line,0,HISTORY_LINE_SIZE - 3)."...\n") : $prev_line  ));
		}
		
		// Last entries, as it was before processing (::= an array of the ModSecurity A,B,C,E,F,H,I,J... sections)
		$last_entries = $parser->lastEntries();
		$k_offset = $parser->entries() - count( $last_entries );
		echo "\nHistory (Entries):\n";
		foreach( $last_entries as $k => $prev_line ) {
			printf( '  > % 6d %s', $k_offset + $k, print_r( $last_entries, true ) );
		}
		
		// Re-throw the exception again
		throw( $e );
	} finally {
		// Print out some information about the last position in the file
		printf( "\n" . 'DONE(%s); Status: [lines "%d"] [entries "%d"] [cursor "%d"]' . "\n", ($more ? 'PARTIAL' : 'COMPLETE'), $parser->lines(), $parser->entries(), $parser->cursor() );
		echo "\n";
	}
