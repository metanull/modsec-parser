<?php

	namespace \metanull\security\modsecurity;
	
	/**
	  * @author Pascal Havelange
	  * Walk a ModSecurity Audit log serial file; parsing it. Each parsed entry can then be further processed by a
	  * custom method or function
	  * 
	  * WARNING, The size of the audit log shall not exceed PHP_INT_MAX bytes! (on 32 bit php, that means about 2GB)
	  *          An integer overflow may arrise on 64bits (file)systems when using the 32bit version of PHP! (As 
	  *          filesize can be greater than PHP_INT_MAX
	  */
	class AuditReader {
	
		/** @const SECTION_DELIMITER The regular expression used to detect AuditLog section markers */
		const SECTION_DELIMITER = '/^--([0-9a-z]{8})-([A-Z])--$/';
		
		/** @const READ_RETRY Number of times to retry in case of read error (such error can be caused by a concurrent
		 *         write operation on the file)
		 */
		const READ_RETRY = 3;	
		
		/**
		 * @const RETRY_AFTER Make a pause of RETRY_AFTER MICRO seconds before each attempts (NB: the duration is
		 *        doubled at the second attempts; tripled at the third and so on)...
		 */
		const RETRY_AFTER = 1000000;	
		
		/*
		 * @const LINE_SIZE Max line length for fgets operations
		 * !!WARNING!! 	Do not define this constant; 
		 *              In current version of PHP 7.0.3 it seems that fgets handles pretty well very long lines, though
		 *              the documentation does not clearly explain what is the default behavior when that parameter is
		 *              ommited:
		 *              (URL: http://be2.php.net/manual/en/function.fgets.php) states the following:
		 *              Until PHP 4.3.0, omitting it would assume 1024 as the line length. If the majority of the lines
		 *              in the file are all larger than 8KB, it is more resource efficient for your script to specify
		 *              the maximum line length.
		 * /
		 const LINE_SIZE = 8192;		// This line is commented out intentionally, read above comments!
		*/
		
		/**
		 * @const LINES_IN_HISTORY Number of lines to keep in the history (useful for debugging)
		 */
		const LINES_IN_HISTORY = 50;	// Number of lines to keep in the history (useful for debugging)
		
		/**
		 * @const ENTRIES_IN_HISTORY Number of entries to keep in the history (useful for debugging)
		 */
		const ENTRIES_IN_HISTORY = 1;	// Number of entries to keep in the history (useful for debugging)
		
		/**
		 * @const PROCESSED_ENTRIES_IN_HISTORY Number of processed entries to keep in the history (useful for debugging)
		 */
		const PROCESSED_ENTRIES_IN_HISTORY = 1;
		
		/**
		 * Configuration array
		 * @var array $config
		 * @see validateConfig
		 */
		private $config = [];
		
		/**
		 * File pointer to the AuditReader's log file
		 * @var resource $log_fp
		 */
		private $log_fp = null;
		
		/**
		 * Array that holds the status and progress of the operation
		 * history[] ::=
		 * 		integer history['lines']			Keeps track of the number of lines read from the log
		 * 		integer history['entries']			Keeps track of the number of records read from the log 
		 *                       	                (entries span over multiple lines)
		 * 		string[] history['last-lines']		Keeps the last self::LINES_IN_HISTORY lines read
		 * 		array[] history['last-entries']		Keeps the last self::ENTRIES_IN_HISTORY records read
		 *                                         	(It is updated before the processing: adding only "raw" data
		 *											to the resulting array)
		 * 		array[] history['last-processed-entries']	Keeps a copy of the the last self::ENTRIES_IN_HISTORY 
		 *											records that have been successfully processed 
		 *                                          (It is updated  AFTER the processing: adding a list of the 
		 *											sections to the result array)
		 *
		 * @var array $history (see above)
		 */
		private $history = [ 
			'lines' => 0, 
			'entries' => 0, 
			'last-lines' => [], 
			'last-entries' => [], 
			'last-processed-entries' => [] 
		];
		/**
		 * Array that holds the status and progress of the operation
		 * internals[] ::=
		 * 		integer internals['cursor']			Offset of the file pointer from the start of the log file (1)
		 * 		string internals['entry-id']		ModSecurity 'id' of the record currently being processed
		 * 		string internals['entry-section']	Current section being read (A, B, C, E, H, I, J, Z)
		 * 		array internals['entry-data']		Buffer for the content of the current section
		 * (1) An integer overflow may arrise on 64bits (file)systems when using the 32bit version of PHP! (As filesize
		 *     can grow bigger than PHP_INT_MAX
		 * @var array $internals (see above)
		 */
		private $internals = [ 
			'cursor' => null,
			'entry-id' => null, 
			'entry-section' => null, 
			'entry-data' => [], 
		];
		
		/**
		 * Holds the AuditProcess callback function that was registered by the constructor
		 * @var callable $callback
		 */
		private $callback = null;
		
		/**
		 * Initializes the AuditReader
		 * config[] ::=
		 * 		string config['copy-to']	Optional. If defined, the path to a folder where to store the decoded 
		 *									entries. Each file will consist of one single entry array, encoded 
		 *									using the serialize() function
		 * @param string $source			Path to the Audit Log
		 * @param callable $callback		A callback to process the entries read by the walk function 
		 *									bool function(array $entry)
		 * @param array $config 			Optional. An array containing the configuration items (see above)
		 * @throws Exception				AuditReader would throw an exception if the $source file does not exists
		 *									it can also throw an exception when the $config['copy-to'] option is set:
		 *									that would happen if $config['copy-to'] is not a valid folder or if it 
		 *									fails in creating that directory
		 * @see walk()
		 */
		public function __construct( string $source, callable $callback, array $config = null) {
			$this->config = $config;
			$this->callback = $callback;
			
			$this->validateConfig();
			$this->open();
		}
		
		/**
		 * Free up the resources (ie: close the file pointer)
		 */
		public function __destruct() {
			$this->close();
		}
		
		/**
		 * Returns the actual number of lines that have been processed since the beginning
		 * @return integer
		 */
		public function lines() {
			return $this->history['lines'];
		}
		
		/**
		 * Returns the actual number of entries that have been fully processed since the beginning
		 * @return integer
		 */
		public function entries() {
			return $this->history['entries'];
		}
		
		/**
		 * Returns and indexed array containing the last self::LINES_IN_HISTORY line(s) read from the Audit file
		 * @return array
		 */
		public function lastLines() {
			return $this->history['last-lines'];
		}
		
		/**
		 * Returns and indexed array containing the last self::ENTRIES_IN_HISTORY entry(ies) read from the Audit file
		 * These entries are NOT processed; therefor they simply contain the raw data extracted from the log
		 * In the event an exception would occure in walk(), the defect entry WOULD be present in this array
		 * @return array
		 * @see lastProcessedEntries()
		 * @see walk()
		 */
		public function lastEntries() {
			return $this->history['last-entries'];
		}
		
		/**
		 * Returns and indexed array containing the last self::ENTRIES_PROCESSED_IN_HISTORY entry(ies) read from the 
		 * Audit file. These entries have been completelly processed; therefore they contain the parsed data
		 * In the event an exception would occure in walk(), the defect entry WOULD NOT be present in this array
		 * @return array
		 * @see lastEntries()
		 * @see walk()
		 */
		public function lastProcessedEntries() {
			return $this->history['last-processed-entries'];
		}
		
		/**
		 * Returns the last position of the file cursor.
		 * It can be used to initiate or resume the read operation from a given point in the file
		 * @return integer
		 * @see walk
		 */
		public function cursor() {
			return $this->internals['cursor'];
		}
		
		/**
		 * Read the audit log file LINE BY LINE, until a complete log entry is decoded
		 * You may use the methods lines(), entries(), cursor() to obtain statistics of the read operation; as well as
		 * lastLines(), lastEntries(), lastProcessedEntries() for debugging purpose. 
		 * NOTE: In the event the walk function would start reading past the start marker of an entry; then this entry
		 * 		 be discarded.This is intentional, and useful, as it allows to resume reading after an exception by
		 *		 implicitly skipping the defact record.
		 * @throws Exception AuditReader would throw an exception if:
		 *		- it was not capable of parsing a given entry; 
		 *		  in such case, you may resume processing the log file, skipping the defect entry, by resuming walk()
		 *		  from the next byte after the last cursor position.
		 *		  ie: $reader->walk( $reader->cursor() + 1 );
		 *		- if the read operation would fail at least self::READ_RETRY times in a row
		 *		- if the seek operation would fail
		 *		- if a regular expression was producing an error 
		 * @return boolan	Returns TRUE if there is more to read, or false otherwise
		 * @see lastLines()
		 * @see lastEntries()
		 * @see lastPrecessedEntries()
		 * @see cursor()
		 */
		public function walk( int $offset = null ) {
			// If an offset is specified; first move the file cursor to the requestd position
			if( null !== $offset ) {
				$this->seek( $offset );
			}
			
			// Capture the current position in the file
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
					// BOM found, keep the current offset of 3 BYTES (the fread operation has moved the file pointer 
					// from 3 bytes already, no need to seek again!)
					$position = 3;
				}
			}

			// Read one line
			// A read error may arise when prossessing live log files. If ModSecurity writed into the file for writing,
			// then the read operation would faild. To overcome this issue walk() will attempt self::READ_RETRY times
			// before actually throwing an exception.
			// In addition the script will pause for several milliseconds before retrying to read from the file. The 
			// duration of the pause is equal to: (N * self::RETRY_AFTER), where N is the iteration number. In other
			// words, at first failure it would wait for 1 * self::RETRY_AFTER; 2 * self::RETRY_AFTER at the second,
			// and so on.
			$attempts = self::READ_RETRY;
			// Read retry loop (see the comment here before)
			while( true ) {
				$line = fgets( $this->log_fp );
				
				// Check if successfull
				if( false === $line ) {
					// Read failed, check if it can be retried
					if( $attempts > 0 ) {
						// echo "\n!!! READ OPERATION FAILED, RETRYING IN AN INSTANT...\n";
						
						// Close the file, as the file pointer is probably not valid anymore because of the error
						$this->close();
						// Pause the script
						usleep( self::RETRY_AFTER * (self::READ_RETRY - $attempts));
						// Open the file again; and scroll down to the latest position
						$this->open();
						$this->seek( $position );
						
						$attempts --;
						continue;
					}
					// If no more retries allowed, check if we have reached the bottom of the file
					if( null !== $this->internals['entry-id'] ) {
						throw new Exception( 'reached the end of the file while more data was still expected', 500 );
					}
					
					// Return false to show that the file has completelly been processed
					return false;
				} else {
					// Read successful, no need to retry
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
			
			// Initialize the variables for parsing the lines
			$current_line_entry_id = null;
			$current_line_entry_section = null;
			$preg_rc = preg_match( self::SECTION_DELIMITER, $line, $matches );
			if( false === $preg_rc ) {
				throw new Exception( 'failed to parse line through regular expression ['.SECTION_DELIMITER.']', 500 );
			} else
			if( 1 === $preg_rc ) {
				list( $dummy, $current_line_entry_id, $current_line_entry_section ) = $matches;
			}

			// Process the current line.
			// the processing is different depending on the current state (state ::= position in the entry record)
			if( null === $this->internals['entry-id'] ) {
				// No entry currently processed; looking for an 'A' section
				if( 'A' == $current_line_entry_section ) {
					// Encountered the sarting point of a new entry, store the file pointer position to enable resuming
					// on failure and increment the counter of entries
					$this->history['entries']++;
					$this->internals['cursor'] = $position;
					
					// Initialize the history record
					$this->internals['entry-id'] = $current_line_entry_id;
					$this->internals['entry-section'] = $current_line_entry_section;
					$this->internals['entry-data'][$current_line_entry_section] = '';
				} else {
					// Empty line, Nothing to do
				}
			} else {
				// Currently processing an entry; until the 'Z' section is found
				if( null !== $current_line_entry_section ) {
					// Check that the entry id in current line is the expected one
					if( null !== $current_line_entry_id && $current_line_entry_id != $this->internals['entry-id'] ) {
						throw new Exception( 
							'invalid sequence in log file, new entry id ['.$current_line_entry_id.'] encountered '.
							'before the end of the previous entry ['.$this->internals['entry-id'].']'
							, 500 
						);
					}
					if( 'Z' == $current_line_entry_section ) {
						// Reached the end of the current entry
						$entry = [
							'sequence' => $this->history['entries'], 
							'cursor' => $this->internals['cursor'], 
							'id' => $this->internals['entry-id'], 
							'sections' => $this->internals['entry-data']
						];
						
						// Flag out the fact that this entry is completely processed
						$this->internals['entry-id'] = null;
						$this->internals['entry-section'] = null;
						
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
						$this->internals['entry-section'] = $current_line_entry_section;
						$this->internals['entry-data'][$current_line_entry_section] = '';
					}
				} else {
					// This line contains only date for the current entry's section
					$this->internals['entry-data'][$this->internals['entry-section']] .= $line;
				}
			}
			
			// Continue with the next line (until the current entry is completelly processed)
			return $this->walk();
		}

		/**
		 * Open the Audit Log file.
		 * @throws Exception open() would throw an exception if the file open operation would result in an error
		 */
		private function open() {
			$this->log_fp = fopen( $this->config('source'), 'rb' );
			if( false === $this->log_fp ) {
				throw new Exception( 'audit log is not readable', 404 );
			}
		}
		
		/**
		 * Close the Audit Log file (if it was open already)
		 */
		private function close() {
			if( null !== $this->log_fp && is_resource( $this->log_fp ) ) {
				fclose( $this->log_fp );
				$this->log_fp = null;
			}
		}
		
		/**
		 * Move the file cursor to a specific position in the file
		 * @param integer $offset Offset (in bytes) from the beginning of the file
		 * @throws Exception seek() would throw an exception if the seek operation would result in an error
		 */
		private function seek( int $offset ) {
			if( -1 === fseek( $this->log_fp, $offset, SEEK_SET)) {
				throw new Exception( 'failed to seek to the requested position', 409 );
			}
		}
		
		/**
		 * Verifies the config array
		 * Look for expected options; and verify their validity
		 */
		private function validateConfig() {
			$log = $this->config( 'source' );
			if( null === $log ) {
				throw new Exception( '[config::source] is not defined', 409 );
			}
			
			if( null !== $this->config( 'copy-to' )) {
				$target = $this->config( 'copy-to' );
				if( !is_dir( $target ) ) {
					$rc = mkdir( $target, 0770, true );
					if( false === $rc ) {
						throw new Exception( 'failed to create the [config::copy-to] directory', 409 );
					}
				}
			}
		}
		
		/**
		 * Dump and entry into a file. That file is stored in the $this->config['copy-to'] folder
		 */
		private function copyTo( $entry ) {
			$target = $this->config['copy-to'];
			if( null === $target ) {
				// 'copy-to' is not set; skip the operation
			} else {
				$target .= '/' . $entry['id'];
				$fp = null;
				try {
					// Open the temporary file (overwriting any existing file hat has the same name)
					$fp = fopen( $target, 'wb' );
					if( false === $fp ) {
						throw new Exception( 'save-to destination is not writable', 500 );
					}
					if( false === fwrite( $fp, serialize( $entry )) ) {
						throw new Exception( 'save-to destination is not writable', 500 );
					}
				} finally {
					// Make sure to free the resources before leaving the function
					if( is_resource( $fp )) {
						fclose( $fp );
					}
				}
			}
		}
		
		/**
		 * Get or set the value of one cofiguration element. 
		 * @param string $element	Name of the element to get/set
		 * @param string $value		Optional. Value of the element to set. If that parameter is ommited (or NULL) then
		 *							a get is performed. If it is present, then a set is performed
		 * @return string For "get", the function will return the actual value of the element, or NULL if it does not 
		 *				  exist. For "set", it will return the previous value of the element, or NULL if it was not 
		 *				  already existing.
		 */
		private function config( $element, $value = null ) {
			$old_value = array_key_exists( $element, $this->config ) ? $this->config[$element] : null;
			if( null !== $value ) {
				$this->config[$element] = $value;
			}
			return $old_value;
		}
		
	}
	