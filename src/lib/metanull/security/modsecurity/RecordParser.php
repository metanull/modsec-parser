<?php

	namespace \metanull\security\modsecurity;
	
	// http://phpenthusiast.com/object-oriented-php-tutorials/type-hinting
	// http://phpenthusiast.com/object-oriented-php-tutorials/type-hinting-for-interfaces
	
	interface RecordParser {
	
		public function parse( array $entry );
		
	}