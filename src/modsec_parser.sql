drop database modsec;
create database modsec;
use modsec;

-- create user modsec@localhost;
-- set password for modsec@localhost = password('M0dS3cUr!7y P@r5eR');
-- grant select, insert, update, delete on modsec.* to modsec@localhost;
-- flush privileges;


create table ENTRY (
	`ID` char(8) primary key,
	`OFFSET` int unsigned,
	`DT` datetime,
	`TOKEN` char(24),
	`CLIENT_IP` varchar(15),
	`CLIENT_PORT` int unsigned,
	`SERVER_IP` varchar(15),
	`SERVER_PORT` int unsigned,
	`REQUEST_METHOD` varchar(32),
	`REQUEST_VERSION` char(8),
	`REQUEST_URL` varchar(256),
	`REQUEST_QUERYSTRING` text,
	`REQUEST_HOST` varchar(256),
	`REQUEST_USERAGENT` varchar(512),
	`REQUEST_ACCEPT` varchar(512),
	`RESPONSE_VERSION` char(8),
	`RESPONSE_STATUS` char(3),
	`RESPONSE_MESSAGE` varchar(512),
	`RESPONSE_CONTENTTYPE` varchar(512),
	`RESPONSE_CONTENTLENGTH` int unsigned,
	`PHPSESSID` varchar(128),
	`SET_PHPSESSID` varchar(128),
	index `entry_offset` (`offset`),
	index `entry_date` (`dt`),
	index `entry_token` (`token`),
	index `entry_client_ip` (`client_ip`),
	index `entry_server` (`server_ip`,`server_port`),
	index `entry_request_method` (`request_method`(5)),
	index `entry_request_version` (`request_version`),
	index `entry_request_url` (`request_url`),
	index `entry_request_host` (`request_host`),
	index `entry_request_useragent` (`request_useragent`),
	index `entry_response_version` (`response_version`),
	index `entry_response_status` (`response_status`),
	index `entry_response_message` (`response_message`(64)),
	index `entry_phpsessid` (`phpsessid`)
) engine innodb default charset utf8;

create table HEADER (
	`ENTRY_ID` char(8),
	`NAME` varchar(128),
	`VALUE` text,
	constraint `fk_header_entry` foreign key (`ENTRY_ID`) references `ENTRY` (`ID`) on update cascade on delete cascade,
	index `header_name` (`name`)
) engine innodb default charset utf8;

create table RESPONSE_HEADER (
	`ENTRY_ID` char(8),
	`NAME` varchar(128),
	`VALUE` text,
	constraint `fk_response_header_entry` foreign key (`ENTRY_ID`) references `ENTRY` (`ID`) on update cascade on delete cascade,
	index `response_header_name` (`name`)
) engine innodb default charset utf8;

create table COOKIE (
	`ENTRY_ID` char(8),
	`NAME` varchar(128),
	`VALUE` text,
	constraint `fk_cookie_entry` foreign key (`ENTRY_ID`) references `ENTRY` (`ID`) on update cascade on delete cascade,
	index `cookie_name` (`name`)
) engine innodb default charset utf8;

create table RESPONSE_COOKIE (
	`ENTRY_ID` char(8),
	`NAME` varchar(128),
	`VALUE` text,
	`ATTRIBUTES` text,
	constraint `fk_response_cookie_entry` foreign key (`ENTRY_ID`) references `ENTRY` (`ID`) on update cascade on delete cascade,
	index `response_cookie_name` (`name`)
) engine innodb default charset utf8;

create table SEGMENT (
	`ENTRY_ID` char(8),
	`ID` char(1),
	`DATA` text,
	primary key (`entry_id`, `id`),
	constraint `fk_segment_entry` foreign key (`ENTRY_ID`) references `ENTRY` (`ID`) on update cascade on delete cascade
) engine innodb default charset utf8;

create table MESSAGE (
	`ENTRY_ID` char(8),
	`ID` char(6),
	`MESSAGE` text,
	`FILE` varchar(512),
	`LINE` int unsigned,
	`REV` int unsigned,
	`VER` varchar(64),
	`MSG` varchar(1024),
	`DATA` varchar(1024),
	`SEVERITY` tinyint unsigned,
	`MATURITY` tinyint unsigned,
	`ACCURACY` tinyint unsigned,
	`ATTRIBUTES` text,
	primary key (`entry_id`, `id`),
	constraint `fk_message_entry` foreign key (`ENTRY_ID`) references `ENTRY` (`ID`) on update cascade on delete cascade,
	index `message_id` (`id`),
	index `message_message` (`message`(128)),
	index `message_msg` (`msg`(128)),
	index `message_data` (`data`(128)),
	index `message_file` (`file`),
	index `message_line` (`line`)
) engine innodb default charset utf8;

create table TAG (
	`MESSAGE_ENTRY_ID` char(8),
	`MESSAGE_ID` char(6),
	`TAG` varchar(256),
	primary key (`message_entry_id`, `message_id`, `tag`),
	constraint `fk_tag_message` foreign key (`MESSAGE_ENTRY_ID`,`MESSAGE_ID`) references `MESSAGE` (`ENTRY_ID`,`ID`) on update cascade on delete cascade,
	index `tag_tag` (`tag`)
) engine innodb default charset utf8;