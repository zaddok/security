
create table setting (
	site text,
	name text,
	value text,
	primary key ((site), name));

create table person (
	site text,
	uuid timeuuid,
	first_name text,
	last_name text,
	email text,
	password text,
	last_auth bigint,
	last_auth_ip text,
	created bigint,
	updated bigint,
	expiry bigint,
	primary key ((site), uuid)) ;

create index person_index1 on person (email) ;

create table request_token (
	uid text primary key,
	site text,
	person_uuid timeuuid,
	expiry bigint,
	type text,
	ip text,
	data text);

create table session_token (
	site text,
	uid text, person_uuid timeuuid,
	first_name text,
	last_name text,
	expiry bigint,
	roles text,
	created bigint,
	primary key ((site, uid)));

create table role (
	role text,
	resource text,
	uid text,
	person_uuid timeuuid,
	primary key(role, person_uuid, resource, uid));

update setting set value='true' where site='dev.theconservative.com.au' and name='self.signup';

update setting set value='' where site='dev.theconservative.com.au' and name='smtp.hostname';
update setting set value='' where site='dev.theconservative.com.au' and name='smtp.user';
update setting set value='' where site='dev.theconservative.com.au' and name='smtp.password';
update setting set value='587' where name='smtp.port';

update setting set value='' where site='dev.theconservative.com.au' and name='support_team.email';
update setting set value='' where site='dev.theconservative.com.au' and name='support_team.name';
