package Oak::AAS::Service::DBI;

use base qw(Oak::AAS::Service);
use Oak::IO::DBI;
use Error qw(:try);
use strict;

sub constructor {
	my $self = shift;
	my $params=shift;
	my @kvs=split(m/;/, $params);
	foreach my $kv (@kvs) {
		my ($k,$v)=split(/=/,$kv);
		$self->{params}{$k}=$v;
	}
	$self->{params}{session_timeout}=3600;
	my $datasource="dbi:".$self->{params}{dbdriver}.":dbname=".$self->{params}{database}.";host=".$self->{params}{hostname};

	$self->{dbi}=new Oak::IO::DBI(
			RESTORE => {
				name=>"VESPRO_SERVICE_IO_DBI",
				datasource=>$datasource,
				username=>'mosca',
				password=>'rosss'
			}
		);
}

=over

=item start_session(user,password)

Must start the session and return a unique id or false.

=back

=cut

sub start_session {
	my $self = shift;
	my $user = shift;
	my $password = shift;
	require Digest::MD5;
	my %tableNames = $self->_getTableNames();
	my $sth = $self->{dbi}->do_sql("SELECT * FROM $tableNames{tableName} WHERE $tableNames{loginField}=".$self->{dbi}->quote($user)." AND $tableNames{passwdField}=".$self->{dbi}->quote(Digest::MD5::md5_hex($password)));
	return undef if $sth->rows < 1;

	$sth=$self->{dbi}->do_sql("DELETE FROM aas_session WHERE login=".$self->{dbi}->quote($user));
	my $id=time.$$.int(rand(4096));

	my $ip=$self->{dbi}->quote(($ENV{HTTP_X_FORWARDED_FOR}||$ENV{REMOTE_ADDR}));
	$sth=$self->{dbi}->do_sql("INSERT INTO aas_session (login,id,last_access,ip) VALUES (".$self->{dbi}->quote($user).",".$self->{dbi}->quote($id).",".time.",$ip)");
	return undef if !$sth->rows;

	return $id;
}

=over

=item _getTableNames()

Must be rewrited or the table will be "Usuario" for default.

=back

=cut

sub _getTableNames() {
	return (tableName => "Usuario" ,  loginField => "login", passwdField => "senha");
}

=over

=item validate_session(user,sessionid)

Check if this is a valid session, return a boolean value (1=>success).

=back

=cut

sub validate_session {
	my $self = shift;
	my $user=shift;
	my $sid=shift;
	my $ip=$ENV{HTTP_X_FORWARDED_FOR}||$ENV{REMOTE_ADDR};
	my $sql="SELECT * FROM aas_session WHERE id=".$self->{dbi}->quote($sid);
	$sql.=" AND login=".$self->{dbi}->quote($user);
	$sql.=" AND ip=".$self->{dbi}->quote($ip);

	if($self->{params}{session_timeout}) {
		$sql.=" AND last_access>".(time-$self->{params}{session_timeout});
	}
	my $sth=$self->{dbi}->do_sql($sql);

	if($sth->rows) {
		$sql="UPDATE aas_session SET last_access=".time." WHERE id=".$self->{dbi}->quote($sid);
		$self->{dbi}->do_sql($sql);
		return 1;
	}
	return 0;
}

=over

=item end_session(user,sessionid)

End this session

=back

=cut

sub end_session {
	my $self = shift;
	my $user=shift;
	my $sid=shift;

	$self->{dbi}->do_sql("DELETE FROM aas_session WHERE login=".$self->{dbi}->quote($user));
}

=over

=item is_allowed(user,uri)

Return a true value if this user have access to this uri false if not.

=back

=cut

sub is_allowed {
	my $self = shift;
	my $user=shift;
	my $uri=shift;
	my $grupos = $self->_get_user_groups($user);
	my $res = 0;
	foreach my $grupo (@{$grupos}) {
		if ($self->is_allowed_group($grupo,$uri)) {
			return 1;
		}
	}
	my $sql="SELECT * FROM aas_user_perms  WHERE login=".$self->{dbi}->quote($user);
	$sql.=" AND (uri=".$self->{dbi}->quote($uri);
	$sql.=" OR uri LIKE ".$self->{dbi}->quote($uri.'/%').")";
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}

=over

=item is_allowed_group(group,uri)

Return a true value if this group have access to this uri false if not.

=back

=cut

sub is_allowed_group {
	my $self = shift;
	my $group=shift;
	my $uri=shift;
	my $sql="SELECT * FROM aas_group_perms WHERE grp=".$self->{dbi}->quote($group);
	$sql.=" AND (uri=".$self->{dbi}->quote($uri);
	$sql.=" AND uri LIKE ".$self->{dbi}->quote($uri.'/%').")";
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}


=over

=item grant(user,uri)

Grant user the access to uri.

=back

=cut

sub grant {
	my $self = shift;
	my $user=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="INSERT INTO aas_user_perms (login,uri) VALUES ($user,$uri)";
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}

=over

=item grant_group(group,uri)

Grant group the access to uri.

=back

=cut

sub grant_group {
	my $self = shift;
	my $group=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="INSERT INTO aas_group_perms (group,uri) VALUES ($group,$uri)";
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}


=over

=item deny(user,uri)

Make the uri denied to the user

=back

=cut

sub deny {
	my $self = shift;
	my $user=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="DELETE FROM aas_user_perms WHERE login=$user AND uri=$uri";
	if($self->{dbi}->do_sql($sql)) {
		return 1;
	}
	return 0;
}

=over

=item deny_group(group,uri)

Make the uri denied to the group

=back

=cut

sub deny_group {
	my $self = shift;
	my $group=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="DELETE FROM aas_group_perms WHERE group=$group AND uri=$uri";
	if($self->{dbi}->do_sql($sql)) {
		return 1;
	}
	return 0;
}

=over

=item list_uri

return an array with the available uri

=back

=cut

sub list_uri {
	my $self = shift;
	die "Abstract method not implemented in ".ref $self;
}

sub _get_user_groups {
	# Abstract in Oak::AAS::Service::DBI
}

1;
