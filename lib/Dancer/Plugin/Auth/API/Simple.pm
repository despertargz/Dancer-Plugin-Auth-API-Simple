package Dancer::Plugin::Auth::API::Simple;

use Exporter;
use Dancer;

our @ISA = qw(Exporter);
our @EXPORT = qw(authenticate authorize);

our $is_user_logged_in;
our $get_user_roles;
our $unauthenticated_message;
our $unauthorized_message;

sub ensure_user_is_logged_in {
	if (!$is_user_logged_in->()) {
		status 401;
		halt $unauthenticated_message;
	}
}
	
sub authenticate {
	my $sub = shift;

	return sub {
		ensure_user_is_logged_in();
		$sub->();
	}
}

sub authorize {
	my $route_roles = shift;
	my $sub = shift;
	
	return sub {
		ensure_user_is_logged_in(); 

		my $authorized = 0;
		my $user_roles_ref = $get_user_roles->();
		my @user_roles = defined $user_roles_ref ? @{$user_roles_ref} : ();

		foreach my $route_role (@$route_roles) {
			 if (grep { $_ eq $route_role } @user_roles) {
				$authorized = 1;
				last;
			}
		}

		if (!$authorized) {
			status 403;
			halt $unauthorized_message;
		}
		else {
			$sub->();
		}
	}  	
}

return 1;

