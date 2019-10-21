package PMG::API2::DKIMSignDomains;

use strict;
use warnings;

use PVE::RESTHandler;

use PMG::API2::Domains;

use base qw(PVE::RESTHandler);

my @domain_args = ('dkimdomains', 'DKIM-sign', 'domains', 0);

__PACKAGE__->register_method(PMG::API2::Domains::index_method(@domain_args));
__PACKAGE__->register_method(PMG::API2::Domains::create_method(@domain_args));
__PACKAGE__->register_method(PMG::API2::Domains::read_method(@domain_args));
__PACKAGE__->register_method(PMG::API2::Domains::write_method(@domain_args));
__PACKAGE__->register_method(PMG::API2::Domains::delete_method(@domain_args));

