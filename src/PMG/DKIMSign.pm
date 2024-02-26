package PMG::DKIMSign;

use strict;
use warnings;
use Email::Address::XS;
use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;
use Crypt::OpenSSL::RSA;

use PVE::Tools;
use PVE::INotify;
use PVE::SafeSyslog;

use PMG::Utils;
use PMG::Config;
use base qw(Mail::DKIM::Signer);

sub new {
    my ($class, $selector, $sign_all) = @_;

    die "no selector provided\n" if ! $selector;

    my %opts = (
	Algorithm => 'rsa-sha256',
	Method => 'relaxed/relaxed',
	Selector => $selector,
	KeyFile => "/etc/pmg/dkim/$selector.private",
    );

    my $self = $class->SUPER::new(%opts);

    $self->{sign_all} = $sign_all;

    return $self;
}

# MIME::Entity can output to all objects responding to 'print' (and does so in
# chunks) Mail::DKIM::Signer has a 'PRINT' method and expects each line
# terminated with "\r\n"


sub print {
    my ($self, $chunk) = @_;
    $chunk =~ s/\012/\015\012/g;
    $self->PRINT($chunk);
}

sub create_signature {
    my ($self) = @_;

    $self->CLOSE();
    return $self->signature->as_string();
}

#determines which domain should be used for signing based on the e-mailaddress
sub signing_domain {
    my ($self, $sender_email, $entity, $use_domain) = @_;

    my $input_domain;
    if ($use_domain eq 'header') {
	$input_domain = parse_headers_for_signing($entity);
    } else {
	my @parts = split('@', $sender_email);
	die "no domain in sender e-mail\n" if scalar(@parts) < 2;
	$input_domain = $parts[-1];
    }

    if ($self->{sign_all}) {
	    $self->domain($input_domain) if $self->{sign_all};
	    return 1;
    }

    # check that input_domain is in/a subdomain of in the
    # dkimdomains, falling back to the relay domains.
    my $dkimdomains = PVE::INotify::read_file('dkimdomains');
    $dkimdomains = PVE::INotify::read_file('domains') if !scalar(%$dkimdomains);

    # Sort domains by length first, so if we have both a sub domain and its parent
    # the correct one will be returned
    foreach my $domain (sort { length($b) <=> length($a) || $a cmp $b} keys %$dkimdomains) {
	if ( $input_domain =~ /\Q$domain\E$/i ) {
	    $self->domain($domain);
	    return 1;
	}
    }

    syslog('info', "not DKIM signing mail from $sender_email");

    return 0;
}


sub parse_headers_for_signing {
    # Following RFC 7489 [1], we only sign emails with exactly one sender in the
    # From header.
    #
    # [1] https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.1
    my ($entity) = @_;

    my $domain;

    my @from_headers = $entity->head->get('from');
    foreach my $from_header (@from_headers) {
	my @addresses = Email::Address::XS::parse_email_addresses($from_header);
	die "there is more than one sender in the header\n"
	    if defined($domain) || scalar(@addresses) > 1;
	$domain = $addresses[0]->host();
    }

    die "there is no sender in the header\n" if !defined($domain);
    return $domain;
}


sub sign_entity {
    my ($entity, $dkim, $sender) = @_;

    my $sign_all = $dkim->{sign_all};
    my $use_domain = $dkim->{use_domain};
    my $selector = $dkim->{selector};

    die "no selector provided\n" if ! $selector;

    #oversign certain headers
    my @oversign_headers = (
	'from',
	'to',
	'cc',
	'reply-to',
	'subject',
    );

    my @cond_headers = (
	'content-type',
    );

    push(@oversign_headers, grep { $entity->head->mime_attr($_) } @cond_headers);

    my $extended_headers = { map { $_ => '+' } @oversign_headers };

    my $signer = __PACKAGE__->new($selector, $sign_all);

    $signer->extended_headers($extended_headers);

    if ($signer->signing_domain($sender, $entity, $use_domain)) {
	$entity->print($signer);
	my $signature = $signer->create_signature();
	$entity->head->add('DKIM-Signature', $signature, 0);
    }

    return $entity;

}

# key-handling and utility methods
sub get_selector_info {
    my ($selector) = @_;

    die "no selector provided\n" if !defined($selector);
    my ($pubkey, $size);
    eval {
	my $privkeytext = PVE::Tools::file_get_contents("/etc/pmg/dkim/$selector.private");
	my $privkey =  Crypt::OpenSSL::RSA->new_private_key($privkeytext);
	$size = $privkey->size() * 8;

	$pubkey = $privkey->get_public_key_x509_string();
    };
    die "$@\n" if $@;

    $pubkey =~ s/-----(?:BEGIN|END) PUBLIC KEY-----//g;
    $pubkey =~ s/\v//mg;

    # split record into 250 byte chunks for DNS-server compatibility
    # see opendkim-genkey
    my $record = qq{$selector._domainkey\tIN\tTXT\t( "v=DKIM1; h=sha256; k=rsa; "\n\t  "p=};
    my $len = length($pubkey);
    my $cur = 0;
    while ($len > 0) {
	if ($len < 250) {
	    $record .= substr($pubkey, $cur);
	    $len = 0;
	} else {
	    $record .= substr($pubkey, $cur, 250) . qq{"\n\t  "};
	    $cur += 250;
	    $len -= 250;
	}
    }
    $record .= qq{" )  ; ----- DKIM key $selector};

    return ($record, $size);
}

sub set_selector {
    my ($selector, $keysize, $force) = @_;

    die "no selector provided\n" if !defined($selector);
    die "no keysize provided\n" if !defined($keysize);
    die "invalid keysize\n" if ($keysize < 1024);
    my $privkey_file = "/etc/pmg/dkim/$selector.private";

    my $code = sub {
	my $genkey = $force || (! -e $privkey_file);
	if (!$genkey) {
	    my ($privkey, $cursize);
	    eval {
		my $privkeytext = PVE::Tools::file_get_contents($privkey_file);
		$privkey =  Crypt::OpenSSL::RSA->new_private_key($privkeytext);
		$cursize = $privkey->size() * 8;
	    };
	    die "error checking $privkey_file: $@\n" if $@;
	    die "$privkey_file already exists, but has different size ($cursize bits)\n"
		if $cursize != $keysize;
	} else {
	    my $cmd = ['openssl', 'genrsa', '-out', $privkey_file, $keysize];
	    PMG::Utils::run_silent_cmd($cmd);
	}
	my $cfg = PMG::Config->new();
	$cfg->set('admin', 'dkim_selector', $selector);
	$cfg->write();
	PMG::Utils::reload_smtp_filter();
    };

    PMG::Config::lock_config($code, "unable to set DKIM key ($selector - $keysize bits)");
}
1;
