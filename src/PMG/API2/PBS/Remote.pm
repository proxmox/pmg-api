package PMG::API2::PBS::Remote;

use strict;
use warnings;

use JSON;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::PBSClient;

use PMG::PBSConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'list',
    path => '',
    method => 'GET',
    description => "List all configured Proxmox Backup Server instances.",
    permissions => { check => ['admin', 'audit'] },
    proxyto => 'master',
    protected => 1,
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => "array",
        items => PMG::PBSConfig->createSchema(1),
        links => [{ rel => 'child', href => "{remote}" }],
    },
    code => sub {
        my ($param) = @_;

        my $res = [];

        my $conf = PMG::PBSConfig->new();
        return $res if !defined($conf);

        for my $remote (sort keys %{ $conf->{ids} }) {
            my $d = $conf->{ids}->{$remote};
            my $remote = {
                remote => $remote,
                server => $d->{server},
                datastore => $d->{datastore},
                username => $d->{username},
                disable => $d->{disable},
            };
            $remote->{namespace} = $d->{namespace}
                if $d->{namespace} && length($d->{namespace});
            push @$res, $remote;
        }

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'create',
    path => '',
    method => 'POST',
    description => "Add Proxmox Backup Server remote instance.",
    permissions => { check => ['admin'] },
    proxyto => 'master',
    protected => 1,
    parameters => PMG::PBSConfig->createSchema(1),
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $code = sub {
            my $conf = PMG::PBSConfig->new();
            $conf->{ids} //= {};
            my $ids = $conf->{ids};

            my $remote = extract_param($param, 'remote');
            die "PBS remote '$remote' already exists\n" if $ids->{$remote};

            my $remotecfg = PMG::PBSConfig->check_config($remote, $param, 1);

            my $password = extract_param($remotecfg, 'password');

            my $pbs = PVE::PBSClient->new($remotecfg, $remote, $conf->{secret_dir});
            $pbs->set_password($password) if defined($password);

            my $encryption_key = extract_param($remotecfg, 'encryption-key');

            if (defined($encryption_key)) {
                my $decoded_key;
                if ($encryption_key eq 'autogen') {
                    $encryption_key = $pbs->autogen_encryption_key();
                    $decoded_key = decode_json($encryption_key);
                } else {
                    $decoded_key = eval { decode_json($encryption_key) };
                    if ($@ || !exists($decoded_key->{data})) {
                        die
                            "Value does not seems like a valid, JSON formatted encryption key!\n";
                    }
                    $pbs->set_encryption_key($encryption_key);
                }
                $remotecfg->{'encryption-key'} = $decoded_key->{fingerprint} || 1;
            } else {
                $pbs->delete_encryption_key();
            }

            $ids->{$remote} = $remotecfg;
            $conf->write();
        };

        PMG::PBSConfig::lock_config($code, "add PBS remote failed");

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'read_config',
    path => '{remote}',
    method => 'GET',
    description => "Get Proxmox Backup Server remote configuration.",
    proxyto => 'master',
    permissions => { check => ['admin', 'audit'] },
    parameters => {
        additionalProperties => 1,
        properties => {
            remote => {
                description => "Proxmox Backup Server ID.",
                type => 'string',
                format => 'pve-configid',
            },
        },
    },
    returns => {},
    code => sub {
        my ($param) = @_;

        my $conf = PMG::PBSConfig->new();

        my $remote = $param->{remote};

        my $data = $conf->{ids}->{$remote};
        die "PBS remote '$remote' does not exist\n" if !$data;

        delete $data->{type};

        $data->{digest} = $conf->{digest};
        $data->{remote} = $remote;

        return $data;
    },
});

__PACKAGE__->register_method({
    name => 'update_config',
    path => '{remote}',
    method => 'PUT',
    description => "Update PBS remote settings.",
    permissions => { check => ['admin'] },
    protected => 1,
    proxyto => 'master',
    parameters => PMG::PBSConfig->updateSchema(),
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $code = sub {

            my $conf = PMG::PBSConfig->new();
            my $ids = $conf->{ids};

            my $digest = extract_param($param, 'digest');
            PVE::SectionConfig::assert_if_modified($conf, $digest);

            my $remote = extract_param($param, 'remote');

            die "PBS remote '$remote' does not exist\n" if !$ids->{$remote};

            my $delete_str = extract_param($param, 'delete');
            die "no options specified\n" if !$delete_str && !scalar(keys %$param);

            my $pbs = PVE::PBSClient->new($ids->{$remote}, $remote, $conf->{secret_dir});
            foreach my $opt (PVE::Tools::split_list($delete_str)) {
                if ($opt eq 'password') {
                    $pbs->delete_password();
                }
                if ($opt eq 'encryption-key') {
                    $pbs->delete_encryption_key();
                }
                delete $ids->{$remote}->{$opt};
            }

            if (defined(my $password = extract_param($param, 'password'))) {
                $pbs->set_password($password);
            }

            if (exists($param->{'encryption-key'})) {
                if (defined(my $encryption_key = extract_param($param, 'encryption-key'))) {
                    my $decoded_key;
                    if ($encryption_key eq 'autogen') {
                        $encryption_key = $pbs->autogen_encryption_key();
                        $decoded_key = decode_json($encryption_key);
                    } else {
                        $decoded_key = eval { decode_json($encryption_key) };
                        if ($@ || !exists($decoded_key->{data})) {
                            die
                                "Value does not seems like a valid, JSON formatted encryption key!\n";
                        }
                        $pbs->set_encryption_key($encryption_key);
                    }
                    $param->{'encryption-key'} = $decoded_key->{fingerprint} || 1;
                } else {
                    $pbs->delete_encryption_key();
                }
            }

            my $remoteconfig = PMG::PBSConfig->check_config($remote, $param, 0, 1);

            foreach my $p (keys %$remoteconfig) {
                $ids->{$remote}->{$p} = $remoteconfig->{$p};
            }

            $conf->write();
        };

        PMG::PBSConfig::lock_config($code, "update PBS remote failed");

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'delete',
    path => '{remote}',
    method => 'DELETE',
    description => "Delete an PBS remote",
    permissions => { check => ['admin'] },
    protected => 1,
    proxyto => 'master',
    parameters => {
        additionalProperties => 0,
        properties => {
            remote => {
                description => "Profile ID.",
                type => 'string',
                format => 'pve-configid',
            },
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $code = sub {
            my $conf = PMG::PBSConfig->new();
            my $ids = $conf->{ids};

            my $remote = $param->{remote};
            die "PBS remote '$remote' does not exist\n" if !$ids->{$remote};

            my $pbs = PVE::PBSClient->new($ids->{$remote}, $remote, $conf->{secret_dir});
            $pbs->delete_password();
            $pbs->delete_encryption_key();
            delete $ids->{$remote};

            $conf->write();

            eval { PMG::PBSSchedule::delete_schedule($remote) }; # best effort only
        };

        PMG::PBSConfig::lock_config($code, "delete PBS remote failed");

        return undef;
    },
});

1;
