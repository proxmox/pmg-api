package PMG::Unpack;

use strict;
use warnings;
use IO::File;
use IO::Select;
use Xdgmime;
use Compress::Zlib qw(gzopen);
use Compress::Bzip2 qw(bzopen);
use IO::Uncompress::Gunzip;
use File::Path;
use File::Temp qw(tempdir);
use File::Basename;
use File::stat;
use POSIX ":sys_wait_h";
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use Archive::Zip qw(:CONSTANTS :ERROR_CODES);
use LibArchive;
use MIME::Parser;

use PMG::Utils;
use PMG::MIMEUtils;

my $unpackers = {

    # TAR
    'application/x-tar' =>                 [ 'tar', \&unpack_tar, 1],
    #'application/x-tar' =>                [ 'tar', \&generic_unpack ],
    #'application/x-tar' =>                [ '7z',   \&generic_unpack ],
    'application/x-compressed-tar' =>      [ 'tar', \&unpack_tar, 1],

    # CPIO
    'application/x-cpio' =>                [ 'cpio', \&unpack_tar, 1],
    #'application/x-cpio' =>               [ '7z', \&generic_unpack ],

    # ZIP
    #'application/zip' =>                  [ 'zip',  \&unpack_tar, 1],
    'application/zip' =>                   [ '7z',   \&generic_unpack ],

    # 7z
    'application/x-7z-compressed' =>       [ '7z',   \&generic_unpack ],

    # RAR
    'application/vnd.rar' =>               [ '7z',   \&generic_unpack ],

    # ARJ
    'application/x-arj' =>                 [ '7z',   \&generic_unpack ],

    # RPM
    'application/x-rpm' =>                 [ '7z', \&generic_unpack ],

    # DEB
    'application/vnd.debian.binary-package' => [ 'ar',   \&unpack_tar, 1],

    # MS CAB
    'application/vnd.ms-cab-compressed' => [ '7z',   \&generic_unpack ],

    # LZH/LHA
    'application/x-lha' =>                 [ '7z',   \&generic_unpack ],

    # TNEF (winmail.dat)
    'application/vnd.ms-tnef' =>           [ 'tnef', \&generic_unpack ],

    # message/rfc822
    'message/rfc822' =>                    [ 'mime', \&unpack_mime ],

    ## CHM, Nsis - supported by 7z, but we currently do not

    ##'application/x-zoo' - old format - no support
    ##'application/x-ms-dos-executable' - exe should be blocked anyways - no support
    ## application/x-arc - old format - no support
};

my $decompressors = {
    'application/gzip' =>  [ 'guzip', \&uncompress_file ],
    'application/x-compress' => [ 'uncompress', \&uncompress_file ],
    # 'application/x-compressed-tar' => [ 'guzip', \&uncompress_file ], # unpack_tar is faster
    'application/x-tarz' => [ 'uncompress', \&uncompress_file ],
    'application/x-bzip' => [ 'bunzip2', \&uncompress_file ],
    'application/x-bzip-compressed-tar' => [ 'bunzip2', \&uncompress_file ],
};


## some helper methods

sub min2 {
    return ( $_[0] < $_[1]) ? $_[0] : $_[1];
}

sub max2 {
    return ( $_[0] > $_[1]) ? $_[0] : $_[1];
}

# STDERR is redirected to STDOUT by default
sub helper_pipe_open {
    my ($fh, $inputfilename, $errorfilename, @cmd) = @_;

    my $pid = $fh->open ('-|');

    die "unable to fork helper process: $!" if !defined $pid;

    return $pid if ($pid != 0); # parent process simply returns

    $inputfilename = '/dev/null' if !$inputfilename;

    # same algorithm as used inside SA

    my $fd = fileno (STDIN);
    close STDIN;
    POSIX::close(0) if $fd != 0;

    if (!open (STDIN, "<$inputfilename")) {
	POSIX::_exit (1);
	kill ('KILL', $$);
    }

    $errorfilename = '&STDOUT' if !$errorfilename;

    $fd = fileno(STDERR);
    close STDERR;
    POSIX::close(2) if $fd != 2;

    if (!open (STDERR, ">$errorfilename")) {
	POSIX::_exit (1);
	kill ('KILL', $$);
    }

    exec @cmd;

    warn "exec failed";

    POSIX::_exit (1);
    kill('KILL', $$);
    die;  # else -w complains
}

sub helper_pipe_consume {
    my ($cfh, $pid, $timeout, $bufsize, $callback)  = @_;

    eval {
	run_with_timeout ($timeout, sub {
	    if ($bufsize) {
		my $buf;
		my $count;

		while (($count = $cfh->sysread ($buf, $bufsize)) > 0) {
		    &$callback ($buf, $count);
		}
		die "pipe read failed" if ($count < 0);

	    } else {
		while (my $line = <$cfh>) {
		    &$callback ($line);
		}
	    }
	});
    };

    my $err = $@;

    # send TERM first if process still exits
    if ($err) {
	kill (15, $pid) if kill (0, $pid);

	# read remaining data, if any
	my ($count, $buf);
	while (($count = $cfh->sysread ($buf, $bufsize)) > 0) {
	    # do nothing
	}
    }

    # then close pipe
    my $closeerr;
    close ($cfh) || ($closeerr = $!);
    my $childstat = $?;

    # still alive ?
    if (kill (0, $pid)) {
	sleep (1);
	kill (9, $pid); # terminate process
	die "child '$pid' termination problems\n";
    }

    die $err if $err;

    die "child '$pid' close failed - $closeerr\n" if $closeerr;

    die "child '$pid' failed: $childstat\n" if $childstat;
}

sub run_with_timeout {
    my ($timeout, $code, @param) = @_;

    die "got timeout\n" if $timeout <= 0;

    my $prev_alarm;

    my $sigcount = 0;

    my $res;

    eval {
	local $SIG{ALRM} = sub { $sigcount++; die "got timeout\n"; };
	local $SIG{PIPE} = sub { $sigcount++; die "broken pipe\n" };
	local $SIG{__DIE__};   # see SA bug 4631

	$prev_alarm = alarm ($timeout);

	$res = &$code (@param);

	alarm 0; # avoid race conditions
    };

    my $err = $@;

    alarm ($prev_alarm) if defined ($prev_alarm);

    die "unknown error" if $sigcount && !$err; # seems to happen sometimes

    die $err if $err;

    return $res;
}

# the unpacker object constructor

sub new {
    my ($type, %param) = @_;

    my $self = {};
    bless $self, $type;

    $self->{tmpdir} = $param{tmpdir} || tempdir (CLEANUP => 1);
    $self->{starttime} = [gettimeofday];
    $self->{timeout} = $param{timeout} || 3600*24;

    # maxfiles: 0 = disabled
    $self->{maxfiles} = defined ($param{maxfiles}) ? $param{maxfiles} : 1000;

    $param{maxrec} = 0 if !defined ($param{maxrec});
    if ($param{maxrec} < 0) {
	$param{maxrec} = - $param{maxrec};
	$self->{maxrec_soft} = 1; # do not die when limit reached
    }

    $self->{maxrec} = $param{maxrec} || 8;     # 0 = disabled
    $self->{maxratio} = $param{maxratio} || 0; # 0 = disabled

    $self->{maxquota} = $param{quota} || 250*1024*1024; # 250 MB

    $self->{ctonly} = $param{ctonly}; # only detect contained content types

    # internal
    $self->{quota} = 0;
    $self->{ratioquota} = 0;
    $self->{size} = 0;
    $self->{files} = 0;
    $self->{levels} = 0;

    $self->{debug} = $param{debug} || 0;

    $self->{mime} = {};
    $self->{filenames} = {};

    $self->{ufid} = 0; # counter to create unique file names
    $self->{udid} = 0; # counter to create unique dir names
    $self->{ulid} = 0; # counter to create unique link names

    $self->{todo} = [];

    return $self;
}

sub cleanup {
    my $self = shift;

    if ($self->{debug}) {
	system ("find '$self->{tmpdir}'");
    }

    rmtree ($self->{tmpdir});
}

sub DESTROY {
    my $self = shift;

    rmtree ($self->{tmpdir});
}


sub uncompress_file {
    my ($self, $app, $filename, $newname, $csize, $filesize) = @_;

    my $timeout = $self->check_timeout();

    my $maxsize = $self->{quota} - $self->{size};

    if ($self->{maxratio}) {
	$maxsize = min2 ($maxsize, $filesize * $self->{maxratio});
    }

    if($app eq 'guzip' && (my $z = IO::Uncompress::Gunzip->new($filename))) {
	# the name (FNAME) field is optional in GZIP archives, so we won't
	# always have a value here
	my $header = $z->getHeaderInfo();
	$self->add_glob_mime_type($header->{Name}) if $header->{Name};
    }

    $self->add_glob_mime_type ($newname);

    my $outfd;

    my $usize = 0;
    my $err;
    my $ct;
    my $todo = 1;

    if ($app eq 'guzip' || $app eq 'bunzip2') {

	my $cfh;

	eval {

	    # bzip provides a gz compatible interface
	    if ($app eq 'bunzip2') {
		$self->{mime}->{'application/x-bzip'} = 1;
		$cfh = bzopen ("$filename", 'r');
		die "bzopen '$filename' failed" if !$cfh;
	    } else {
		$self->{mime}->{'application/gzip'} = 1;
		$cfh = gzopen ("$filename", 'rb');
		die "gzopen '$filename' failed" if !$cfh;
	    }

	    run_with_timeout ($timeout, sub {
		my $count;
		my $buf;
		while (($count = $cfh->gzread ($buf, 128*1024)) > 0) {

		    if (!$usize) {
			$ct = xdg_mime_get_mime_type_for_data ($buf, $count);

			$usize += $count;
			$self->{mime}->{$ct} = 1;

			if (!is_archive ($ct)) {
			    $todo = 0;

			    # warning: this can lead to wrong size/quota test
			    last if $self->{ctonly};
			}
		    } else {
			$usize += $count;
		    }

		    $self->check_comp_ratio ($filesize, $usize);

		    $self->check_quota (1, $usize, $csize);

		    if (!$outfd) {
			$outfd = IO::File->new;

			if (!$outfd->open ($newname, O_CREAT|O_EXCL|O_WRONLY, 0640)) {
			    die "unable to create file $newname: $!";
			}
		    }

		    if (!$outfd->print ($buf)) {
			die "unable to write '$newname' - $!";
		    }
		}
		if ($count < 0) {
		    die "gzread failed";
		}
	    });
	};

	$err = $@;

	$cfh->gzclose();

    } elsif ($app eq 'uncompress') {

	$self->{mime}->{'application/x-compress'} = 1;

	eval {
	    my @cmd = ('/bin/gunzip', '-c', $filename);
	    my $cfh = IO::File->new();
	    my $pid = helper_pipe_open ($cfh, '/dev/null', '/dev/null', @cmd);

	    helper_pipe_consume ($cfh, $pid, $timeout, 128*1024, sub {
		my ($buf, $count) = @_;

		$ct = xdg_mime_get_mime_type_for_data ($buf, $count) if (!$usize);

		$usize += $count;

		$self->check_comp_ratio ($filesize, $usize);

		$self->check_quota (1, $usize, $csize);

		if (!$outfd) {
		    $outfd = IO::File->new;

		    if (!$outfd->open ($newname, O_CREAT|O_EXCL|O_WRONLY, 0640)) {
			die "unable to create file $newname: $!";
		    }
		}

		if (!$outfd->print ($buf)) {
		    die "unable to write '$newname' - $!";
		}

	    });
	};

	$err = $@;
    }

    $outfd->close () if $outfd;

    if ($err) {
	unlink $newname;
	die $err;
    }

    $self->check_quota (1, $usize, $csize, 1);

    $self->todo_list_add ($newname, $ct, $usize);

    return $newname;
};

# calculate real filesystem space (needed by ext3 to store files/dirs)
sub realsize {
    my ($size, $isdir) = @_;

    my $bs = 4096; # ext3 block size

    $size = max2 ($size, $bs) if $isdir; # dirs needs at least one block

    return int (($size + $bs - 1) / $bs) * $bs; # round up to block size
}

sub todo_list_add {
    my ($self, $filename, $ct, $size) = @_;

    if ($ct) {
	$self->{mime}->{$ct} = 1;
	if (is_archive ($ct)) {
	    push @{$self->{todo}}, [$filename, $ct, $size];
	}
    }
}

sub check_timeout {
    my ($self) = @_;

    my $elapsed = int (tv_interval ($self->{starttime}));
    my $timeout = $self->{timeout} - $elapsed;

    die "got timeout\n" if $timeout <= 0;

    return $timeout;
}

sub check_comp_ratio {
    my ($self, $compsize, $usize) = @_;

    return if !$compsize || !$self->{maxratio};

    my $ratio = $usize/$compsize;

    die "compression ratio too large (> $self->{maxratio})"
	if $ratio > $self->{maxratio};
}

sub check_quota {
    my ($self, $files, $size, $csize, $commit) = @_;

    my $sizediff = $csize ? $size - $csize : $size;

    die "compression ratio too large (> $self->{maxratio})"
	if $self->{maxratio} && (($self->{size} + $sizediff) > $self->{ratioquota});

    die "archive too large (> $self->{quota})"
	if ($self->{size} + $sizediff) > $self->{quota};

    die "unexpected number of files '$files'" if $files <= 0;

    $files-- if ($csize);

    die "too many files in archive (> $self->{maxfiles})"
	if $self->{maxfiles} && (($self->{files} + $files) > $self->{maxfiles});

    if ($commit) {
	$self->{files} += $files;
	$self->{size} += $sizediff;
    }

}

sub add_glob_mime_type {
    my ($self, $filename) = @_;

    my $basename = basename($filename);
    $self->{filenames}->{$basename} = 1;

    if (my $ct = xdg_mime_get_mime_type_from_file_name($basename)) {
	$self->{mime}->{$ct} = 1 if $ct ne 'application/octet-stream';
    }
}

sub unpack_mime {
    my ($self, $app, $filename, $tmpdir, $csize, $filesize) = @_;

    my $size = 0;
    my $files = 0;

    my $timeout = $self->check_timeout();

    eval {
	run_with_timeout ($timeout, sub {

	    # Create a new MIME parser:
	    my $max;
	    if ($self->{maxfiles}) {
		$max = $self->{maxfiles} - $self->{files};
	    }

	    my $parser = PMG::MIMEUtils::new_mime_parser({
		dumpdir => $tmpdir,
		nested => 1,
		ignore_errors => 1,
		extract_uuencode => 1,
		ignore_filename => 1,
		maxfiles => $max,
	    }, 1);

	    my $entity = $parser->parse_open ($filename);

	    PMG::MIMEUtils::traverse_mime_parts($entity, sub {
		my ($part) = @_;
		my $ct = $part->head->mime_attr('content-type');
		$self->{mime}->{$ct} = 1 if $ct && length($ct) < 256;

		if (my $body = $part->bodyhandle) {
		    my $path = $body->path;
		    $size += -s $path;
		    $files++;
		}
	    });
	});
    };

    my $err = $@;

    die $err if $err;

    $self->check_quota ($files, $size, $csize, 1); # commit sizes

    return 1;

}

sub unpack_zip {
    my ($self, $app, $filename, $tmpdir, $csize, $filesize) = @_;

    my $size = 0;
    my $files = 0;

    my $timeout = $self->check_timeout();

    eval {

	my $zip = Archive::Zip->new ();

	Archive::Zip::setErrorHandler (sub { die @_ });

	run_with_timeout ($timeout, sub {

	    my $status = $zip->read ($filename);
	    die "unable to open zip file '$filename'" if $status != AZ_OK;

	    my $tid = 1;
	    foreach my $mem ($zip->members) {

		$files++;

		my $cm = $mem->compressionMethod();
		die "unsupported zip compression method '$cm'\n"
		    if !(($cm == COMPRESSION_DEFLATED ||
			  $cm == COMPRESSION_STORED));

		die "encrypted archive detected\n"
		    if $mem->isEncrypted();

		my $us = $mem->uncompressedSize();

		next if $us <= 0; # skip zero size files

		if ($mem->isDirectory) {
		    $size += realsize ($us, 1);
		} else {
		    $size += realsize ($us);
		}

		$self->check_comp_ratio ($filesize, $size);

		$self->check_quota ($files, $size, $csize);

		next if $mem->isDirectory; # skip dirs

		my $name = basename ($mem->fileName());
		$name =~ s|[^A-Za-z0-9\.]|-|g;
		my $newfn = sprintf "$tmpdir/Z%08d_$name", $tid++;

		$self->add_glob_mime_type ($name);

		my $outfd = IO::File->new;
		if (!$outfd->open ($newfn, O_CREAT|O_EXCL|O_WRONLY, 0640)) {
		    die "unable to create file $newfn: $!";
		}

		my $ct;

		eval {

		    $mem->desiredCompressionMethod (COMPRESSION_STORED);

		    $status = $mem->rewindData();

		    die "unable to rewind zip stream" if $status !=  AZ_OK;

		    my $outRef;
		    my $bytes = 0;
		    while ($status == AZ_OK) {
			($outRef, $status) = $mem->readChunk();
			die "unable to read zip member"
			    if ($status != AZ_OK && $status != AZ_STREAM_END);

			my $len = length ($$outRef);
			if ($len > 0) {
			    $ct = xdg_mime_get_mime_type_for_data ($$outRef, $len) if (!$bytes);
			    $outfd->print ($$outRef) || die "write error during zip copy";
			    $bytes += $len;
			}

			last if $status == AZ_STREAM_END;
		    }

		    $mem->endRead();

		    $self->todo_list_add ($newfn, $ct, $bytes);

		};

		my $err = $@;

		$outfd->close ();

		if ($err) {
		    unlink $newfn;
		    die $err;
		}
	    }
	});
    };

    my $err = $@;

    die $err if $err;

    $self->check_quota ($files, $size, $csize, 1); # commit sizes

    return 1;
}

sub unpack_tar {
    my ($self, $app, $filename, $tmpdir, $csize, $filesize) = @_;

    my $size = 0;
    my $files = 0;

    my $timeout = $self->check_timeout();

    my $a = LibArchive::archive_read_new();

    die "unable to create LibArchive object" if !$a;

    LibArchive::archive_read_support_format_all ($a);
    LibArchive::archive_read_support_filter_all ($a);

    eval {
	run_with_timeout ($timeout, sub {

	    if ((my $r = LibArchive::archive_read_open_filename ($a, $filename, 10240))) {
		die "LibArchive error: %s", LibArchive::archive_error_string ($a);
	    }
	    my $tid = 1;
	    for (;;) {
		my $entry;
		my $r = LibArchive::archive_read_next_header ($a, $entry);

		last if ($r == LibArchive::ARCHIVE_EOF);

		if ($r != LibArchive::ARCHIVE_OK) {
		    die "LibArchive error: %s",  LibArchive::archive_error_string ($a);
		}

		my $us = LibArchive::archive_entry_size ($entry);
		my $mode = LibArchive::archive_entry_mode ($entry);

		my $rs;
		if (POSIX::S_ISREG ($mode)) {
		    $rs = realsize ($us);
		} else {
		    $rs = POSIX::S_ISDIR ($mode) ? realsize ($us, 1) : 256;
		}
		$size += $rs;
		$files += 1;

		$self->check_comp_ratio ($filesize, $size);

		$self->check_quota ($files, $size, $csize);

		next if POSIX::S_ISDIR ($mode);
		next if !POSIX::S_ISREG ($mode);

		my $name = basename (LibArchive::archive_entry_pathname ($entry));
		$name =~ s|[^A-Za-z0-9\.]|-|g;
		my $newfn = sprintf "$tmpdir/A%08d_$name", $tid++;

		$self->add_glob_mime_type ($name);

		my $outfd;

		eval {
		    my $bytes = 0;
		    my $ct;
		    my $todo = 1;

		    if ($us > 0) {
			my $len;
			my $buf;
			while (($len = LibArchive::archive_read_data($a, $buf, 128*1024)) > 0) {

			    if (!$bytes) {
				if ($ct = xdg_mime_get_mime_type_for_data ($buf, $len)) {
				    $self->{mime}->{$ct} = 1;

				    if (!is_archive ($ct)) {
					$todo = 0;
					last if $self->{ctonly};
				    }
				}
			    }

			    $bytes += $len;

			    if (!$outfd) { # create only when needed
				$outfd = IO::File->new;

				if (!$outfd->open ($newfn, O_CREAT|O_EXCL|O_WRONLY, 0640)) {
				    die "unable to create file $newfn: $!";
				}
			    }

			    if (!$outfd->print ($buf)) {
				die "unable to write '$newfn' - $!";
			    }
			}

			die ("error reading archive (encrypted)\n")
			    if ($len < 0);
		    }

		    $self->todo_list_add ($newfn, $ct, $bytes) if $todo;
		};

		my $err = $@;

		$outfd->close () if $outfd;

		if ($err) {
		    unlink $newfn;
		    die $err;
		}
	    }
	});
    };

    my $err = $@;

    LibArchive::archive_read_close($a);
    LibArchive::archive_read_free($a);

    die $err if $err;

    $self->check_quota ($files, $size, $csize, 1); # commit sizes

    return 1;
}

sub generic_unpack {
    my ($self, $app, $filename, $tmpdir, $csize, $filesize) = @_;

    my $size = 0;
    my $files = 0;

    my $timeout = $self->check_timeout();

    my @listcmd;
    my @restorecmd = ('/bin/false');

    my $filter;

    if ($app eq 'tar') {
	@listcmd = ('/bin/tar', '-tvf', $filename);
	@restorecmd = ('/bin/tar', '-x', '--backup=number', "--transform='s,[^A-Za-z0-9\./],-,g'", '-o',
		       '-m', '-C', $tmpdir, '-f', $filename);
	$filter = sub {
	    my $line = shift;
	    if ($line =~ m/^(\S)\S+\s+\S+\s+([\d,\.]+)\s+\S+/) {
		my ($type, $bytes) = ($1, $2);
		$bytes =~ s/[,\.]//g;

		if ($type eq 'd') {
		    $bytes = realsize ($bytes, 1);
		} elsif ($type eq '-') {
		    $bytes = realsize ($bytes);
		} else {
		    $bytes = 256; # simple assumption
		}

		$size += $bytes;
		$files++;

		$self->check_comp_ratio ($filesize, $size);
		$self->check_quota ($files, $size, $csize);

	    } else {
		die "can't parse tar output: $line\n";
	    }
	}
    } elsif ($app eq '7z' || $app eq '7zsimple') {
	# Note: set password to 'none' with '-pnone', to avoid reading from /dev/tty
	@restorecmd = ('/usr/bin/7z', 'e', '-pnone', '-bd', '-y', '-aou', "-w$self->{tmpdir}", "-o$tmpdir", $filename);

	@listcmd = ('/usr/bin/7z', 'l', '-slt', $filename);

	my ($path, $folder, $bytes);

	$filter = sub {
	    my $line = shift;
	    chomp $line;

	    if ($line =~ m/^\s*\z/) {
		if (defined ($path) && defined ($bytes)) {
		    $bytes = realsize ($bytes, $folder);
		    $size += $bytes;
		    $files++;

		    $self->check_comp_ratio ($filesize, $size);
		    $self->check_quota ($files, $size, $csize);
		}
		undef $path;
		undef $folder;
		undef $bytes;

	    } elsif ($line =~ m/^Path = (.*)\z/s) {
		$path = $1;
	    } elsif ($line =~ m/^Size = (\d+)\z/s) {
		$bytes = $1;
	    } elsif ($line =~ m/^Folder = (\d+)\z/s) {
		$folder = $1;
	    } elsif ($line =~ m/^Attributes = ([D\.][R\.][H\.][S\.][A\.])\z/s) {
		$folder = 1 if $1 && substr ($1, 0, 1) eq 'D';
	    }
	};

    } elsif ($app eq 'tnef') {
	@listcmd = ('/usr/bin/tnef', '-tv', '-f', $filename);
	@restorecmd = ('/usr/bin/tnef', '-C', $tmpdir, '--number-backups', '-f', $filename);

	$filter = sub {
	    my $line = shift;
	    chomp $line;

	    if ($line =~ m!^\s*(\d+)\s*|\s*\d{4}/\d{1,2}/\d{1,2}\s+\d{1,2}:\d{1,2}:\d{1,2}\s*|!) {
		my $bytes = $1;

		$bytes = realsize ($bytes);
		$size += $bytes;
		$files++;

		$self->check_comp_ratio ($filesize, $size);
		$self->check_quota ($files, $size, $csize);
	    } else {
		die "can't parse tnef output\n";
	    }

	};

    } else {
	die "unknown application '$app'";
    }

    eval {

	my $cfh = IO::File->new();
	my $pid = helper_pipe_open ($cfh, '/dev/null', '/dev/null', @listcmd);

	helper_pipe_consume ($cfh, $pid, $timeout, 0, $filter);
    };

    my $err = $@;

    die $err if $err;

    return if !$files; # empty archive

    $self->check_quota ($files, $size, $csize, 1);

    $timeout = $self->check_timeout();

    my $cfh = IO::File->new();
    my $pid = helper_pipe_open ($cfh, '/dev/null', undef, @restorecmd);
    helper_pipe_consume ($cfh, $pid, $timeout, 0, sub {
	my $line = shift;
	print "$app: $line" if $self->{debug};
    });

    return 1;
}

sub unpack_dir {
    my ($self, $dirname, $level) = @_;

    local (*DIR);

    print "unpack dir '$dirname'\n" if $self->{debug};

    opendir(DIR, $dirname) || die "can't opendir $dirname: $!";

    my $name;

    while (defined ($name = readdir (DIR))) {
	my $path = "$dirname/$name";
	my $st = lstat ($path);

	if (!$st) {
	    die "no such file '$path' - $!";
	} elsif (POSIX::S_ISDIR ($st->mode)) {
	    next if ($name eq '.' || $name eq '..');
	    $self->unpack_dir ($path, $level);
	} elsif (POSIX::S_ISREG ($st->mode)) {
	    my $size = $st->size;
	    $self->__unpack_archive ($path, $level + 1, $size);
	}
    }

    closedir DIR;
}

sub unpack_todo {
    my ($self, $level) = @_;

    my $ta = $self->{todo};
    $self->{todo} = [];

    foreach my $todo (@$ta) {
	$self->__unpack_archive ($todo->[0], $level, $todo->[2], $todo->[1]);
    }
}

sub __unpack_archive {
    my ($self, $filename, $level, $size, $ct) = @_;

    $level = 0 if !$level;

    $self->{levels} = max2($self->{levels}, $level);

    if ($self->{maxrec} && ($level >= $self->{maxrec})) {
	return if $self->{maxrec_soft};
	die "max recursion limit reached\n";
    }

    die "undefined file size" if !defined ($size);

    return if !$size; # nothing to do

    if (!$ct) {
	$ct = PMG::Utils::magic_mime_type_for_file($filename);
	$self->add_glob_mime_type($filename);
    }

    if ($ct) {
	$self->{mime}->{$ct} = 1;

	if (defined($decompressors->{$ct})) {

	    my ($app, $code) = @{$decompressors->{$ct}};

	    if ($app) {

		# we try to keep extension correctly
		my $tmp = basename($filename);
		($ct eq 'application/gzip') &&
		    $tmp =~ s/\.gz\z//;
		($ct eq 'application/x-bzip') &&
		    $tmp =~ s/\.bz2?\z//;
		($ct eq 'application/x-compress') &&
		    $tmp =~ s/\.Z\z//;
		($ct eq 'application/x-compressed-tar') &&
		    $tmp =~ s/\.gz\z// || $tmp =~ s/\.tgz\z/.tar/;
		($ct eq 'application/x-bzip-compressed-tar') &&
		    $tmp =~ s/\.bz2?\z// || $tmp =~ s/\.tbz\z/.tar/;
		($ct eq 'application/x-tarz') &&
		    $tmp =~ s/\.Z\z//;

		my $newname = sprintf "%s/DC_%08d_%s", $self->{tmpdir}, ++$self->{ufid}, $tmp;

		print "Decomp: $filename\n\t($ct) with $app to $newname\n"
		    if  $self->{debug};

		if (my $res = &$code($self, $app, $filename, $newname, $level ? $size : 0, $size)) {
		    unlink $filename if $level;
		    $self->unpack_todo ($level + 1);
		}
	    }
	} elsif (defined ($unpackers->{$ct})) {

	    my ($app, $code, $ctdetect) = @{$unpackers->{$ct}};

	    if ($app) {

		my $tmpdir = sprintf "%s/DIR_%08d", $self->{tmpdir}, ++$self->{udid};
		mkdir $tmpdir;

		print "Unpack: $filename\n\t($ct) with $app to $tmpdir\n"
		    if $self->{debug};

		if (my $res = &$code ($self, $app, $filename, $tmpdir, $level ? $size : 0, $size)) {
		    unlink $filename if $level;

		    if ($ctdetect) {
			$self->unpack_todo ($level + 1);
		    } else {
			$self->unpack_dir ($tmpdir, $level);
		    }
		}
	    }
	}
    }
}

sub is_archive {
    my ($ct) = @_;

    return defined($decompressors->{$ct}) || defined($unpackers->{$ct});
}

# unpack_archive
#
# Description: unpacks an archive and records containing
# content types (detected by magic numbers and file extension)
# Extracted files are stored inside 'tempdir'.
#
# returns: true if file is archive, undef otherwise

sub unpack_archive {
    my ($self, $filename, $ct) = @_;

    my $st = lstat($filename);
    my $size = 0;

    if (!$st) {
	die "no such file '$filename' - $!";
    } elsif (POSIX::S_ISREG($st->mode)) {
	$size = $st->size;

	return if !$size; #  do nothing

	$self->{quota} = $self->{maxquota} - $self->{size};

	$self->{ratioquota} = $size * $self->{maxratio} if $self->{maxratio};

    } else {
	return; # do nothing
    }

    $ct = PMG::Utils::magic_mime_type_for_file($filename) if !$ct;

    return if (!$ct || !is_archive($ct)); # not an archive

    eval {
	$self->__unpack_archive($filename, 0, $st->size, $ct);
    };

    my $err = $@;

    printf "ELAPSED: %.2f ms $filename\n",
    int(tv_interval ($self->{starttime}) * 1000)
	if $self->{debug};

    if ($err) {
	$self->{mime}->{'proxmox/unreadable-archive'} = 1;
	die $err;
    }
    return 1;
}

1;
__END__
