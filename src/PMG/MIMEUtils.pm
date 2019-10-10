package PMG::MIMEUtils;

# provides helpers for dealing with MIME related code

use strict;
use warnings;

use MIME::Parser;
use File::Path;

# wrapper around MIME::Parser::new which allows to give the config as hash
sub new_mime_parser {
    my ($params, $dump_under) = @_;

    my $parser = new MIME::Parser;

    $parser->extract_nested_messages($params->{nested} // 0);
    $parser->ignore_errors($params->{ignore_errors} // 1);
    $parser->extract_uuencode($params->{extract_uuencode})
	if defined($params->{extract_uuencode});
    $parser->decode_bodies($params->{decode_bodies})
	if defined($params->{decode_bodies});
    $parser->max_parts($params->{maxfiles})
	if defined($params->{maxfiles});

    my $dumpdir = $params->{dumpdir};
    if (!$dumpdir) {
	$parser->output_to_core(1);
    } elsif ($dump_under) {
	$parser->output_under($dumpdir);
    } else {
	rmtree $dumpdir;

	# Create and set the output directory:
	(-d $dumpdir || mkdir($dumpdir ,0755)) ||
	die "can't create $dumpdir: $! : ERROR";
	(-w $dumpdir) ||
	die "can't write to directory $dumpdir: $! : ERROR";

	$parser->output_dir($dumpdir);
    }

    # this has to be done after setting the dumpdir
    $parser->filer->ignore_filename($params->{ignore_filename})
	if defined($params->{ignore_filename});

    return $parser;
}

# bug fix for content/mimeparser.txt in regression test
sub fixup_multipart {
    my ($entity) = @_;

    if ($entity->mime_type =~ m|multipart/|i && !$entity->head->multipart_boundary) {
	$entity->head->mime_attr('Content-type' => "application/x-unparseable-multipart");
    }

    return $entity;
}

sub traverse_mime_parts {
    my ($entity, $subbefore, $subafter) = @_;

    if (defined($subbefore)) {
	$subbefore->($entity);
    }

    foreach my $part ($entity->parts) {
	traverse_mime_parts($part, $subbefore, $subafter);
    }

    if (defined($subafter)) {
	$subafter->($entity);
    }
}

1;
