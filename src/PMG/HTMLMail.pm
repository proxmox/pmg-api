package PMG::HTMLMail;

use strict;
use warnings;
use Encode;
use Data::Dumper;
use MIME::Head;
use File::Path;
use HTML::Entities;
use MIME::Parser;
use MIME::Base64;
use HTML::TreeBuilder;
use HTML::Scrubber;

sub dump_html {
    my ($tree, $cid_hash) = @_;

    my @html = ();

    my($tag, $node, $start, $depth);

    $tree->traverse(
	sub {
	    ($node, $start) = @_;
	    if(ref $node) {
		$tag = $node->{'_tag'};

		# try to open a new window when user activates a anchor
		$node->{target} = '_blank' if $tag eq 'a';

		if ($tag eq 'img') {
		    if ($node->{src} =~ m/^cid:(\S+)$/) {
			if (my $datauri = $cid_hash->{$1}) {
			    $node->{src} = $datauri;
			}
		    }
		}

		if($start) { # on the way in
		    push(@html, $node->starttag);
		} else {
		    # on the way out
		    push(@html, $node->endtag);
		}
	    } else {
		# simple text content
		$node = encode_entities($node)
		    # That does magic things if $entities is undef.
		    unless $HTML::Tagset::isCDATA_Parent{ $_[3]{'_tag'} };
		# To keep from amp-escaping children of script et al.
		# That doesn't deal with descendants; but then, CDATA
		#  parents shouldn't /have/ descendants other than a
		#  text children (or comments?)
		push(@html, $node);
	    }
	    1; # keep traversing
	}
    );

    return join('', @html, "\n");
}

sub getscrubber {
    my ($viewimages, $allowhref) = @_;

    # see http://web.archive.org/web/20110726052341/http://feedparser.org/docs/html-sanitization.html

    my @allow = qw(a abbr acronym address area b big blockquote br button caption center cite code col colgroup dd del dfn dir div dl dt em fieldset font form h1 h2 h3 h4 h5 h6 head hr i img input ins kbd label legend li map menu ol optgroup option p pre q s samp select small span style strike strong sub sup title table tbody td textarea tfoot th thead tr tt u ul var html body);

    my @rules = ( script => 0 );

    my @default = (
	0 =>  # default rule, deny all tags
	{
	    '*' => 0, # default rule, deny all attributes
	    abbr => 1,
	    accept => 1,
	    'accept-charset' => 1,
	    accesskey => 1,
	    align => 1,
	    alt => 1,
	    axis => 1,
	    border => 1,
	    bgcolor => 1,
	    cellpadding => 1,
	    cellspacing => 1,
	    char => 1,
	    charoff => 1,
	    charset => 1,
	    checked => 1,
	    cite => 1,
	    class => 1,
	    clear => 1,
	    cols => 1,
	    colspan => 1,
	    color => 1,
	    compact => 1,
	    coords => 1,
	    datetime => 1,
	    dir => 1,
	    disabled => 1,
	    enctype => 1,
	    frame => 1,
	    headers => 1,
	    height => 1,
	    # only allow http:// and https:// hrefs
	    'href' => $allowhref ? qr{^https?://[^/]+/}i : 0,
	    hreflang => 1,
	    hspace => 1,
	    id => 1,
	    ismap => 1,
	    label => 1,
	    lang => 1,
	    longdesc => 1,
	    maxlength => 1,
	    media => 1,
	    method => 1,
	    multiple => 1,
	    name => 1,
	    nohref => 1,
	    noshade => 1,
	    nowrap => 1,
	    prompt => 1,
	    readonly => 1,
	    rel => 1,
	    rev => 1,
	    rows => 1,
	    rowspan => 1,
	    rules => 1,
	    scope => 1,
	    selected => 1,
	    shape => 1,
	    size => 1,
	    span => 1,
	    src => $viewimages ? qr{^(?!(?:java)?script)}i : 0,
	    start => 1,
	    style => 1,
	    summary => 1,
	    tabindex => 1,
	    target => 1,
	    title => 1,
	    type => 1,
	    usemap => 1,
	    valign => 1,
	    value => 1,
	    vspace => 1,
	    width => 1,
	}
    );

    my $scrubber = HTML::Scrubber->new(
	allow   => \@allow,
	rules   => \@rules,
	default => \@default,
	comment => 0,
	process => 0,
    );

    $scrubber->style(1);

    return $scrubber;
}

sub read_raw_email {
    my ($path, $maxbytes) = @_;

    open (my $fh, '<', $path) || die "unable to open '$path' - $!\n";

    my $data = '';
    my $raw_header = '';

    # read header
    my $header;
    while (defined(my $line = <$fh>)) {
	$raw_header .= $line;
	chomp $line;
	push @$header, $line;
	last if $line =~ m/^\s*$/;
    }

    my $head = MIME::Head->new($header);

    my $cs = $head->mime_attr("content-type.charset");

    my $bytes = 0;

    while (defined(my $line = <$fh>)) {
	$bytes += length ($line);
	if ($cs) {
	    $data .= decode($cs, $line);
	} else {
	    $data .= $line;
	}
	if (defined($maxbytes) && ($bytes >= $maxbytes)) {
	    $data .= "\n... mail truncated (> $maxbytes bytes)\n";
	    last;
	}
    }

    close($fh);

    return ($raw_header, $data);
}

my $read_part = sub {
    my ($part) = @_;

    my $io = $part->open("r");
    return undef if !$io;

    my $raw = '';
    while (defined(my $line = $io->getline)) { $raw .= $line; }
    $io->close;

    return $raw;
};

my $find_images = sub {
    my ($cid_hash, $entity) = @_;

    foreach my $part ($entity->parts)  {
	if (my $rawcid = $part->head->get('Content-Id')) {
	    if ($rawcid =~ m/^\s*<(\S+)>\s*$/) {
		my $cid = $1;
		my $ctype = $part->head->mime_attr('Content-type') // '';
		if ($ctype =~ m!^image/!) {
		    if (defined(my $raw = $read_part->($part))) {
			$cid_hash->{$cid} = "data:$ctype;base64," . encode_base64($raw, '');
		    }
		}
	    }
	}
    }
};

sub entity_to_html {
    my ($entity, $cid_hash, $viewimages, $allowhref) = @_;

    my $mime_type = lc($entity->mime_type);;

    if ($mime_type eq 'text/plain') {
	my $raw = $read_part->($entity) // '';
	my $html = "<pre>\n";

	if (defined(my $cs = $entity->head->mime_attr("content-type.charset"))) {
	    $html .= PMG::Utils::decode_to_html($cs, $raw);
	} else {
	    $html .= encode_entities($raw);
	}

	$html .= "</pre>\n";

	return $html;

    } elsif ($mime_type eq 'text/html') {
	my $raw = $read_part->($entity) // '';

	if (defined(my $cs = $entity->head->mime_attr("content-type.charset"))) {
	    eval { $raw = decode($cs, $raw); }; # ignore errors here
	}

	# create a well formed tree
	my $tree = HTML::TreeBuilder->new();
	$tree->parse($raw);
	$tree->eof();

	my $whtml = dump_html($tree, $viewimages ? $cid_hash : {});
	$tree->delete;

	# remove dangerous/unneeded elements
	my $scrubber = getscrubber($viewimages, $allowhref);
	return $scrubber->scrub($whtml);

    } elsif ($mime_type =~ m|^multipart/|i) {
	my $multi_part;
	my $html_part;
	my $text_part;

	foreach my $part ($entity->parts)  {
	    my $subtype = lc($part->mime_type);
	    $multi_part = $part if !defined($multi_part) && $subtype =~ m|multipart/|i;
	    $html_part = $part if !defined($html_part) && $subtype eq 'text/html';
	    $text_part = $part if !defined($text_part) && $subtype eq 'text/plain';
	}

	# get related/embedded images as data uris
	$find_images->($cid_hash, $entity);

	my $alt = $multi_part || $html_part || $text_part;

	return entity_to_html($alt, $cid_hash, $viewimages, $allowhref) if $alt;
    }

    return undef;
}

sub email_to_html {
    my ($path, $raw, $viewimages, $allowhref) = @_;

    my $dumpdir = "/tmp/.proxdumpview_$$";

    my $html = '';

    eval {
	if ($raw) {

	    my ($header, $content) = read_raw_email($path);

	    $html .= "<pre>\n" .
		encode_entities($header) .
		"\n" .
		encode_entities($content) .
		"</pre>\n";

	} else {

	    my $parser = new MIME::Parser;
	    $parser->extract_nested_messages(0);

	    rmtree $dumpdir;

	    # Create and set the output directory:
	    (-d $dumpdir || mkdir($dumpdir ,0755)) ||
		die "can't create $dumpdir: $! : ERROR";
	    (-w $dumpdir) ||
		die "can't write to directory $dumpdir: $! : ERROR";

	    $parser->output_dir($dumpdir);

	    my $entity = $parser->parse_open($path);

	    # bug fix for bin/tests/content/mimeparser.txt
	    if ($entity->mime_type =~ m|multipart/|i && !$entity->head->multipart_boundary) {
		$entity->head->mime_attr('Content-type' => "application/x-unparseable-multipart");
	    }

	    $html = entity_to_html($entity, {}, $viewimages, $allowhref);
	}
    };
    my $err = $@;

    rmtree $dumpdir;

    die "unable to parse mail: $err" if $err;

    return $html;
}

1;
