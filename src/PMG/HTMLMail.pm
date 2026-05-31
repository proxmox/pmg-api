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

use PMG::Utils;
use PMG::MIMEUtils;

# $value is a ref to a string scalar
my sub remove_urls {
    my ($value) = @_;
    return if !defined $$value;

    # convert 'url([..])' to '___([..])' so the browser does not load it
    $$value =~ s|url\(|___(|gi;

    # @import can pull in an external stylesheet without a url() wrapper
    $$value =~ s|\@import|_import|gi;

    # similar for all protocols
    $$value =~ s|[a-z0-9]+://|_|gi;
}

my sub remove_urls_from_attr {
    my ($obj, $tag_name, $attr_name, $value) = @_;

    remove_urls(\$value);

    return $value;
}

# Map the tri-state 'viewimages' setting to two booleans. Embedded (cid:) images are shown unless
# images are fully blocked, as they carry no network request; external resources are only loaded in
# 'allow' mode ('on-demand' blocks them but lets the user opt in via a re-render).
my sub viewimages_flags {
    my ($viewimages) = @_;

    my $mode;
    if (defined($viewimages) && $viewimages eq 'on-demand') {
        $mode = 'on-demand';
    } elsif (!$viewimages || $viewimages eq '0') {
        $mode = 'block';
    } else {
        $mode = 'allow';
    }

    my $show_embedded = $mode ne 'block';
    my $show_external = $mode eq 'allow';

    return ($show_embedded, $show_external);
}

sub dump_html {
    my ($tree, $cid_hash, $view_images) = @_;

    my ($show_embedded, $show_external) = viewimages_flags($view_images);

    my @html = ();

    $tree->traverse(sub {
        my ($node, $start, $depth) = @_;
        if (ref $node) {
            my $tag = $node->{'_tag'};

            # try to open a new window when user activates a anchor
            $node->{target} = '_blank' if $tag eq 'a';

            if ($tag eq 'img' && $show_embedded) {
                if ($node->{src} && $node->{src} =~ m/^cid:(\S+)$/) {
                    if (my $datauri = $cid_hash->{$1}) {
                        $node->{src} = $datauri;
                    }
                }
            }

            # strip url() references from inline <style> blocks unless external
            # resources may be loaded, so they cannot fetch remote content
            if ($tag eq 'style' && !$show_external) {
                remove_urls($_) for grep { !ref $$_ } $node->content_refs_list();
            }

            if ($start) { # on the way in
                push(@html, $node->starttag);
            } else { # on the way out
                push(@html, $node->endtag);
            }
        } else { # simple text content
            # To keep from amp-escaping children of script et al. That doesn't deal with descendants;
            # but then, CDATA parents shouldn't /have/ descendants other than a text children (or comments?)
            if (!$HTML::Tagset::isCDATA_Parent{ $_[3]->{'_tag'} }) {
                # That does magic things if $entities is undef.
                $node = encode_entities($node);
            }
            push(@html, $node);
        }
        return 1; # keep traversing
    });

    return join('', @html, "\n");
}

sub getscrubber {
    my ($viewimages, $allowhref) = @_;

    my ($show_embedded, $show_external) = viewimages_flags($viewimages);

    # see http://web.archive.org/web/20110726052341/http://feedparser.org/docs/html-sanitization.html

    my @allow =
        qw(a abbr acronym address area b big blockquote br button caption center cite code col colgroup dd del dfn dir div dl dt em fieldset font form h1 h2 h3 h4 h5 h6 head hr i img input ins kbd label legend li map menu ol optgroup option p pre q s samp select small span style strike strong sub sup title table tbody td textarea tfoot th thead tr tt u ul var html body);

    my @rules = (script => 0);

    my $src_allowed = 0;
    # allow any non-script src when external resources are permitted; otherwise (on-demand) only
    # allow the inlined data: URIs of embedded images, so nothing is fetched.
    if ($show_external) {
        $src_allowed = qr{^(?!(?:java)?script)}i;
    } elsif ($show_embedded) {
        $src_allowed = qr{^data:image/}i;
    }

    my @default = (
        0 => # default rule, deny all tags
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
                src => $src_allowed,
                start => 1,
                style => $show_external ? 1 : \&remove_urls_from_attr,
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
            },
    );

    my $scrubber = HTML::Scrubber->new(
        allow => \@allow,
        rules => \@rules,
        default => \@default,
        comment => 0,
        process => 0,
    );

    $scrubber->style(1);

    return $scrubber;
}

sub read_raw_email {
    my ($path, $maxbytes) = @_;

    open(my $fh, '<', $path) || die "unable to open '$path' - $!\n";

    my $data = '';
    my $raw_header = '';

    # read header
    my $header;
    while (defined(my $line = <$fh>)) {
        my $decoded_line = PMG::Utils::try_decode_utf8($line);
        $raw_header .= $decoded_line;
        chomp $decoded_line;
        push @$header, $decoded_line;
        last if $line =~ m/^\s*$/;
    }

    my $head = MIME::Head->new($header);

    my $cs = $head->mime_attr("content-type.charset");

    my $bytes = 0;

    while (defined(my $line = <$fh>)) {
        $bytes += length($line);
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

    foreach my $part ($entity->parts) {
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

# Pick the child part that gets rendered for a multipart entity: the first nested
# multipart, else the first text/html, else the first text/plain.
my $select_alternative_part = sub {
    my ($entity) = @_;

    my ($multi_part, $html_part, $text_part);
    foreach my $part ($entity->parts) {
        my $subtype = lc($part->mime_type);
        $multi_part //= $part if $subtype =~ m|^multipart/|;
        $html_part //= $part if $subtype eq 'text/html';
        $text_part //= $part if $subtype eq 'text/plain';
    }

    return $multi_part || $html_part || $text_part;
};

sub entity_to_html {
    my ($entity, $cid_hash, $viewimages, $allowhref) = @_;

    my $mime_type = lc($entity->mime_type);

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

        # normalizes html, replaces CID references with data uris and scrubs style tags
        my $whtml = dump_html($tree, $cid_hash, $viewimages);
        $tree->delete;

        # remove dangerous/unneeded elements
        my $scrubber = getscrubber($viewimages, $allowhref);
        return $scrubber->scrub($whtml);

    } elsif ($mime_type =~ m|^multipart/|i) {
        # get related/embedded images as data uris
        $find_images->($cid_hash, $entity);

        my $alt = $select_alternative_part->($entity);

        return entity_to_html($alt, $cid_hash, $viewimages, $allowhref) if $alt;
    }

    return undef;
}

sub email_to_html {
    my ($path, $raw, $viewimages, $allowhref, $accept_broken_mime) = @_;

    my $dumpdir = "/tmp/.proxdumpview_$$";

    my $html = '';

    eval {
        if ($raw) {

            my ($header, $content) = read_raw_email($path);

            $html .=
                "<pre>\n"
                . encode_entities($header) . "\n"
                . encode_entities($content)
                . "</pre>\n";

        } else {

            my $parser = PMG::MIMEUtils::new_mime_parser({
                dumpdir => $dumpdir,
                ignore_errors => $accept_broken_mime,
            });

            my $entity = $parser->parse_open($path);

            PMG::MIMEUtils::fixup_multipart($entity);

            $html = entity_to_html($entity, {}, $viewimages, $allowhref);
        }
    };
    my $err = $@;

    rmtree $dumpdir;

    die "unable to parse mail: $err" if $err;

    return $html;
}

# Descend to the leaf part that entity_to_html() would render, following the same selection, so only
# what is actually shown gets inspected - resources in other parts (attachments, the non-rendered
# alternative) never get fetched anyway.
my $select_rendered_entity;
$select_rendered_entity = sub {
    my ($entity) = @_;

    my $mime_type = lc($entity->mime_type);
    return $entity if $mime_type eq 'text/html' || $mime_type eq 'text/plain';
    return undef if $mime_type !~ m|^multipart/|;

    my $alt = $select_alternative_part->($entity);
    return defined($alt) ? $select_rendered_entity->($alt) : undef;
};

# Whether the given HTML references external resources that the 'on-demand' mode strips, so
# offering the user an opt-in to load such images makes sense.
my $html_has_external_resource = sub {
    my ($raw) = @_;

    my $tree = HTML::TreeBuilder->new();
    # external CSS reference (url() or @import), as opposed to inlined data:/cid: ones
    my $css_ext = qr{(?:url\(|\@import)\s*['"]?\s*(?:https?:)?//}i;
    my $found = 0;
    eval {
        $tree->parse($raw);
        $tree->eof();
        # http(s) or scheme-relative src on fetching tags (img, input) and external CSS in <style>
        # blocks or inline style="" attrs; inlined cid:/data: and relative refs do not count
        $tree->traverse(sub {
            my ($node, $start) = @_;
            return 1 if !$start || !ref $node; # keep traversing
            my $tag = lc($node->{'_tag'} // '');
            $found = 1
                if ($tag eq 'img' || $tag eq 'input')
                && ($node->{src} // '') =~ m{^\s*(?:https?:)?//}i;
            $found = 1 if ($node->{style} // '') =~ $css_ext;
            $found = 1
                if $tag eq 'style' && grep { !ref && $_ =~ $css_ext } $node->content_list;
            return 1; # keep traversing
        });
    };
    my $err = $@;
    $tree->delete; # break the cyclic tree even if traversal died

    die $err if $err;

    return $found;
};

# Returns true if the rendered mail body references external resources that the 'on-demand' view
# mode blocks and that loading images would fetch. This parses the mail best-effort (false on err).
sub mail_has_external_images {
    my ($path, $accept_broken_mime) = @_;

    my $dumpdir = "/tmp/.proxextimgcheck_$$";

    my $found = eval {
        my $parser = PMG::MIMEUtils::new_mime_parser({
            dumpdir => $dumpdir,
            ignore_errors => $accept_broken_mime,
        });
        my $entity = $parser->parse_open($path);
        PMG::MIMEUtils::fixup_multipart($entity);

        my $part = $select_rendered_entity->($entity);
        if (defined($part) && lc($part->mime_type) eq 'text/html') {
            my $raw = $read_part->($part) // '';
            # decode like entity_to_html() does, so the scan sees what gets rendered
            if (defined(my $cs = $part->head->mime_attr("content-type.charset"))) {
                eval { $raw = decode($cs, $raw); };
            }
            $html_has_external_resource->($raw);
        } else {
            0;
        }
    };
    my $err = $@;

    rmtree $dumpdir;

    if ($err) {
        warn "unable to check mail for external images: $err\n";
        return 0;
    }

    return $found ? 1 : 0;
}

1;
