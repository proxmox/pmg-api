#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use POSIX qw(setlocale strftime tzset);

use PMG::Utils;

$ENV{TZ} = 'Europe/Vienna';
tzset();

subtest 'format_date_header works' => sub {
    cmp_ok(length(PMG::Utils::format_date_header(localtime())), '>=', 30);
    is(
        PMG::Utils::format_date_header(47, 55, 12, 1, 8, 125, 1, 243, 1),
        'Mon, 01 Sep 2025 12:55:47 +0200',
    );
    is(
        PMG::Utils::format_date_header(59, 2, 8, 2, 0, 125, 4, 2, 0),
        'Thu, 02 Jan 2025 08:02:59 +0100',
    );
};

subtest 'format_date_header works with other locales' => sub {
    # also check correctness under some other locale
    my $old_locale = setlocale(POSIX::LC_TIME);

    if (!defined(setlocale(POSIX::LC_TIME, "de_DE.UTF-8"))) {
        # if the locale is not available, setlocale() returns undef
        # in that case, the tests below do not make sense
        plan(skip_all => "due to 'de_DE.UTF-8' locale not available");
    }

    # first check if the other locale indeed produces another format
    is(
        strftime('%a, %d %b %Y %T %z', 47, 55, 12, 1, 8, 125, 1, 243, 1),
        'Mo, 01 Sep 2025 12:55:47 +0200',
    );

    cmp_ok(length(PMG::Utils::format_date_header(localtime())), '>=', 30);
    is(
        PMG::Utils::format_date_header(47, 55, 12, 1, 8, 125, 1, 243, 1),
        'Mon, 01 Sep 2025 12:55:47 +0200',
    );
    is(
        PMG::Utils::format_date_header(59, 2, 8, 2, 0, 125, 4, 2, 0),
        'Thu, 02 Jan 2025 08:02:59 +0100',
    );

    setlocale(POSIX::LC_TIME, $old_locale);
};

done_testing();
