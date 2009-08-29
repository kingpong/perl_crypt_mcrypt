#!/usr/bin/env sh

pod2wiki -s textile lib/Crypt/Mcrypt.pm |
    perl -e ' $/=undef; $_ = <>;
        s/\\n/\n/g;  # fix literal newlines
        s/^\s*$//mg; # clean up an lines with just whitespace
        s/\n*- (.*) :=\s*</\n\nh3. $1\n\n</g;
        s/^- (.*) :=\s*/\n* $1\n\n/mg;
        s/<pre>\n/<pre>/g;
        s{\s*</pre>}{</pre>}g;
        print;
    '
