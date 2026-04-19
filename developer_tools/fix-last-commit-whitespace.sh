#!/bin/sh

set -eu

base="${1:-HEAD~}"
target="${2:-HEAD}"

git rev-parse --show-toplevel >/dev/null
git rev-parse --verify "$base" >/dev/null
git rev-parse --verify "$target" >/dev/null

ROOT="$(git rev-parse --show-toplevel)"
export ROOT
export BASE="$base"
export TARGET="$target"

diff_file="$(mktemp)"
trap 'rm -f "$diff_file"' EXIT

git diff --unified=0 --no-color --no-ext-diff --no-renames "$base" "$target" > "$diff_file"

perl - "$diff_file" <<'PERL'
use strict;
use warnings;

my $diff_path = shift @ARGV;
my $root = $ENV{'ROOT'};
my $base = $ENV{'BASE'};
my $target = $ENV{'TARGET'};
my %selected_lines;
my $current_file;
my $target_line;

open(my $diff, '<', $diff_path) or die "Unable to read diff: $!";

while (my $line = <$diff>) {
	if ($line =~ /^\+\+\+ b\/(.*)\r?\n$/) {
		$current_file = $1;
		next;
	}

	if ($line =~ /^diff --git /) {
		$current_file = undef;
		$target_line = undef;
		next;
	}

	if ($line =~ /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/) {
		$target_line = $1;
		next;
	}

	next if !defined($current_file) || !defined($target_line);

	if ($line =~ /^\+/ && $line !~ /^\+\+\+/) {
		$selected_lines{$current_file}{$target_line} = 1;
		$target_line++;
		next;
	}

	if ($line =~ /^ /) {
		$target_line++;
		next;
	}

	if ($line =~ /^-/ || $line =~ /^\\ /) {
		next;
	}
}

close($diff);

my @changed_files;

for my $relative_path (sort keys %selected_lines) {
	my $path = "$root/$relative_path";
	next if !-f $path;

	open(my $in, '<:raw', $path) or die "Unable to read $relative_path: $!";
	local $/;
	my $content = <$in>;
	close($in);

	my $output = '';
	my $line_number = 1;
	my $changed = 0;

	pos($content) = 0;

	while (pos($content) < length($content)) {
		$content =~ /\G([^\r\n]*)(\r\n|\n|\r|$)/gc
			or die "Unable to parse line endings in $relative_path";

		my ($text, $eol) = ($1, $2);

		if ($selected_lines{$relative_path}{$line_number}) {
			my $new_text = $text;
			$new_text =~ s/[ \t]+$//;

			my $new_eol = ($eol eq '') ? '' : "\n";

			if ($new_text ne $text || $new_eol ne $eol) {
				$changed = 1;
			}

			$output .= $new_text . $new_eol;
		}
		else {
			$output .= $text . $eol;
		}

		last if $eol eq '';
		$line_number++;
	}

	next if !$changed;

	open(my $out, '>:raw', $path) or die "Unable to write $relative_path: $!";
	print $out $output or die "Unable to write $relative_path: $!";
	close($out);

	push(@changed_files, $relative_path);
}

if (@changed_files) {
	print "Fixed whitespace/EOL in files from $base..$target:\n";
	for my $relative_path (@changed_files) {
		print "$relative_path\n";
	}
}
else {
	print "No whitespace/EOL fixes needed for $base..$target.\n";
}
PERL
