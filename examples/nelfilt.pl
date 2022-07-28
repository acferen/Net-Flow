#!/usr/bin/perl

# nelfilt.pl: Translate flow stream from $bind_addr:$receive_port to
# $send_addr:$send_port, filtering out all flows except "NAT events".

use strict; no strict 'subs';
use Net::Flow qw(decode encode search_template);
use Net::Flow::Constants;
use IO::Socket::INET;

# command-line arguments
my $bind_addr    = "127.0.0.2";
my $receive_port = 2055;
my $send_addr    = "127.0.0.1";
my $send_port    = 2055;

# list of interesting IDs used by sub filter
my @filter_ids =
    map($Net::Flow::Constants::informationElementsByName{$_}{elementId},
        "postNATSourceIPv4Address",
        "postNATSourceIPv6Address",
        "postNATDestinationIPv4Address",
        "postNATDestinationIPv6Address");

# templates learned from input packets
# $templates{$source_id}[template_hash, ...]
my %templates;

# templates for output packets
# $otemplates{$source_id}{$id} = template_hash
my %otemplates;



sub usage {
    die "Usage: nelfilt [-b BIND_IPADDR] [-p INPORT] [TARGET_IPADDR[:PORT]]\n";
}


sub parse_args {
    while (local $_ = shift @ARGV) {
        if (s/^-b(\d+\.\d+\.\d+\.\d+)?$//) {
            $bind_addr = $1 || shift @ARGV || usage();
        }
        elsif (s/^-p(\d*)$//) {
            $receive_port = $1 || shift @ARGV || usage();
        }
        elsif (s/^(\d+\.\d+\.\d+\.\d+)$//) {
            $send_addr = $1;
        }
        elsif (s/^(\d+\.\d+\.\d+\.\d+):(\d+)$//) {
            $send_addr = $1;
            $send_port = $2;
        }
        else {
            usage();
        }
    }
}

# Return stream identification based on packet header.  This is
# necessary when handling mixed data stram from several sources: every
# source uses its own set of templates.  No separation for netflow v5
# sources: they all use the same fixed template.
sub stream_id {
    my ($packet, $sender) = @_;
    my ($sender_port, $sender_addr) = unpack_sockaddr_in($sender);
    $sender_addr = inet_ntoa($sender_addr);
    my ($version, $observationDomainId, $sourceId) = unpack('nx10N2', $packet);
    return ($version == 9? "$sender_port $sender_addr $sourceId":
            $version == 10? "$sender_port $sender_addr $observationDomainId":
            "v5");
}


# given [a reference to] a list of flows returned by from
# Net::Flow::decode, return the list of "interesting" flows.
# Currently we are interested only in NAT event flows which are
# recognized by presence of certain IDs.
sub filter {
    my ($flows) = @_;
    my @out;
    for my $flow (@$flows) {
        if (grep {$flow->{$_}} @filter_ids) {
            push @out, $flow;
        }
    }
    return @out;
}


sub main {
    parse_args();

    my $sock  = IO::Socket::INET->new(Proto => "udp",
                                      LocalAddr => $bind_addr,
                                      LocalPort => $receive_port)
        or die "udp $bind_addr:$receive_port: $!\n";

    my $osock = IO::Socket::INET->new(Proto => "udp",
                                      PeerAddr => $send_addr,
                                      PeerPort => $send_port)
        or die "udp $send_addr:$send_port: $!\n";

    # Net::Flow::encode receives keeps state data in encode_header, so
    # define it outside the loop.
    my %encode_header = (TemplateResendSecs => 3);

    while (my $sender = $sock->recv(my $packet, 0xFFFF)) {
        my $version = unpack("n", $packet);
        if ($version != 9 && $version != 10) {
            warn "v$version packet ignored\n";
            next;
        }

        my $stream_id = stream_id($packet, $sender);
        my ($header, $updated_templates, $flows, $errs) =
            decode(\$packet, \@{$templates{$stream_id}});
        map {warn "$_\n"} grep !/NOT FOUND TEMPLATE/, @$errs;
        $templates{$stream_id} = $updated_templates;

        my @oflows = filter($flows);
        next unless @oflows;

        for (@oflows) {
            my $id = $_->{SetId};
            if (! $otemplates{$stream_id}{$id}) {
                my ($templ, $err) =
                    search_template($id, $templates{$stream_id});
                if ($err) {
                    warn "$_\n";
                }
                $otemplates{$stream_id}{$id} = $templ;
            }
        }

        my @otempl = values %{$otemplates{$stream_id}};
        # Net::Flow::encode increments SequenceNum.
        # We don't want it changed, work around...
        if ($header->{SequenceNum}) {
            $header->{SequenceNum}--;
        }
        %encode_header = (%encode_header, %$header);

        my (undef, $pkts, $errs2) =
            encode(\%encode_header, \@otempl, \@oflows, 1468);
        map {print "$_\n"} @$errs2;

        for (@$pkts) {
            $osock->send($$_); # Reference-happy Net::Flow...
        }
    }
}

main();
exit 0;

# Local Variables: ***
# mode:Perl ***
# perl-indent-level:4 ***
# End: ***
#
# vim: ts=4 sw=4 expandtab
