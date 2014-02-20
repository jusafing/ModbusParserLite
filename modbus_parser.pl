#!/usr/bin/perl -w
use File::Touch;
use LogUtils;
use ParserConfig;
use Switch;
use strict;
use warnings;

#############################################################################
#############################################################################
package GLOBAL;
	our $pcapFile = $ARGV[0];
	our @argusData;
	our %streams;
	our $msg;
package main;
#############################################################################
#############################################################################

startParser("MAIN");
createModbusStreamsFile("MAIN","$ARGV[0].streams",\%streams);
createModbusDataSSFile("MAIN","$ARGV[0].ss",\%streams);

#############################################################################
#############################################################################
sub startParser
{
    my $functionCaller = shift;
    my $functionName   = getFunctionName($functionCaller,(caller(0))[3]);
    print "---------------------------------\n";
    print "Modbus parser v0.1.0\n\n";
    print "See README file for more info\n";
    print "---------------------------------\n\n";
    $CFG::LOGFILE = $ARGV[1] if ($ARGV[1]);
    if (-d $CFG::LOGFILE)
    {
	print "ERROR: LOGFILE is a directory. It must be a regular file\n\n";
	exit(-1);
    }
    touch $CFG::LOGFILE unless (-e $CFG::LOGFILE);
    unless (-w "$CFG::LOGFILE")
    {
	print "ERROR, Unable to access LOG file ($CFG::LOGFILE)\n\n";
	exit (-1);
    }
    
    if ( -e "$pcapFile.argus" )
    {
	logMsgT($functionName,"Argus file already exists."
	. "Deleting the file ... ",1,$CFG::LOGFILE);
	unlink "$pcapFile.argus";
    }	
    logMsgT($functionName,"Reading capture file  :"
	    . " ($pcapFile)",2,$CFG::LOGFILE);
    logMsgT($functionName,"Writing argus   file  :"
	    . " ($pcapFile.argus)",2,$CFG::LOGFILE);
    my $cmdArgus;
    switch ($CFG::MODE)
    {
	case 1{
	    $cmdArgus = "$CFG::ARGUS_BIN -r $pcapFile -w $pcapFile.argus"
    	    . " -s 1500 -U 1500  - tcp and dst port $CFG::MODBUS_PORT";}
	case 2{
	    $cmdArgus = "$CFG::ARGUS_BIN -r $pcapFile -w $pcapFile.argus"
    	    . " -s 1500 -U 1500  - tcp and src port $CFG::MODBUS_PORT";}
	case 3{
	    $cmdArgus = "$CFG::ARGUS_BIN -r $pcapFile -w $pcapFile.argus"
    	    . " -s 1500 -U 1500  - tcp and port $CFG::MODBUS_PORT";}
	else {
	    my $msg = "ERROR, Invalid Mode ($CFG::MODE). Define only:\n ".
		    " 1 - Requests  only\n".
		    " 2 - Responses only\n".
		    " 3 - Full TcpStream\n\n".
	    print $msg;
	    exit (-1);}
    }
    `$cmdArgus`;
    my $cmdRa = "$CFG::RA_BIN -r $pcapFile.argus -s dir saddr sport".
    " daddr dport suser:1500 duser:1500 -M printer=hex";
    my @argusData = `$cmdRa`;
    shift @argusData;
    readModbusHeader($functionName,\@argusData);
}

#############################################################################
sub readModbusHeader
{
    my $functionCaller = shift;
    my $argusData      = shift;
    my $functionName   = getFunctionName($functionCaller,(caller(0))[3]);
    my $fixedHeader    = 6;
    my $mbFlag         = 0;
    my $mbCnt          = 0;
    my $dataCnt        = 0;
    my $headerCnt      = 0;
    my $tcpStreamCnt   = 0;
    my $connection     = "";
    my $headerDataSize = 0;
    foreach my $dataLine (@$argusData)
    {
	next if ($dataLine =~ m/^$/);
	my @fields = split(" ",$dataLine);
	#if ($fields[0] eq "<?>" or $fields[0] eq "?>" )
	if ($fields[0] =~ m/<*\?*>/ )
	{
	    $connection  = "$fields[1]-$fields[2]";
	    next;
	}
	elsif ($fields[0] =~ m/0x0000/)
	{
	    $tcpStreamCnt++;
	    $mbCnt       ++ if ($dataCnt < $headerDataSize && $mbFlag == 1) ;
	    $mbFlag      = 0;
	    $dataCnt     = 0;
	    $headerCnt   = 0;
	}
	$dataLine =~ s/0x....//;
	$dataLine =~ s/ //g;
	$dataLine =~ m/(\w{1,32})/g;
	my @dataBytes = ( $1 =~ m/../g );
	my $dataBytesSize = @dataBytes;
	if($CFG::DEBUG==1){
	    logMsgT($functionName,"ByteLine($dataBytesSize)",3,$CFG::LOGFILE);}
	for(my $i=0; $i<$dataBytesSize; $i++)
	{
	    if ($mbFlag == 0)
	    {
		if ($dataBytesSize - $i > $fixedHeader && $headerCnt==0)
		{
		    my $j = 0;	
		    do
		    {
			$streams{"$connection\_$mbCnt"}.=$dataBytes[$i+$j];
			if($CFG::DEBUG==1){
			    $msg = "Adding ($dataBytes[$i+$j]) to fixed header".
			    " ($j) ($connection\_$mbCnt)";
			    logMsgT($functionName,$msg,3,$CFG::LOGFILE);
			}
			$j++;
		    }while($j<7);
		    my $headerDataSizeHex="0x$dataBytes[$i+4]$dataBytes[$i+5]";
		    $headerDataSize = hex $headerDataSizeHex;
		    if($CFG::DEBUG==1)
		    {
			$msg = "Modbus bytes-to-follow size:($headerDataSize)";
			logMsgT($functionName,$msg,3,$CFG::LOGFILE);
		    }
		    $i += 6;
		    $mbFlag  = 1;
		    $dataCnt = 1;
		}
		else
		{
		    do
		    {
			$streams{"$connection\_$mbCnt"}.=$dataBytes[$i];
			if($CFG::DEBUG==1)
			{
			    $msg = "Adding ($dataBytes[$i]) to fixed header".
			    " ($headerCnt) ($connection\_$mbCnt)";
			    logMsgT($functionName,$msg,3,$CFG::LOGFILE);
			}
			$i++;
			$headerCnt++;
		    }while($i < $dataBytesSize && $headerCnt < 7);
		    if($headerCnt > 6)
		    {
			$streams{"$connection\_$mbCnt"} =~ m/.{8}(....)/;
			$headerDataSize = hex "0x$1";

			if($CFG::DEBUG==1)
			{ 
			    $msg="Modbus DATA field size:($headerDataSize)";
			    logMsgT($functionName,$msg,3,$CFG::LOGFILE);
			}
			$headerCnt  = 0;
			$mbFlag = 1;
			$dataCnt = 1;
			$i--;
		    }
		}
	    }
	    else
	    {
		my $cnt = $dataCnt+$fixedHeader;
		if($CFG::DEBUG==1)
		{
		    $msg = "Adding ($dataBytes[$i]) to header ($cnt)".
		    " ($connection\_$mbCnt)";
		    logMsgT($functionName,$msg,3,$CFG::LOGFILE)
		}
		$streams{"$connection\_$mbCnt"} .= $dataBytes[$i];
		$dataCnt++;
		if ($dataCnt == $headerDataSize)
		{
		    $mbCnt++;
		    $mbFlag  = 0;
		    $dataCnt = 0;
		}
	    }
	} 
    }
    $tcpStreamCnt++;	## Real number from 0-n
    $msg="Retrieved ($mbCnt) Modbus Headers from ($tcpStreamCnt) Tcp streams";
    logMsgT($functionName,$msg,2,$CFG::LOGFILE);
}

#############################################################################
sub createModbusStreamsFile
{
    my ($functionCaller, $outputFile, $modbusStreams) = @_;
    my $functionName   = getFunctionName($functionCaller,(caller(0))[3]);
    open(OUTFH, ">$outputFile");
    foreach my $stream (sort { $a cmp $b } keys %$modbusStreams) 
    {
	$msg = "$stream|$modbusStreams->{$stream}";
	print OUTFH "$msg\n";
    }
    close(OUTFH);
}
#############################################################################
sub createModbusDataSSFile
{
    my ($functionCaller, $outputFile, $modbusStreams) = @_;
    my $functionName   = getFunctionName($functionCaller,(caller(0))[3]);
    my %shortSequenceData;
    my $totalModbusHeaders = 0;
    foreach my $stream (keys%$modbusStreams)
    {
	$stream =~ m/(.+)\_.*/g;
	my $realStream = $1;
	$modbusStreams->{$stream} =~ m/.{12}(..)(..)(.*)/g ;
	$shortSequenceData{$realStream} .= "$1-$2-$3,";
	if ($CFG::DEBUG==1)
	{
	    $msg = "Adding ($1-$2-$3) to ($realStream)";
	    logMsgT($functionName,$msg,3,$CFG::LOGFILE)
	}
    }
    open(OUTFH, ">$outputFile");
    foreach my $stream (keys%shortSequenceData)
    {
	print OUTFH "$stream|$shortSequenceData{$stream}\n";
    }
    close(OUTFH);
}
#############################################################################
sub getByteArray
{
    {
	use bytes;
	my $bindata = shift;
	(my $hexdata = unpack("H*", $bindata)) =~ s/(..)/$1 /g;
	my @array = split(" ", $hexdata);
	foreach my $val ( @array )
	{
	    print "$val, ";
	}
	print "\n";
    }
}
#############################################################################
