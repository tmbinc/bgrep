#!/bin/bash

PREPARE=1

if [ $# -gt 0 ];then
 echo Skipping test preparation.
 PREPARE=0
fi

if [ $PREPARE -eq 1 ]; then
 echo Preparing tests for bgrep

 rm -f /tmp/bgrep*

 #
 # create files with AAA...A BBBC AAA...A
 # to find the sequence "BBB" == 0x424242
 #
 for index in `seq 0 1025`;do
  fileIndex=`printf "%04i" ${index}`
  perl -e 'print "A"x'"${index}"';print "BBBC";print "A"x20;' > /tmp/bgrepTest${fileIndex}.txt
  printf "%016x\n" ${index} >> /tmp/bgrepExpectedResult.txt
 done

 #
 # create files with AAA...A BBB
 # to find the sequence "BBB" == 0x424242
 #
 for index in `seq 1020 1025`;do
  perl -e 'print "A"x'"${index}"';print "BBB"' > /tmp/bgrepTestSpecial${index}.txt
  printf "%016x\n" ${index} >> /tmp/bgrepExpectedResult.txt
 done

fi

#
# Test execution
#
echo Testing bgrep
echo "../bgrep 424242 /tmp/bgrepTest* | sed 's/^.*: //g' > /tmp/results.txt"

../bgrep 424242 /tmp/bgrepTest* | sed 's/^.*: //g' > /tmp/results.txt

echo -e "\nDifferences between /tmp/results.txt and /tmp/bgrepExpectedResult.txt:"

diff -u /tmp/results.txt /tmp/bgrepExpectedResult.txt
