echo "=== POC for ParseXLSX ==="
rm /tmp/inject.txt
perl test.pl
cat /tmp/inject.txt

echo "=== POC for ParseExcel ==="
rm /tmp/inject.txt
perl test-xls.pl
cat /tmp/inject.txt
