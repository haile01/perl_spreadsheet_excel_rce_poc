use Spreadsheet::ParseXLSX;
use Spreadsheet::ParseExcel;
use open qw( :std :encoding(UTF-8) );

my $t = time();
my $parser = Spreadsheet::ParseXLSX->new();
my $workbook = $parser->parse("ahihi.xlsx") or die $parser->error;

$t = time() - $t;
print "Parsing took $t secs";
