use Spreadsheet::ParseExcel;
use open qw( :std :encoding(UTF-8) );

my $parser = Spreadsheet::ParseExcel->new();
my $workbook = $parser->parse("test.xls") or die $parser->error;
