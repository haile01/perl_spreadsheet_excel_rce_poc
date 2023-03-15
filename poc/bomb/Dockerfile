FROM perl:5.32

COPY ahihi.xlsx /app/ahihi.xlsx
COPY ahihi.pl /app/ahihi.pl
WORKDIR /app
RUN cpanm Spreadsheet::ParseXLSX

CMD perl ahihi.pl
