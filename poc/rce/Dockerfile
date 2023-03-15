FROM perl:5.32

COPY . /app
WORKDIR /app
RUN cpanm Spreadsheet::ParseExcel
RUN cpanm Spreadsheet::ParseXLSX

CMD bash run.sh