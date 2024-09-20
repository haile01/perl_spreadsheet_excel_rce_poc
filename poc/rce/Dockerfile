FROM perl:5.32

COPY . /app
WORKDIR /app
RUN cpanm Spreadsheet::ParseExcel@0.65
RUN cpanm Spreadsheet::ParseXLSX@0.27

CMD bash run.sh
