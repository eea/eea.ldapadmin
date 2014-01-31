import codecs
import csv
import xlwt
import logging
from StringIO import StringIO

logger = logging.getLogger(__name__)


def csv_headers_to_object(properties):
    """ Converts row data to object, according to header keys """
    # main purpose is to save code lines in logic
    return {
            'id': properties.get('user id*'),
            'password': str(properties.get('password*')),
            'email': properties.get('e-mail*'),
            'first_name': properties.get('first name*'),
            'last_name': properties.get('last name*'),
            'job_title': properties.get('job title'),
            'url': properties.get('url'),
            'postal_address': properties.get('postal address'),
            'phone': properties.get('telephone number'),
            'mobile': properties.get('mobile telephone number'),
            'fax': properties.get('fax number'),
            'organisation': properties.get('organisation')
    }

def generate_csv(header, rows):
    output = StringIO()
    csv_writer = csv.writer(output)

    csv_writer.writerow(header)
    for item in rows:
        csv_writer.writerow([value.encode('utf-8') for value in item])

    return codecs.BOM_UTF8 + output.getvalue()

class UTF8Recoder(object):
    """
    Iterator that reads an encoded stream and reencodes the input to UTF-8

    """
    def __init__(self, f, encoding):
        self.reader = codecs.getreader(encoding)(f)

    def __iter__(self):
        return self

    def next(self):
        return self.reader.next().encode("utf-8")


class UnicodeReader(object):
    """
    A CSV reader which will iterate over lines in the CSV file "f",
    which is encoded in the given encoding.

    """

    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        f = UTF8Recoder(f, encoding)
        self.reader = csv.reader(f, dialect=dialect, **kwds)

    def next(self):
        row = self.reader.next()
        return [unicode(s, "utf-8") for s in row]

    def __iter__(self):
        return self


class CSVReader(object):
    """ Manipulate CSV files """

    def __init__(self, file, dialect, encoding):
        """ """
        if dialect == 'comma':
            dialect=csv.excel
        elif dialect == 'tab':
            dialect=csv.excel_tab
        else:
            dialect=csv.excel
        self.csv = UnicodeReader(file, dialect, encoding)

    def read(self):
        """ return the content of the file """
        try:
            header = self.csv.next()
            output = []
            for values in self.csv:
                buf = {}
                for field, value in zip(header, values):
                    buf[field.encode('utf-8')] = value.encode('utf-8')
                output.append(buf)
            return (output, '')
        except Exception, ex:
            logger.exception('Read error')
            return (None, ex)

def generate_excel(header, rows):
    style = xlwt.XFStyle()
    normalfont = xlwt.Font()
    headerfont = xlwt.Font()
    headerfont.bold = True
    style.font = headerfont

    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet('Sheet 1')
    row = 0
    for col in range(0, len(header)):
        ws.row(row).set_cell_text(col, header[col], style)
    style.font = normalfont
    for item in rows:
        row += 1
        for col in range(0, len(item)):
            ws.row(row).set_cell_text(col, item[col], style)
    output = StringIO()
    wb.save(output)
    return output.getvalue()
